//! Exercise both OAuth legs against a real local OIDC provider, with signed ID tokens.
use axum::{
    Form, Json, Router,
    body::{Body, to_bytes},
    extract::{Query, State},
    http::{Request, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use idfrog::{
    config::{AuthenticationConfig, Config, RegisteredClient, Resource, UpstreamConfig},
    signing,
    state::{Store, random_token, token_hash},
    upstream::Upstream,
    web::{AppState, router},
};
use idp_oauth::token::SigningKey;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header,
};
use p256::{ecdsa::SigningKey as EcSigningKey, elliptic_curve::Generate, pkcs8::EncodePrivateKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::{Mutex, Notify};
use tower::ServiceExt;
use url::Url;

const API_ID: &str = "0816f759-d89d-4319-a8d7-d88b5d751dc9";
const API_SCOPE: &str = "api://0816f759-d89d-4319-a8d7-d88b5d751dc9/.default";
const RESOURCE: &str = "https://tools.example/mcp";
const CALLBACK: &str = "http://127.0.0.1:3000/callback";
const ORIGIN: &str = "http://localhost:8081";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

#[derive(Clone)]
struct Provider {
    issuer: String,
    jwk: Value,
    key: EncodingKey,
    algorithm: Algorithm,
    certificate_auth: bool,
    assertion_ids: Arc<Mutex<HashSet<String>>>,
    behavior: Arc<Mutex<Behavior>>,
    codes: Arc<Mutex<HashMap<String, ProviderLogin>>>,
    refresh: Arc<Mutex<HashMap<String, String>>>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}
#[derive(Clone)]
struct ProviderLogin {
    nonce: String,
    challenge: String,
    offline: bool,
}
#[derive(Clone)]
struct Behavior {
    mode: &'static str,
    groups: Vec<String>,
    scopes: String,
    pause_refresh: bool,
}

async fn provider_metadata(State(provider): State<Provider>) -> Json<Value> {
    Json(json!({"issuer":provider.issuer,
        "authorization_endpoint":format!("{}/authorize",provider.issuer),
        "token_endpoint":format!("{}/token",provider.issuer),
        "jwks_uri":format!("{}/jwks",provider.issuer),
        "response_types_supported":["code"],"subject_types_supported":["public"],
        "id_token_signing_alg_values_supported":[provider.algorithm],"token_endpoint_auth_methods_supported":[if provider.certificate_auth {"private_key_jwt"} else {"client_secret_post"}]
    }))
}
async fn provider_authorize(
    State(provider): State<Provider>,
    Query(request): Query<HashMap<String, String>>,
) -> Redirect {
    assert_eq!(request["client_id"], "upstream-client");
    assert_eq!(request["response_type"], "code");
    assert_eq!(request["code_challenge_method"], "S256");
    assert_eq!(request["redirect_uri"], format!("{ORIGIN}/oidc/callback"));
    assert!(request["scope"].split_whitespace().any(|s| s == "openid"));
    assert!(request["scope"].split_whitespace().any(|s| s == API_SCOPE));
    let code = random_token();
    provider.codes.lock().await.insert(
        code.clone(),
        ProviderLogin {
            nonce: request["nonce"].clone(),
            challenge: request["code_challenge"].clone(),
            offline: request["scope"]
                .split_whitespace()
                .any(|s| s == "offline_access"),
        },
    );
    let mut redirect = Url::parse(&request["redirect_uri"]).unwrap();
    redirect
        .query_pairs_mut()
        .append_pair("state", &request["state"])
        .append_pair("code", &code);
    Redirect::to(redirect.as_str())
}
async fn provider_token(
    State(provider): State<Provider>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    assert_eq!(form["client_id"], "upstream-client");
    if provider.certificate_auth {
        assert!(!form.contains_key("client_secret"));
        assert_eq!(
            form["client_assertion_type"],
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        );
        let assertion = &form["client_assertion"];
        let header = decode_header(assertion).unwrap();
        assert_eq!(header.alg, Algorithm::PS256);
        let cert = include_bytes!("fixtures/test-only-client-cert.pem");
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let der = CertificateDer::from_pem_slice(cert).unwrap();
        assert_eq!(
            header.x5t_s256,
            Some(URL_SAFE_NO_PAD.encode(Sha256::digest(der.as_ref())))
        );
        let mut validation = Validation::new(Algorithm::PS256);
        validation.set_issuer(&["upstream-client"]);
        validation.set_audience(&[format!("{}/token", provider.issuer)]);
        validation.sub = Some("upstream-client".into());
        validation.validate_nbf = true;
        let claims = decode::<Value>(
            assertion,
            &DecodingKey::from_rsa_pem(cert).unwrap(),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            300
        );
        assert!(
            provider
                .assertion_ids
                .lock()
                .await
                .insert(claims["jti"].as_str().unwrap().to_string())
        );
    } else {
        assert_eq!(form["client_secret"], "upstream-secret");
        assert!(!form.contains_key("client_assertion"));
    }
    let behavior = provider.behavior.lock().await.clone();
    if behavior.mode == "token_endpoint_error" {
        return (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_client", "error_description":"AADSTS700027: provider-private-sentinel"}))).into_response();
    }
    let is_refresh = form["grant_type"] == "refresh_token";
    let (nonce, offline) = if is_refresh {
        let scopes: HashSet<_> = form["scope"].split_whitespace().collect();
        assert_eq!(
            scopes,
            HashSet::from([API_SCOPE, "openid", "profile", "email", "offline_access"])
        );
        if behavior.mode == "deny_refresh" {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_grant"})),
            )
                .into_response();
        }
        let Some(nonce) = provider.refresh.lock().await.remove(&form["refresh_token"]) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_grant"})),
            )
                .into_response();
        };
        if behavior.pause_refresh {
            provider.entered.notify_one();
            provider.release.notified().await;
        }
        (nonce, true)
    } else {
        assert_eq!(form["grant_type"], "authorization_code");
        let login = provider.codes.lock().await.remove(&form["code"]).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes())),
            login.challenge
        );
        assert_eq!(form["redirect_uri"], format!("{ORIGIN}/oidc/callback"));
        (login.nonce, login.offline)
    };
    let now = Utc::now().timestamp();
    let mut claims = json!({"iss":provider.issuer,"sub":"upstream-alice","aud":"upstream-client",
        "iat":now,"exp":now+3600,"auth_time":now-300,"email":"alice@example.com","groups":behavior.groups});
    if !is_refresh {
        claims["nonce"] = json!(nonce);
    }
    match behavior.mode {
        "bad_nonce" => claims["nonce"] = json!("wrong-nonce"),
        "bad_audience" => claims["aud"] = json!("another-app"),
        "bad_issuer" => claims["iss"] = json!("https://another-issuer.example"),
        "expired" => claims["exp"] = json!(now - 300),
        "future_issued" => claims["iat"] = json!(now + 300),
        "changed_subject" => claims["sub"] = json!("upstream-bob"),
        "overage" => {
            claims.as_object_mut().unwrap().remove("groups");
            claims["_claim_names"] = json!({"groups":"source"});
        }
        _ => {}
    }
    let mut header = Header::new(provider.algorithm);
    header.kid = Some("upstream-key".into());
    let mut token = jsonwebtoken::encode(&header, &claims, &provider.key).unwrap();
    if behavior.mode == "wrong_key" {
        let split = token.rfind('.').unwrap() + 1;
        let replacement = if token.as_bytes()[split] == b'A' {
            "B"
        } else {
            "A"
        };
        token.replace_range(split..split + 1, replacement);
    }
    let mut access_claims = json!({"iss":provider.issuer,"sub":"upstream-alice","aud":API_ID,
        "azp":"upstream-client","iat":now,"nbf":now-10,"exp":now+3600,"scp":behavior.scopes});
    match behavior.mode {
        "access_missing_scope" => access_claims["scp"] = json!(""),
        "access_wrong_prefix" => access_claims["scp"] = json!("api://another-api/Full"),
        "access_app_only" => {
            access_claims.as_object_mut().unwrap().remove("scp");
            access_claims["roles"] = json!(["Full"]);
        }
        "access_wrong_audience" => access_claims["aud"] = json!("another-api"),
        "access_uri_audience" => access_claims["aud"] = json!(format!("api://{API_ID}")),
        "access_wrong_issuer" => access_claims["iss"] = json!("https://another-issuer.example"),
        "access_wrong_user" => access_claims["sub"] = json!("upstream-bob"),
        "access_wrong_client" => access_claims["azp"] = json!("another-client"),
        "access_short_lived" => access_claims["exp"] = json!(now + 120),
        "access_expired" => access_claims["exp"] = json!(now - 1),
        "access_future" => access_claims["nbf"] = json!(now + 300),
        "access_future_iat" => access_claims["iat"] = json!(now + 300),
        _ => {}
    }
    let mut access = jsonwebtoken::encode(&header, &access_claims, &provider.key).unwrap();
    if behavior.mode == "access_wrong_key" {
        let split = access.rfind('.').unwrap() + 1;
        let replacement = if access.as_bytes()[split] == b'A' {
            "B"
        } else {
            "A"
        };
        access.replace_range(split..split + 1, replacement);
    }
    if behavior.mode == "access_opaque" {
        access = "opaque-access-token".into();
    }
    let mut response =
        json!({"access_token":access,"token_type":"Bearer","expires_in":3600,"id_token":token});
    if behavior.mode == "missing_id_token" {
        response.as_object_mut().unwrap().remove("id_token");
    }
    if offline {
        let refresh = random_token();
        provider.refresh.lock().await.insert(refresh.clone(), nonce);
        response["refresh_token"] = json!(refresh);
    }
    Json(response).into_response()
}

fn provider_key(algorithm: Algorithm) -> (EncodingKey, Value) {
    if algorithm == Algorithm::ES256 {
        let key = EcSigningKey::generate().to_pkcs8_der().unwrap();
        let jwk = SigningKey::from_pkcs8("upstream-key", key.as_bytes())
            .unwrap()
            .public_jwk();
        return (
            EncodingKey::from_ec_der(key.as_bytes()),
            serde_json::to_value(jwk).unwrap(),
        );
    }
    use rsa::{pkcs8::DecodePrivateKey as _, traits::PublicKeyParts};
    // A committed key: generating RSA keys in unoptimized test builds takes seconds.
    const PEM: &str = include_str!("fixtures/test-only-provider-key.pem");
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(PEM).unwrap();
    let jwk = json!({"kty":"RSA", "kid":"upstream-key", "use":"sig", "alg":"RS256",
        "n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        "e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())});
    (EncodingKey::from_rsa_pem(PEM.as_bytes()).unwrap(), jwk)
}

struct Fixture {
    app: Router,
    provider: Provider,
    server: tokio::task::JoinHandle<()>,
    directory: PathBuf,
    config: Config,
    store: Store,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::with_algorithm(Algorithm::RS256).await
    }
    async fn with_algorithm(algorithm: Algorithm) -> Self {
        Self::with_authentication(algorithm, false).await
    }
    async fn with_authentication(algorithm: Algorithm, certificate_auth: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let (key, jwk) = provider_key(algorithm);
        let provider = Provider {
            issuer: issuer.clone(),
            jwk,
            key,
            algorithm,
            certificate_auth,
            assertion_ids: Default::default(),
            behavior: Arc::new(Mutex::new(Behavior {
                mode: "normal",
                groups: vec!["engineering".into()],
                scopes: "Read Full".into(),
                pause_refresh: false,
            })),
            codes: Default::default(),
            refresh: Default::default(),
            entered: Default::default(),
            release: Default::default(),
        };
        let upstream_router = Router::new()
            .route("/.well-known/openid-configuration", get(provider_metadata))
            .route("/authorize", get(provider_authorize))
            .route("/token", post(provider_token))
            .route(
                "/jwks",
                get(|State(p): State<Provider>| async move { Json(json!({"keys":[p.jwk]})) }),
            )
            .with_state(provider.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, upstream_router).await.unwrap();
        });
        let directory = std::env::temp_dir().join(format!("idfrog-test-{}", random_token()));
        std::fs::create_dir(&directory).unwrap();
        let secret = directory.join("client-secret");
        std::fs::write(&secret, "upstream-secret\n").unwrap();
        let authentication = if certificate_auth {
            let certificate_file = directory.join("tls.crt");
            let private_key_file = directory.join("tls.key");
            std::fs::write(
                &certificate_file,
                include_bytes!("fixtures/test-only-client-cert.pem"),
            )
            .unwrap();
            std::fs::write(
                &private_key_file,
                include_bytes!("fixtures/test-only-client-key.pem"),
            )
            .unwrap();
            AuthenticationConfig::PrivateKeyJwt {
                certificate_file,
                private_key_file,
            }
        } else {
            AuthenticationConfig::ClientSecretPost {
                client_secret_file: secret,
            }
        };
        let key_path = directory.join("signing-key.pem");
        signing::generate(&key_path).unwrap();
        let mut config = Config {
            origin: ORIGIN.into(),
            listen: "127.0.0.1:8081".parse().unwrap(),
            signing_key_file: key_path.clone(),
            tls_cert_path: None,
            tls_key_path: None,
            traces: None,
            upstream: UpstreamConfig {
                issuer,
                client_id: "upstream-client".into(),
                authentication,
            },
            resources: [RESOURCE, "https://other.example/mcp"]
                .iter()
                .map(|uri| Resource {
                    uri: (*uri).into(),
                    application_id: API_ID.into(),
                })
                .collect(),
            clients: vec![
                RegisteredClient {
                    client_id: "mcp-test".into(),
                    name: "Test <client>".into(),
                    redirect_uris: vec![CALLBACK.into()],
                    native: true,
                },
                RegisteredClient {
                    client_id: "other-client".into(),
                    name: "Other".into(),
                    redirect_uris: vec![CALLBACK.into()],
                    native: false,
                },
            ],
            state: Default::default(),
        };
        config.validate().unwrap();
        let upstream = Upstream::discover(&config).await.unwrap();
        let store = test_store().await;
        let app = router(AppState::new(
            config.clone(),
            upstream,
            signing::load(&key_path).unwrap(),
            store.clone(),
        ));
        Self {
            app,
            provider,
            server,
            directory,
            config,
            store,
        }
    }
    async fn get(&self, uri: &str, cookie: Option<&str>) -> Response {
        request(&self.app, "GET", uri, cookie, None).await
    }
    async fn post(&self, uri: &str, cookie: Option<&str>, form: &[(String, String)]) -> Response {
        request(&self.app, "POST", uri, cookie, Some(form)).await
    }
    async fn begin(&self, scopes: &str) -> (String, String) {
        let url = authorization_url(scopes);
        let response = self
            .get(&format!("{}?{}", url.path(), url.query().unwrap()), None)
            .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Lax"));
        let cookie = set_cookie.split(';').next().unwrap().to_string();
        (cookie, location(&response))
    }
    async fn callback_uri(&self, upstream: &str) -> String {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let response = http.get(upstream).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let url = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        format!("{}?{}", url.path(), url.query().unwrap())
    }
    async fn code(&self, scopes: &str) -> String {
        let (cookie, upstream) = self.begin(scopes).await;
        let callback = self.callback_uri(&upstream).await;
        let response = self.get(&callback, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let url = Url::parse(&location(&response)).unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["state"], "downstream-state");
        assert_eq!(query["iss"], ORIGIN);
        query["code"].clone()
    }
    async fn exchange(&self, code: &str) -> Value {
        let response = self.post("/token", None, &code_form(code)).await;
        assert_eq!(response.status(), StatusCode::OK);
        json_body(response).await
    }
    async fn verify(&self, token: &str, audience: &str) -> Value {
        let keys = json_body(self.get("/jwks.json", None).await).await;
        let jwk = serde_json::from_value(keys["keys"][0].clone()).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[ORIGIN]);
        validation.set_audience(&[audience]);
        decode::<Value>(token, &DecodingKey::from_jwk(&jwk).unwrap(), &validation)
            .unwrap()
            .claims
    }
}

/// The in-memory store, or a fresh table in DynamoDB Local when
/// `IDFROG_TEST_DYNAMODB_ENDPOINT` is set and the `dynamodb` feature is enabled.
async fn test_store() -> Store {
    #[cfg(feature = "dynamodb")]
    if let Ok(endpoint) = std::env::var("IDFROG_TEST_DYNAMODB_ENDPOINT") {
        return dynamodb_store(&endpoint).await;
    }
    Store::memory()
}

#[cfg(feature = "dynamodb")]
async fn dynamodb_store(endpoint: &str) -> Store {
    use aws_sdk_dynamodb::{
        Client,
        config::{BehaviorVersion, Credentials, Region},
        types::{AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType},
    };
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new("test", "test", None, None, "test"))
        .endpoint_url(endpoint)
        .http_client(idfrog::dynamodb::http_client())
        .build();
    let client = Client::from_conf(config);
    let table = format!("idfrog-test-{}", random_token());
    client
        .create_table()
        .table_name(&table)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("pk")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("pk")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    Store::DynamoDb(idfrog::dynamodb::DynamoStore::new(client, table))
}

fn authorization_url(scopes: &str) -> Url {
    let mut url = Url::parse(&format!("{ORIGIN}/authorize")).unwrap();
    url.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", "mcp-test"),
        ("redirect_uri", CALLBACK),
        ("scope", scopes),
        ("resource", RESOURCE),
        ("state", "downstream-state"),
        ("nonce", "downstream-nonce"),
        ("code_challenge_method", "S256"),
        (
            "code_challenge",
            &URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
        ),
    ]);
    url
}
fn code_form(code: &str) -> Vec<(String, String)> {
    vec![
        ("grant_type".into(), "authorization_code".into()),
        ("client_id".into(), "mcp-test".into()),
        ("code".into(), code.into()),
        ("redirect_uri".into(), CALLBACK.into()),
        ("resource".into(), RESOURCE.into()),
        ("code_verifier".into(), VERIFIER.into()),
    ]
}
fn refresh_form(token: &str) -> Vec<(String, String)> {
    vec![
        ("grant_type".into(), "refresh_token".into()),
        ("client_id".into(), "mcp-test".into()),
        ("refresh_token".into(), token.into()),
    ]
}
async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    form: Option<&[(String, String)]>,
) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let content = if let Some(form) = form {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().map(|(k, v)| (k, v)))
            .finish()
    } else {
        String::new()
    };
    app.clone()
        .oneshot(builder.body(Body::from(content)).unwrap())
        .await
        .unwrap()
}
fn location(response: &Response) -> String {
    response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .into()
}
async fn body(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
async fn json_body(response: Response) -> Value {
    serde_json::from_str(&body(response).await).unwrap()
}

#[tokio::test]
async fn both_oauth_legs_issue_distinct_scoped_tokens_and_rotate_refresh_with_fresh_claims() {
    let fixture = Fixture::new().await;
    let metadata = json_body(
        fixture
            .get("/.well-known/oauth-authorization-server", None)
            .await,
    )
    .await;
    assert_eq!(metadata["issuer"], ORIGIN);
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert!(metadata.get("registration_endpoint").is_none());
    assert!(metadata.get("userinfo_endpoint").is_none());
    let code = fixture.code("openid email groups offline_access").await;
    let tokens = fixture.exchange(&code).await;
    let access = tokens["access_token"].as_str().unwrap();
    let header = decode_header(access).unwrap();
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    let claims = fixture.verify(access, RESOURCE).await;
    assert_eq!(claims["client_id"], "mcp-test");
    assert_eq!(claims["email"], "alice@example.com");
    assert_eq!(claims["groups"], json!(["engineering"]));
    assert_eq!(
        claims["sub"],
        token_hash(&format!("{}\0upstream-alice", fixture.provider.issuer))
    );
    assert!(
        (3500..=3600)
            .contains(&(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap()))
    );
    let id = fixture
        .verify(tokens["id_token"].as_str().unwrap(), "mcp-test")
        .await;
    assert_eq!(id["nonce"], "downstream-nonce");
    assert!(id["auth_time"].as_i64().unwrap() <= Utc::now().timestamp() - 290);
    let old = tokens["refresh_token"].as_str().unwrap();
    fixture.provider.behavior.lock().await.groups = vec!["operations".into()];
    let response = fixture.post("/token", None, &refresh_form(old)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let renewed = json_body(response).await;
    assert!(renewed.get("id_token").is_none());
    assert_ne!(renewed["refresh_token"], old);
    let claims = fixture
        .verify(renewed["access_token"].as_str().unwrap(), RESOURCE)
        .await;
    assert_eq!(claims["groups"], json!(["operations"]));
    let mut narrowed = refresh_form(renewed["refresh_token"].as_str().unwrap());
    narrowed.push(("scope".into(), "email".into()));
    let response = fixture.post("/token", None, &narrowed).await;
    assert_eq!(response.status(), StatusCode::OK);
    let narrowed = json_body(response).await;
    let claims = fixture
        .verify(narrowed["access_token"].as_str().unwrap(), RESOURCE)
        .await;
    assert!(claims.get("groups").is_none());
    assert_eq!(claims["scope"], "email");
    // Reusing any old token revokes the current member of the entire family.
    assert_eq!(
        fixture
            .post("/token", None, &refresh_form(old))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fixture
            .post(
                "/token",
                None,
                &refresh_form(narrowed["refresh_token"].as_str().unwrap())
            )
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn code_binding_checks_do_not_consume_the_code_but_success_is_single_use() {
    let fixture = Fixture::new().await;
    let code = fixture.code("email").await;
    for (field, bad) in [
        ("client_id", "other-client"),
        ("redirect_uri", "http://127.0.0.1:3000/other"),
        ("resource", "https://other.example/mcp"),
        ("code_verifier", "invalid-verifier"),
    ] {
        let mut form = code_form(&code);
        form.iter_mut().find(|(k, _)| k == field).unwrap().1 = bad.into();
        let response = fixture.post("/token", None, &form).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
    }
    let form = code_form(&code);
    let (one, two) = tokio::join!(
        fixture.post("/token", None, &form),
        fixture.post("/token", None, &form)
    );
    let statuses = [one.status(), two.status()];
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
}

#[tokio::test]
async fn browser_binding_and_single_use_state_are_required_without_local_consent() {
    let fixture = Fixture::new().await;
    let (cookie, url) = fixture.begin("email").await;
    let callback = fixture.callback_uri(&url).await;
    assert_eq!(
        fixture.get(&callback, None).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fixture
            .get(&callback, Some("idfrog-browser=another-browser"))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fixture
            .get("/oidc/callback?state=unknown&code=invalid", Some(&cookie))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let response = fixture.get(&callback, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let url = Url::parse(&location(&response)).unwrap();
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert!(query.contains_key("code"));
    assert_eq!(query["state"], "downstream-state");
    assert_eq!(
        fixture.get(&callback, Some(&cookie)).await.status(),
        StatusCode::BAD_REQUEST
    );
    // Removing local consent does not expose an alternative grant-issuance endpoint.
    assert_eq!(
        fixture
            .post("/authorize/consent", Some(&cookie), &[])
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn upstream_denial_returns_only_the_validated_downstream_redirect_and_issuer() {
    let fixture = Fixture::new().await;
    let (cookie, upstream) = fixture.begin("email").await;
    let upstream = Url::parse(&upstream).unwrap();
    let state = upstream
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let response = fixture
        .get(
            &format!("/oidc/callback?state={state}&error=access_denied"),
            Some(&cookie),
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let url = Url::parse(&location(&response)).unwrap();
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["error"], "access_denied");
    assert_eq!(query["state"], "downstream-state");
    assert_eq!(query["iss"], ORIGIN);
    assert!(!query.contains_key("code"));
}

#[tokio::test]
async fn invalid_upstream_signatures_and_oidc_claims_never_issue_a_code() {
    let fixture = Fixture::new().await;
    for mode in [
        "bad_nonce",
        "bad_audience",
        "bad_issuer",
        "expired",
        "future_issued",
        "wrong_key",
        "missing_id_token",
    ] {
        fixture.provider.behavior.lock().await.mode = mode;
        let (cookie, url) = fixture.begin("email").await;
        let callback = fixture.callback_uri(&url).await;
        let response = fixture.get(&callback, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{mode}");
        assert!(!body(response).await.contains("upstream-secret"));
    }
}

#[tokio::test]
async fn groups_are_refreshed_without_group_admission_policy_and_overage_fails_closed() {
    let fixture = Fixture::new().await;
    let code = fixture.code("email groups offline_access").await;
    let tokens = fixture.exchange(&code).await;
    fixture.provider.behavior.lock().await.groups.clear();
    let refreshed = json_body(
        fixture
            .post(
                "/token",
                None,
                &refresh_form(tokens["refresh_token"].as_str().unwrap()),
            )
            .await,
    )
    .await;
    let claims = fixture
        .verify(refreshed["access_token"].as_str().unwrap(), RESOURCE)
        .await;
    assert_eq!(claims["groups"], json!([]));
    fixture.provider.behavior.lock().await.mode = "overage";
    let (cookie, url) = fixture.begin("groups").await;
    let callback = fixture.callback_uri(&url).await;
    assert_eq!(
        fixture.get(&callback, Some(&cookie)).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn refresh_cannot_change_subject_resource_client_or_widen_scopes() {
    let fixture = Fixture::new().await;
    let code = fixture.code("email offline_access").await;
    let tokens = fixture.exchange(&code).await;
    let refresh = tokens["refresh_token"].as_str().unwrap();
    for (field, value) in [
        ("client_id", "other-client"),
        ("resource", "https://other.example/mcp"),
        ("scope", "email groups"),
    ] {
        let mut form = refresh_form(refresh);
        if let Some((_, v)) = form.iter_mut().find(|(k, _)| k == field) {
            *v = value.into();
        } else {
            form.push((field.into(), value.into()));
        }
        assert_eq!(
            fixture.post("/token", None, &form).await.status(),
            StatusCode::BAD_REQUEST,
            "{field}"
        );
    }
    fixture.provider.behavior.lock().await.mode = "changed_subject";
    assert_eq!(
        fixture
            .post("/token", None, &refresh_form(refresh))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn concurrent_refresh_replay_revokes_the_in_flight_family_without_resurrection() {
    let fixture = Fixture::new().await;
    let code = fixture.code("email offline_access").await;
    let tokens = fixture.exchange(&code).await;
    fixture.provider.behavior.lock().await.pause_refresh = true;
    let form = refresh_form(tokens["refresh_token"].as_str().unwrap());
    let app = fixture.app.clone();
    let first_form = form.clone();
    let first =
        tokio::spawn(async move { request(&app, "POST", "/token", None, Some(&first_form)).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.provider.entered.notified(),
    )
    .await
    .unwrap();
    assert_eq!(
        fixture.post("/token", None, &form).await.status(),
        StatusCode::BAD_REQUEST
    );
    fixture.provider.release.notify_one();
    assert_eq!(first.await.unwrap().status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unconfigured_resources_and_unsafe_redirects_are_rejected_before_login() {
    let fixture = Fixture::new().await;
    for (field, value) in [
        ("resource", "https://unconfigured.example/mcp"),
        ("redirect_uri", "https://attacker.example/callback"),
        ("code_challenge_method", "plain"),
        ("code_challenge", "short"),
        ("scope", "invalid\\scope"),
    ] {
        let original = authorization_url("email");
        let mut url = original.clone();
        url.set_query(None);
        for (key, old) in original.query_pairs() {
            url.query_pairs_mut()
                .append_pair(&key, if key == field { value } else { &old });
        }
        let response = fixture
            .get(&format!("{}?{}", url.path(), url.query().unwrap()), None)
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}

#[tokio::test]
async fn restart_keeps_verifiable_access_tokens_but_loses_codes_and_refresh_grants() {
    let fixture = Fixture::new().await;
    let issued_code = fixture.code("email offline_access").await;
    let tokens = fixture.exchange(&issued_code).await;
    let pending_code = fixture.code("email").await;
    let upstream = Upstream::discover(&fixture.config).await.unwrap();
    let restarted = router(AppState::new(
        fixture.config.clone(),
        upstream,
        signing::load(&fixture.config.signing_key_file).unwrap(),
        Store::memory(),
    ));
    assert_eq!(
        request(
            &restarted,
            "POST",
            "/token",
            None,
            Some(&code_form(&pending_code))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &restarted,
            "POST",
            "/token",
            None,
            Some(&refresh_form(tokens["refresh_token"].as_str().unwrap()))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let before = json_body(fixture.get("/jwks.json", None).await).await;
    let after = json_body(request(&restarted, "GET", "/jwks.json", None, None).await).await;
    assert_eq!(before, after);
    fixture
        .verify(tokens["access_token"].as_str().unwrap(), RESOURCE)
        .await;
}

#[tokio::test]
async fn replicas_sharing_a_store_exchange_codes_and_rotate_refresh_grants() {
    let fixture = Fixture::new().await;
    let issued_code = fixture.code("email offline_access").await;
    let tokens = fixture.exchange(&issued_code).await;
    let pending_code = fixture.code("email").await;
    let upstream = Upstream::discover(&fixture.config).await.unwrap();
    let replica = router(AppState::new(
        fixture.config.clone(),
        upstream,
        signing::load(&fixture.config.signing_key_file).unwrap(),
        fixture.store.clone(),
    ));
    let response = request(
        &replica,
        "POST",
        "/token",
        None,
        Some(&code_form(&pending_code)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let spent = tokens["refresh_token"].as_str().unwrap();
    let refreshed =
        json_body(request(&replica, "POST", "/token", None, Some(&refresh_form(spent))).await)
            .await;
    let replacement = refreshed["refresh_token"].as_str().unwrap();
    assert_ne!(replacement, spent);
    // Replaying the spent token on the original replica revokes the family everywhere.
    assert_eq!(
        fixture
            .post("/token", None, &refresh_form(spent))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &replica,
            "POST",
            "/token",
            None,
            Some(&refresh_form(replacement))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn https_origin_uses_host_scoped_secure_browser_cookie_and_oauth_form_errors_are_json() {
    let fixture = Fixture::new().await;
    let mut config = fixture.config.clone();
    config.origin = "https://idfrog.noa.re".into();
    let upstream = Upstream::discover(&config).await.unwrap();
    let secure_app = router(AppState::new(
        config,
        upstream,
        signing::load(&fixture.config.signing_key_file).unwrap(),
        fixture.store.clone(),
    ));
    let url = authorization_url("email");
    let response = request(
        &secure_app,
        "GET",
        &format!("{}?{}", url.path(), url.query().unwrap()),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with("__Host-idfrog-browser="));
    for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(cookie.contains(attribute));
    }
    assert!(!cookie.contains("Domain="));
    let response = fixture.post("/token", None, &[]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"], "invalid_request");
}

#[tokio::test]
async fn es256_upstream_providers_are_supported_alongside_entra_style_rs256() {
    let fixture = Fixture::with_algorithm(Algorithm::ES256).await;
    let code = fixture.code("email groups").await;
    let tokens = fixture.exchange(&code).await;
    let claims = fixture
        .verify(tokens["access_token"].as_str().unwrap(), RESOURCE)
        .await;
    assert_eq!(claims["groups"], json!(["engineering"]));
}

#[tokio::test]
async fn failed_upstream_refresh_or_missing_fresh_id_token_revokes_the_grant() {
    let fixture = Fixture::new().await;
    for mode in ["deny_refresh", "missing_id_token"] {
        fixture.provider.behavior.lock().await.mode = "normal";
        let code = fixture.code("email offline_access").await;
        let tokens = fixture.exchange(&code).await;
        let form = refresh_form(tokens["refresh_token"].as_str().unwrap());
        fixture.provider.behavior.lock().await.mode = mode;
        let response = fixture.post("/token", None, &form).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{mode}");
        assert_eq!(json_body(response).await["error"], "invalid_grant");
        fixture.provider.behavior.lock().await.mode = "normal";
        assert_eq!(
            fixture.post("/token", None, &form).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn certificate_client_authentication_covers_code_exchange_and_refresh_without_client_secret()
{
    let fixture = Fixture::with_authentication(Algorithm::RS256, true).await;
    let code = fixture.code("openid email groups offline_access").await;
    let tokens = fixture.exchange(&code).await;
    fixture
        .verify(tokens["access_token"].as_str().unwrap(), RESOURCE)
        .await;
    let response = fixture
        .post(
            "/token",
            None,
            &refresh_form(tokens["refresh_token"].as_str().unwrap()),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let renewed = json_body(response).await;
    fixture
        .verify(renewed["access_token"].as_str().unwrap(), RESOURCE)
        .await;
    assert_eq!(fixture.provider.assertion_ids.lock().await.len(), 2);
}

#[tokio::test]
async fn api_tokens_must_be_signed_bound_and_carry_application_scopes() {
    let fixture = Fixture::new().await;
    for mode in [
        "access_missing_scope",
        "access_wrong_prefix",
        "access_app_only",
        "access_wrong_audience",
        "access_uri_audience",
        "access_wrong_issuer",
        "access_wrong_user",
        "access_wrong_client",
        "access_expired",
        "access_future",
        "access_future_iat",
        "access_wrong_key",
        "access_opaque",
    ] {
        fixture.provider.behavior.lock().await.mode = mode;
        let (cookie, url) = fixture.begin("email").await;
        let callback = fixture.callback_uri(&url).await;
        let response = fixture.get(&callback, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{mode}");
    }
}

#[tokio::test]
async fn lost_upstream_api_permission_prevents_refresh_and_revokes_the_family() {
    let fixture = Fixture::new().await;
    let code = fixture.code("email offline_access").await;
    let tokens = fixture.exchange(&code).await;
    let form = refresh_form(tokens["refresh_token"].as_str().unwrap());
    fixture.provider.behavior.lock().await.mode = "access_missing_scope";
    let response = fixture.post("/token", None, &form).await;
    assert_eq!(json_body(response).await["error"], "invalid_grant");
    fixture.provider.behavior.lock().await.mode = "normal";
    assert_eq!(
        fixture.post("/token", None, &form).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn downstream_access_token_does_not_outlive_the_upstream_permission() {
    let fixture = Fixture::new().await;
    fixture.provider.behavior.lock().await.mode = "access_short_lived";
    let code = fixture.code("email").await;
    let tokens = fixture.exchange(&code).await;
    let claims = fixture
        .verify(tokens["access_token"].as_str().unwrap(), RESOURCE)
        .await;
    let ttl = tokens["expires_in"].as_i64().unwrap();
    assert!((1..=120).contains(&ttl));
    assert!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap() <= 120);
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn request_and_failure_logs_explain_errors_without_exposing_oauth_credentials() {
    let logs = LogBuffer::default();
    let writer = logs.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .compact()
            .with_target(false)
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();
    let fixture = Fixture::new().await;
    for mode in [
        "access_missing_scope",
        "access_wrong_audience",
        "access_uri_audience",
        "bad_nonce",
        "token_endpoint_error",
    ] {
        fixture.provider.behavior.lock().await.mode = mode;
        let (cookie, upstream) = fixture.begin("email").await;
        let callback = fixture.callback_uri(&upstream).await;
        let response = fixture.get(&callback, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{mode}");
        assert!(body(response).await.contains("Authorization failed"));
    }
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz?code=query-private-sentinel&state=state-private-sentinel")
                .header(header::AUTHORIZATION, "Bearer header-private-sentinel")
                .header(header::COOKIE, "idfrog-browser=cookie-private-sentinel")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fixture
            .post(
                "/token",
                None,
                &[("code".into(), "body-private-sentinel".into())]
            )
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fixture.get("/missing-route", None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fixture.get("/oidc/callback", None).await.status(),
        StatusCode::BAD_REQUEST
    );
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for expected in [
        "method=GET",
        "method=POST",
        "path=/healthz",
        "path=/token",
        "path=/missing-route",
        "status=200",
        "status=404",
        "status=502",
        "latency_ms=",
        "Missing delegated API scopes",
        "Access token audience mismatch",
        "id_token_nonce_mismatch",
        "invalid_client",
        "aadsts_code=",
        "700027",
    ] {
        assert!(
            text.contains(expected),
            "missing diagnostic {expected}: {text}"
        );
    }
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("path=/healthz"))
            .count(),
        1
    );
    for noise in [
        "request_id=",
        "request started",
        "http_request",
        "idp_server::",
        "idfrog::",
        "uri=",
        "version=HTTP",
    ] {
        assert!(!text.contains(noise), "unnecessary log field: {noise}");
    }
    for secret in [
        "query-private-sentinel",
        "state-private-sentinel",
        "header-private-sentinel",
        "cookie-private-sentinel",
        "body-private-sentinel",
        "provider-private-sentinel",
        "upstream-secret",
        "alice@example.com",
        "?code=",
        "nonce=",
    ] {
        assert!(
            !text.contains(secret),
            "sensitive value was logged: {secret}"
        );
    }
}

#[tokio::test]
async fn arbitrary_api_permissions_are_forwarded_without_an_idfrog_scope_allowlist() {
    let fixture = Fixture::new().await;
    fixture.provider.behavior.lock().await.scopes =
        format!("api://{API_ID}/Read api://{API_ID}/Dashboard.Edit api://different-api/Root Read");
    let code = fixture.code("email NotGrantedByEntra").await;
    let tokens = fixture.exchange(&code).await;
    assert_eq!(tokens["scope"], "email Read Dashboard.Edit");
    let claims = fixture
        .verify(tokens["access_token"].as_str().unwrap(), RESOURCE)
        .await;
    assert_eq!(claims["scope"], tokens["scope"]);
    assert_eq!(claims["aud"], RESOURCE);
    assert_eq!(claims["email"], "alice@example.com");
    for granted in ["Read", "FullOther", "Custom.Permission"] {
        fixture.provider.behavior.lock().await.scopes = granted.into();
        let code = fixture.code("email").await;
        let tokens = fixture.exchange(&code).await;
        assert_eq!(tokens["scope"], format!("email {granted}"));
    }
}

#[tokio::test]
async fn refresh_removes_revoked_api_permissions_and_does_not_add_new_ones() {
    let fixture = Fixture::new().await;
    fixture.provider.behavior.lock().await.scopes = "Read Write".into();
    let code = fixture.code("email offline_access").await;
    let tokens = fixture.exchange(&code).await;
    assert_eq!(tokens["scope"], "email offline_access Read Write");
    fixture.provider.behavior.lock().await.scopes = "Read NewPermission".into();
    let response = fixture
        .post(
            "/token",
            None,
            &refresh_form(tokens["refresh_token"].as_str().unwrap()),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = json_body(response).await;
    assert_eq!(tokens["scope"], "email offline_access Read");
    fixture.provider.behavior.lock().await.scopes = "Read Write NewPermission".into();
    let mut form = refresh_form(tokens["refresh_token"].as_str().unwrap());
    form.push(("scope".into(), "email Read".into()));
    let response = fixture.post("/token", None, &form).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = json_body(response).await;
    assert_eq!(tokens["scope"], "email Read");
    let mut form = refresh_form(tokens["refresh_token"].as_str().unwrap());
    form.push(("scope".into(), "email Write".into()));
    let response = fixture.post("/token", None, &form).await;
    assert_eq!(json_body(response).await["error"], "invalid_scope");
}

#[tokio::test]
async fn api_scope_names_do_not_implicitly_grant_oidc_claim_disclosure() {
    let fixture = Fixture::new().await;
    fixture.provider.behavior.lock().await.scopes = "email groups openid offline_access".into();
    let code = fixture.code("Read").await;
    let tokens = fixture.exchange(&code).await;
    assert!(tokens.get("id_token").is_none());
    assert!(tokens.get("refresh_token").is_none());
    let claims = fixture
        .verify(tokens["access_token"].as_str().unwrap(), RESOURCE)
        .await;
    assert!(claims.get("email").is_none());
    assert_eq!(claims["groups"], json!([]));
}
