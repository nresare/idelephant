use crate::auth::IDENTITY;
use crate::error::IdentityError;
use crate::oidc::{JwksResponse, OidcService, OpenidConfiguration};
use crate::persistence::{
    AuthorizationCode, CreateAuthorizationCode, Identity, OAuthClient, PersistenceService,
};
use crate::util::Token;
use crate::web::Templates;
use crate::AppState;
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower_sessions::Session;
use url::Url;

pub fn oauth_routes() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize))
        .route("/authorize/resume", get(resume_authorize))
        .route("/authorize/consent", post(authorize_consent))
        .route("/token", post(token))
        .route("/oauth-client", post(create_oauth_client))
        .route("/userinfo", get(userinfo))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/jwks.json", get(jwks))
}

pub const PENDING_AUTHORIZATION: &str = "idelephant.oauth.pending-authorization";

#[derive(Debug, Deserialize)]
struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PendingAuthorizationRequest {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: String,
}

#[derive(Debug, Deserialize)]
struct ConsentRequest {
    decision: String,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateOAuthClientRequest {
    client_id: String,
    name: String,
    redirect_uris: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserinfoResponse {
    sub: String,
    email: String,
}

async fn create_oauth_client(
    session: Session,
    State(persistence_service): State<PersistenceService>,
    Json(request): Json<CreateOAuthClientRequest>,
) -> Result<axum::http::StatusCode, IdentityError> {
    let Some(identity): Option<Identity> = session.get(IDENTITY).await? else {
        return Ok(axum::http::StatusCode::UNAUTHORIZED);
    };
    if !identity.admin {
        return Ok(axum::http::StatusCode::UNAUTHORIZED);
    }
    validate_client_registration_request(&request)?;
    persistence_service
        .create_oauth_client(&request.client_id, &request.name, request.redirect_uris)
        .await?;
    Ok(axum::http::StatusCode::CREATED)
}

async fn authorize(
    Query(request): Query<AuthorizationRequest>,
    session: Session,
    State(persistence_service): State<PersistenceService>,
    State(oidc_service): State<OidcService>,
    State(templates): State<Templates>,
) -> Result<Response, IdentityError> {
    let Some(client) = persistence_service
        .fetch_oauth_client(&request.client_id)
        .await?
    else {
        return Err(IdentityError::BadRequest(
            "Unknown OAuth client".to_string(),
        ));
    };
    let pending = validate_authorization_request(request, &client)?;
    continue_authorization(
        session,
        persistence_service,
        oidc_service,
        templates,
        &client,
        pending,
        false,
    )
    .await
}

async fn resume_authorize(
    session: Session,
    State(persistence_service): State<PersistenceService>,
    State(oidc_service): State<OidcService>,
    State(templates): State<Templates>,
) -> Result<Response, IdentityError> {
    let Some(pending): Option<PendingAuthorizationRequest> =
        session.get(PENDING_AUTHORIZATION).await?
    else {
        return Err(IdentityError::BadRequest(
            "No pending authorization request".to_string(),
        ));
    };

    let Some(client) = persistence_service
        .fetch_oauth_client(&pending.client_id)
        .await?
    else {
        return Err(IdentityError::BadRequest(
            "Pending authorization request references unknown client".to_string(),
        ));
    };

    continue_authorization(
        session,
        persistence_service,
        oidc_service,
        templates,
        &client,
        pending,
        true,
    )
    .await
}

async fn authorize_consent(
    session: Session,
    State(persistence_service): State<PersistenceService>,
    Form(consent): Form<ConsentRequest>,
) -> Result<Redirect, IdentityError> {
    let Some(identity): Option<Identity> = session.get(IDENTITY).await? else {
        return Err(IdentityError::BadRequest(
            "No authenticated identity found for authorization".to_string(),
        ));
    };
    let Some(pending): Option<PendingAuthorizationRequest> =
        session.get(PENDING_AUTHORIZATION).await?
    else {
        return Err(IdentityError::BadRequest(
            "No pending authorization request".to_string(),
        ));
    };

    if consent.decision == "deny" {
        session
            .remove::<PendingAuthorizationRequest>(PENDING_AUTHORIZATION)
            .await?;
        return Ok(Redirect::to(&build_redirect(
            &pending.redirect_uri,
            &[
                ("error", Some("access_denied")),
                ("state", pending.state.as_deref()),
            ],
        )?));
    }
    if consent.decision != "approve" {
        return Err(IdentityError::BadRequest(
            "Unknown authorization decision".to_string(),
        ));
    }

    persistence_service
        .grant_consent(
            &identity.id()?,
            &pending.client_id,
            pending.scopes.clone(),
            chrono::Utc::now(),
        )
        .await?;

    let code = Token::random().base64();
    persistence_service
        .create_authorization_code(CreateAuthorizationCode {
            code: code.clone(),
            client_id: pending.client_id.clone(),
            subject_id: identity.id()?,
            redirect_uri: pending.redirect_uri.clone(),
            scopes: pending.scopes.clone(),
            nonce: pending.nonce.clone(),
            code_challenge: pending.code_challenge.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        })
        .await?;
    session
        .remove::<PendingAuthorizationRequest>(PENDING_AUTHORIZATION)
        .await?;

    Ok(Redirect::to(&build_redirect(
        &pending.redirect_uri,
        &[("code", Some(&code)), ("state", pending.state.as_deref())],
    )?))
}

async fn token(
    State(persistence_service): State<PersistenceService>,
    State(oidc_service): State<OidcService>,
    Form(request): Form<TokenRequest>,
) -> Result<axum::Json<TokenResponse>, IdentityError> {
    if request.grant_type != "authorization_code" {
        return Err(IdentityError::BadRequest(
            "Only grant_type=authorization_code is supported".to_string(),
        ));
    }

    let Some(code) = persistence_service
        .fetch_authorization_code(&request.code)
        .await?
    else {
        return Err(IdentityError::BadRequest(
            "Unknown authorization code".to_string(),
        ));
    };

    validate_token_request(&request, &code)?;

    let Some(_client) = persistence_service
        .fetch_oauth_client(&request.client_id)
        .await?
    else {
        return Err(IdentityError::BadRequest(
            "Unknown OAuth client".to_string(),
        ));
    };
    if !verify_pkce(&request.code_verifier, &code.code_challenge) {
        return Err(IdentityError::BadRequest(
            "code_verifier did not match the PKCE challenge".to_string(),
        ));
    }

    let access_token = Token::random().base64();
    let expires_in = chrono::Duration::hours(1);
    persistence_service
        .create_access_token(
            &access_token,
            &code.client_id,
            &code.subject_id,
            code.scopes.clone(),
            chrono::Utc::now() + expires_in,
        )
        .await?;
    persistence_service
        .delete_authorization_code(&request.code)
        .await?;

    let id_token = if code.scopes.iter().any(|scope| scope == "openid") {
        let identity = persistence_service
            .fetch_identity(&code.subject_id)
            .await?
            .ok_or_else(|| {
                IdentityError::BadRequest(
                    "authorization code references unknown identity".to_string(),
                )
            })?;
        Some(
            oidc_service
                .mint_id_token(
                    &code.subject_id,
                    &code.client_id,
                    code.nonce.as_deref(),
                    &identity.email,
                )
                .await?,
        )
    } else {
        None
    };

    Ok(axum::Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: expires_in.num_seconds(),
        scope: code.scopes.join(" "),
        id_token,
    }))
}

async fn userinfo(
    headers: HeaderMap,
    State(persistence_service): State<PersistenceService>,
) -> Result<axum::Json<UserinfoResponse>, IdentityError> {
    let token = bearer_token(&headers)?;
    let access_token = persistence_service
        .fetch_access_token(token)
        .await?
        .ok_or_else(|| IdentityError::BadRequest("Unknown access token".to_string()))?;
    if access_token.expires_at < chrono::Utc::now() {
        return Err(IdentityError::BadRequest(
            "access token has expired".to_string(),
        ));
    }
    let identity = persistence_service
        .fetch_identity(&access_token.subject_id)
        .await?
        .ok_or_else(|| IdentityError::BadRequest("Unknown identity".to_string()))?;
    Ok(axum::Json(UserinfoResponse {
        sub: access_token.subject_id,
        email: identity.email,
    }))
}

async fn openid_configuration(
    State(oidc_service): State<OidcService>,
) -> axum::Json<OpenidConfiguration> {
    axum::Json(oidc_service.configuration())
}

async fn jwks(
    State(oidc_service): State<OidcService>,
) -> Result<axum::Json<JwksResponse>, IdentityError> {
    Ok(axum::Json(oidc_service.jwks().await?))
}

async fn continue_authorization(
    session: Session,
    persistence_service: PersistenceService,
    oidc_service: OidcService,
    templates: Templates,
    client: &OAuthClient,
    pending: PendingAuthorizationRequest,
    pending_stored: bool,
) -> Result<Response, IdentityError> {
    let Some(identity): Option<Identity> = session.get(IDENTITY).await? else {
        if !pending_stored {
            session.insert(PENDING_AUTHORIZATION, &pending).await?;
        }
        return Ok(Redirect::to("/").into_response());
    };

    let existing_consent = persistence_service
        .fetch_consent_grant(&identity.id()?, &pending.client_id)
        .await?;
    if consent_satisfies_request(existing_consent.as_ref(), &pending.scopes) {
        let code = Token::random().base64();
        persistence_service
            .create_authorization_code(CreateAuthorizationCode {
                code: code.clone(),
                client_id: pending.client_id.clone(),
                subject_id: identity.id()?,
                redirect_uri: pending.redirect_uri.clone(),
                scopes: pending.scopes.clone(),
                nonce: pending.nonce.clone(),
                code_challenge: pending.code_challenge.clone(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            })
            .await?;
        if pending_stored {
            session
                .remove::<PendingAuthorizationRequest>(PENDING_AUTHORIZATION)
                .await?;
        }
        return Ok(Redirect::to(&build_redirect(
            &pending.redirect_uri,
            &[("code", Some(&code)), ("state", pending.state.as_deref())],
        )?)
        .into_response());
    }

    if !pending_stored {
        session.insert(PENDING_AUTHORIZATION, &pending).await?;
    }

    let body = templates.render(
        "authorize",
        &json!({
            "client_name": client.name,
            "idp_basename": oidc_service.issuer_basename(),
            "identity_email": identity.email,
            "scopes": pending.scopes,
            "requests_email": pending.scopes.iter().any(|scope| scope == "email"),
        }),
    )?;
    Ok(Html(body).into_response())
}

fn validate_authorization_request(
    request: AuthorizationRequest,
    client: &OAuthClient,
) -> Result<PendingAuthorizationRequest, IdentityError> {
    if request.response_type != "code" {
        return Err(IdentityError::BadRequest(
            "Only response_type=code is supported".to_string(),
        ));
    }
    if !client.redirect_uris.contains(&request.redirect_uri) {
        return Err(IdentityError::BadRequest(
            "redirect_uri is not registered for this client".to_string(),
        ));
    }
    let scopes = parse_scopes(&request.scope)?;
    for scope in &scopes {
        if !allowed_scopes().iter().any(|allowed| allowed == scope) {
            return Err(IdentityError::BadRequest(format!(
                "scope '{scope}' is not supported"
            )));
        }
    }
    let code_challenge = request
        .code_challenge
        .ok_or_else(|| IdentityError::BadRequest("code_challenge is required".to_string()))?;
    let code_challenge_method = request.code_challenge_method.ok_or_else(|| {
        IdentityError::BadRequest("code_challenge_method is required".to_string())
    })?;
    if code_challenge_method != "S256" {
        return Err(IdentityError::BadRequest(
            "Only PKCE code_challenge_method=S256 is supported".to_string(),
        ));
    }
    if code_challenge.is_empty() {
        return Err(IdentityError::BadRequest(
            "code_challenge must not be empty".to_string(),
        ));
    }

    Ok(PendingAuthorizationRequest {
        client_id: client.client_id.clone(),
        redirect_uri: request.redirect_uri,
        scopes,
        state: request.state,
        nonce: request.nonce,
        code_challenge,
    })
}

fn parse_scopes(scope: &str) -> Result<Vec<String>, IdentityError> {
    let scopes: Vec<String> = scope
        .split(' ')
        .filter(|scope| !scope.is_empty())
        .map(ToString::to_string)
        .collect();
    if scopes.is_empty() {
        return Err(IdentityError::BadRequest(
            "scope must not be empty".to_string(),
        ));
    }
    if !scopes.iter().any(|scope| scope == "openid") {
        return Err(IdentityError::BadRequest(
            "scope must include 'openid'".to_string(),
        ));
    }
    Ok(scopes)
}

fn validate_token_request(
    request: &TokenRequest,
    code: &AuthorizationCode,
) -> Result<(), IdentityError> {
    if code.client_id != request.client_id {
        return Err(IdentityError::BadRequest(
            "authorization code was not issued to this client".to_string(),
        ));
    }
    if code.redirect_uri != request.redirect_uri {
        return Err(IdentityError::BadRequest(
            "redirect_uri did not match the authorization request".to_string(),
        ));
    }
    if code.expires_at < chrono::Utc::now() {
        return Err(IdentityError::BadRequest(
            "authorization code has expired".to_string(),
        ));
    }
    if request.code_verifier.is_empty() {
        return Err(IdentityError::BadRequest(
            "code_verifier must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_client_registration_request(
    request: &CreateOAuthClientRequest,
) -> Result<(), IdentityError> {
    if request.client_id.is_empty() {
        return Err(IdentityError::BadRequest(
            "client_id must not be empty".to_string(),
        ));
    }
    if request.name.is_empty() {
        return Err(IdentityError::BadRequest(
            "name must not be empty".to_string(),
        ));
    }
    if request.redirect_uris.is_empty() {
        return Err(IdentityError::BadRequest(
            "At least one redirect_uri is required".to_string(),
        ));
    }
    for redirect_uri in &request.redirect_uris {
        Url::parse(redirect_uri).map_err(|e| {
            IdentityError::BadRequest(format!("Invalid redirect URI '{redirect_uri}': {e}"))
        })?;
    }
    Ok(())
}

fn allowed_scopes() -> [&'static str; 3] {
    ["openid", "profile", "email"]
}

fn verify_pkce(code_verifier: &str, expected_challenge: &str) -> bool {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    challenge == expected_challenge
}

fn consent_satisfies_request(
    consent: Option<&crate::persistence::ConsentGrant>,
    requested_scopes: &[String],
) -> bool {
    let Some(consent) = consent else {
        return false;
    };
    requested_scopes
        .iter()
        .all(|scope| consent.scopes.iter().any(|granted| granted == scope))
}

fn build_redirect(
    redirect_uri: &str,
    params: &[(&str, Option<&str>)],
) -> Result<String, IdentityError> {
    let mut redirect = Url::parse(redirect_uri)
        .map_err(|e| IdentityError::BadRequest(format!("Invalid redirect URI: {e}")))?;
    {
        let mut pairs = redirect.query_pairs_mut();
        for (key, value) in params {
            if let Some(value) = value {
                pairs.append_pair(key, value);
            }
        }
    }
    Ok(redirect.to_string())
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, IdentityError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| IdentityError::BadRequest("Missing Authorization header".to_string()))?;
    let authorization = authorization
        .to_str()
        .map_err(|_| IdentityError::BadRequest("Invalid Authorization header".to_string()))?;
    let token = authorization
        .strip_prefix("Bearer ")
        .ok_or_else(|| IdentityError::BadRequest("Expected Bearer token".to_string()))?;
    if token.is_empty() {
        return Err(IdentityError::BadRequest(
            "Bearer token must not be empty".to_string(),
        ));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::{
        bearer_token, build_redirect, consent_satisfies_request, validate_authorization_request,
        validate_token_request, verify_pkce, AuthorizationRequest, CreateOAuthClientRequest,
        PendingAuthorizationRequest, TokenRequest, PENDING_AUTHORIZATION,
    };
    use crate::auth::IDENTITY;
    use crate::config::EmailConfig;
    use crate::error::IdentityError;
    use crate::invite::InviteService;
    use crate::oidc::OidcService;
    use crate::persistence::{
        mem_db, AuthorizationCode, ConsentGrant, Credential, Identity, IdentityState, OAuthClient,
        PersistenceService,
    };
    use crate::register::RegistrationService;
    use crate::web::Templates;
    use crate::AppState;
    use axum::body::{to_bytes, Body};
    use axum::extract::{Query, State};
    use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chrono::{Duration, Utc};
    use serde::Deserialize;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use surrealdb::types::RecordId;
    use tower::ServiceExt;
    use tower_sessions::Session;
    use url::Url;

    #[derive(Deserialize)]
    struct TestLoginRequest {
        user_id: String,
    }

    #[derive(Deserialize)]
    struct TokenJson {
        access_token: String,
        id_token: Option<String>,
    }

    fn admin_identity() -> Identity {
        Identity {
            email: "root@example.com".to_string(),
            created: Utc::now(),
            admin: true,
            id: None,
            state: IdentityState::Active {
                credentials: vec![Credential {
                    id: b"credential".to_vec(),
                    public_key: b"public-key".to_vec(),
                    public_key_algorithm: -7,
                    sign_count: 0,
                }],
            },
        }
    }

    fn client() -> OAuthClient {
        OAuthClient {
            client_id: "client-1".to_string(),
            name: "Example client".to_string(),
            redirect_uris: vec!["http://localhost:4000/callback".to_string()],
            id: RecordId::new("oauth_client", "client-1"),
        }
    }

    #[test]
    fn validate_authorization_request_accepts_valid_request() {
        let request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "client-1".to_string(),
            redirect_uri: "http://localhost:4000/callback".to_string(),
            scope: "openid email".to_string(),
            state: Some("state-123".to_string()),
            nonce: Some("nonce-123".to_string()),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
        };

        let pending = validate_authorization_request(request, &client()).unwrap();
        assert_eq!(pending.client_id, "client-1");
        assert_eq!(
            pending.scopes,
            vec!["openid".to_string(), "email".to_string()]
        );
        assert_eq!(pending.state.as_deref(), Some("state-123"));
        assert_eq!(pending.nonce.as_deref(), Some("nonce-123"));
    }

    #[test]
    fn validate_authorization_request_rejects_unregistered_redirect_uri() {
        let request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "client-1".to_string(),
            redirect_uri: "http://localhost:5000/callback".to_string(),
            scope: "openid".to_string(),
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
        };

        let err = validate_authorization_request(request, &client()).unwrap_err();
        assert!(matches!(err, IdentityError::BadRequest(_)));
    }

    #[test]
    fn validate_authorization_request_rejects_missing_openid_scope() {
        let request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "client-1".to_string(),
            redirect_uri: "http://localhost:4000/callback".to_string(),
            scope: "email".to_string(),
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
        };

        let err = validate_authorization_request(request, &client()).unwrap_err();
        assert!(matches!(err, IdentityError::BadRequest(_)));
    }

    fn token_request() -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: "code-123".to_string(),
            redirect_uri: "http://localhost:4000/callback".to_string(),
            client_id: "client-1".to_string(),
            code_verifier: "verifier-123".to_string(),
        }
    }

    fn authorization_code(code_challenge: String) -> AuthorizationCode {
        AuthorizationCode {
            code: "code-123".to_string(),
            client_id: "client-1".to_string(),
            subject_id: "identity:alice".to_string(),
            redirect_uri: "http://localhost:4000/callback".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
            nonce: Some("nonce-123".to_string()),
            code_challenge,
            expires_at: Utc::now() + Duration::minutes(5),
            id: RecordId::new("authorization_code", "code-123"),
        }
    }

    #[test]
    fn build_redirect_appends_code_and_state() {
        let redirect = build_redirect(
            "http://localhost:4000/callback",
            &[("code", Some("code-123")), ("state", Some("state-123"))],
        )
        .unwrap();
        assert_eq!(
            redirect,
            "http://localhost:4000/callback?code=code-123&state=state-123"
        );
    }

    #[test]
    fn consent_satisfies_request_requires_all_scopes() {
        let consent = ConsentGrant {
            subject_id: "identity:alice".to_string(),
            client_id: "client-1".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
            created_at: Utc::now(),
            id: RecordId::new("consent_grant", "grant-1"),
        };

        assert!(consent_satisfies_request(
            Some(&consent),
            &["openid".to_string()]
        ));
        assert!(!consent_satisfies_request(
            Some(&consent),
            &["openid".to_string(), "profile".to_string()]
        ));
    }

    #[test]
    fn verify_pkce_accepts_matching_verifier() {
        let verifier = "verifier-123";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert!(verify_pkce(verifier, &challenge));
    }

    #[test]
    fn validate_token_request_rejects_expired_code() {
        let request = token_request();
        let mut code = authorization_code("challenge".to_string());
        code.expires_at = Utc::now() - Duration::seconds(1);

        let err = validate_token_request(&request, &code).unwrap_err();
        assert!(matches!(err, IdentityError::BadRequest(_)));
    }

    #[test]
    fn bearer_token_extracts_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token-123"),
        );
        assert_eq!(bearer_token(&headers).unwrap(), "token-123");
    }

    async fn test_login(
        Query(query): Query<TestLoginRequest>,
        session: Session,
        State(persistence_service): State<PersistenceService>,
    ) -> Result<StatusCode, IdentityError> {
        let identity = persistence_service
            .fetch_identity(&query.user_id)
            .await?
            .ok_or_else(|| IdentityError::BadRequest("Unknown test identity".to_string()))?;
        session.insert(IDENTITY, &identity).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    async fn test_pending_authorization(
        session: Session,
    ) -> Result<axum::Json<bool>, IdentityError> {
        Ok(axum::Json(
            session
                .get::<PendingAuthorizationRequest>(PENDING_AUTHORIZATION)
                .await?
                .is_some(),
        ))
    }

    fn test_app(
        state: AppState,
        db: std::sync::Arc<surrealdb::Surreal<surrealdb::engine::any::Any>>,
    ) -> Router {
        Router::new()
            .route("/test-login", get(test_login))
            .route(
                "/test-pending-authorization",
                get(test_pending_authorization),
            )
            .merge(crate::oauth::oauth_routes())
            .layer(crate::make_session_layer(db.clone()))
            .with_state(state)
    }

    async fn response_body(response: axum::response::Response) -> Vec<u8> {
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    fn session_cookie(response: &axum::response::Response) -> String {
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn oidc_smoke_test() -> anyhow::Result<()> {
        let db = mem_db().await?;
        let persistence = Arc::new(PersistenceService::new(db.clone()));
        let user_id = persistence
            .persist_identity(Identity {
                email: "alice@example.com".to_string(),
                ..admin_identity()
            })
            .await?;
        let mut alice = persistence.fetch_identity(&user_id).await?.unwrap();
        alice.admin = false;
        persistence.update_identity(&alice).await?;
        persistence
            .create_oauth_client(
                "client-1",
                "Example client",
                vec!["http://localhost:4000/callback".to_string()],
            )
            .await?;

        let state = AppState {
            ps: persistence.clone(),
            is: Arc::new(InviteService::new(
                persistence.clone(),
                &EmailConfig {
                    relay_host: "localhost".to_string(),
                    username: None,
                    password_file: None,
                    sender_email: "test@example.com".to_string(),
                },
                "http://localhost:8080",
            )?),
            templates: Arc::new(Templates::new()?),
            oidc: Arc::new(OidcService::new(
                "http://localhost:8080",
                persistence.as_ref().clone(),
            )),
            rs: Arc::new(RegistrationService::new("http://localhost:8080")?),
        };
        let app = test_app(state, db);

        let discovery = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(discovery.status(), StatusCode::OK);
        let discovery_json: Value = serde_json::from_slice(&response_body(discovery).await)?;
        assert_eq!(
            discovery_json["issuer"],
            Value::String("http://localhost:8080".to_string())
        );

        let jwks = app
            .clone()
            .oneshot(Request::builder().uri("/jwks.json").body(Body::empty())?)
            .await?;
        assert_eq!(jwks.status(), StatusCode::OK);
        let jwks_json: Value = serde_json::from_slice(&response_body(jwks).await)?;
        assert_eq!(jwks_json["keys"].as_array().unwrap().len(), 2);

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/test-login?user_id={user_id}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(login.status(), StatusCode::NO_CONTENT);
        let cookie = session_cookie(&login);

        let verifier = "verifier-123";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let authorize = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/authorize?response_type=code&client_id=client-1&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback&scope=openid%20email&state=state-123&nonce=nonce-123&code_challenge={challenge}&code_challenge_method=S256"
                    ))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(authorize.status(), StatusCode::OK);
        let authorize_body = String::from_utf8(response_body(authorize).await)?;
        assert!(authorize_body
            .contains("The website Example client is attempting to use this service for logins."));

        let consent = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/authorize/consent")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("decision=approve"))?,
            )
            .await?;
        assert_eq!(consent.status(), StatusCode::SEE_OTHER);
        let location = consent
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()?
            .to_string();
        let redirect = Url::parse(&location)?;
        let query: std::collections::HashMap<String, String> =
            redirect.query_pairs().into_owned().collect();
        let code = query.get("code").unwrap().to_string();
        assert_eq!(query.get("state").unwrap(), "state-123");

        let token = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=authorization_code&code={code}&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback&client_id=client-1&code_verifier={verifier}"
                    )))?,
            )
            .await?;
        assert_eq!(token.status(), StatusCode::OK);
        let token_json: TokenJson = serde_json::from_slice(&response_body(token).await)?;
        assert!(!token_json.access_token.is_empty());
        assert_eq!(token_json.id_token.as_ref().unwrap().split('.').count(), 3);

        let userinfo = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/userinfo")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", token_json.access_token),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(userinfo.status(), StatusCode::OK);
        let userinfo_json: Value = serde_json::from_slice(&response_body(userinfo).await)?;
        assert_eq!(userinfo_json["sub"], Value::String(user_id));
        assert_eq!(
            userinfo_json["email"],
            Value::String("alice@example.com".to_string())
        );

        Ok(())
    }

    #[tokio::test]
    async fn authorize_without_consent_does_not_store_pending_authorization() -> anyhow::Result<()>
    {
        let db = mem_db().await?;
        let persistence = Arc::new(PersistenceService::new(db.clone()));
        let user_id = persistence
            .persist_identity(Identity {
                email: "alice@example.com".to_string(),
                ..admin_identity()
            })
            .await?;
        let mut alice = persistence.fetch_identity(&user_id).await?.unwrap();
        alice.admin = false;
        persistence.update_identity(&alice).await?;
        persistence
            .create_oauth_client(
                "client-1",
                "Example client",
                vec!["http://localhost:4000/callback".to_string()],
            )
            .await?;
        persistence
            .grant_consent(
                &user_id,
                "client-1",
                vec!["openid".to_string(), "email".to_string()],
                Utc::now(),
            )
            .await?;

        let state = AppState {
            ps: persistence.clone(),
            is: Arc::new(InviteService::new(
                persistence.clone(),
                &EmailConfig {
                    relay_host: "localhost".to_string(),
                    username: None,
                    password_file: None,
                    sender_email: "test@example.com".to_string(),
                },
                "http://localhost:8080",
            )?),
            templates: Arc::new(Templates::new()?),
            oidc: Arc::new(OidcService::new(
                "http://localhost:8080",
                persistence.as_ref().clone(),
            )),
            rs: Arc::new(RegistrationService::new("http://localhost:8080")?),
        };
        let app = test_app(state, db);

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/test-login?user_id={user_id}"))
                    .body(Body::empty())?,
            )
            .await?;
        let cookie = session_cookie(&login);

        let verifier = "verifier-123";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let authorize = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/authorize?response_type=code&client_id=client-1&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback&scope=openid%20email&state=state-123&nonce=nonce-123&code_challenge={challenge}&code_challenge_method=S256"
                    ))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(authorize.status(), StatusCode::SEE_OTHER);

        let pending = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/test-pending-authorization")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(pending.status(), StatusCode::OK);
        let pending_json: bool = serde_json::from_slice(&response_body(pending).await)?;
        assert!(!pending_json);

        Ok(())
    }

    #[tokio::test]
    async fn authorization_code_cannot_be_reused_after_token_exchange() -> anyhow::Result<()> {
        let db = mem_db().await?;
        let persistence = Arc::new(PersistenceService::new(db.clone()));
        let user_id = persistence
            .persist_identity(Identity {
                email: "alice@example.com".to_string(),
                ..admin_identity()
            })
            .await?;
        let mut alice = persistence.fetch_identity(&user_id).await?.unwrap();
        alice.admin = false;
        persistence.update_identity(&alice).await?;
        persistence
            .create_oauth_client(
                "client-1",
                "Example client",
                vec!["http://localhost:4000/callback".to_string()],
            )
            .await?;

        let state = AppState {
            ps: persistence.clone(),
            is: Arc::new(InviteService::new(
                persistence.clone(),
                &EmailConfig {
                    relay_host: "localhost".to_string(),
                    username: None,
                    password_file: None,
                    sender_email: "test@example.com".to_string(),
                },
                "http://localhost:8080",
            )?),
            templates: Arc::new(Templates::new()?),
            oidc: Arc::new(OidcService::new(
                "http://localhost:8080",
                persistence.as_ref().clone(),
            )),
            rs: Arc::new(RegistrationService::new("http://localhost:8080")?),
        };
        let app = test_app(state, db);

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/test-login?user_id={user_id}"))
                    .body(Body::empty())?,
            )
            .await?;
        let cookie = session_cookie(&login);

        let verifier = "verifier-123";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let authorize = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/authorize?response_type=code&client_id=client-1&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback&scope=openid%20email&state=state-123&nonce=nonce-123&code_challenge={challenge}&code_challenge_method=S256"
                    ))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(authorize.status(), StatusCode::OK);

        let consent = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/authorize/consent")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("decision=approve"))?,
            )
            .await?;
        assert_eq!(consent.status(), StatusCode::SEE_OTHER);
        let location = consent
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()?
            .to_string();
        let redirect = Url::parse(&location)?;
        let query: std::collections::HashMap<String, String> =
            redirect.query_pairs().into_owned().collect();
        let code = query.get("code").unwrap().to_string();

        let form = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback&client_id=client-1&code_verifier={verifier}"
        );
        let first_token = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form.clone()))?,
            )
            .await?;
        assert_eq!(first_token.status(), StatusCode::OK);

        let second_token = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))?,
            )
            .await?;
        assert_eq!(second_token.status(), StatusCode::BAD_REQUEST);
        let error = String::from_utf8(response_body(second_token).await)?;
        assert!(error.contains("Unknown authorization code"));

        Ok(())
    }

    #[tokio::test]
    async fn admin_can_create_oauth_client() -> anyhow::Result<()> {
        let db = mem_db().await?;
        let persistence = Arc::new(PersistenceService::new(db.clone()));
        let admin_id = persistence.persist_identity(admin_identity()).await?;

        let state = AppState {
            ps: persistence.clone(),
            is: Arc::new(InviteService::new(
                persistence.clone(),
                &EmailConfig {
                    relay_host: "localhost".to_string(),
                    username: None,
                    password_file: None,
                    sender_email: "test@example.com".to_string(),
                },
                "http://localhost:8080",
            )?),
            templates: Arc::new(Templates::new()?),
            oidc: Arc::new(OidcService::new(
                "http://localhost:8080",
                persistence.as_ref().clone(),
            )),
            rs: Arc::new(RegistrationService::new("http://localhost:8080")?),
        };
        let app = test_app(state, db);

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/test-login?user_id={admin_id}"))
                    .body(Body::empty())?,
            )
            .await?;
        let cookie = session_cookie(&login);

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth-client")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&CreateOAuthClientRequest {
                        client_id: "configured-client".to_string(),
                        name: "Configured Client".to_string(),
                        redirect_uris: vec!["http://localhost:4000/callback".to_string()],
                    })?))?,
            )
            .await?;
        assert_eq!(create.status(), StatusCode::CREATED);

        let created = persistence.fetch_oauth_client("configured-client").await?;
        assert!(created.is_some());
        assert_eq!(created.unwrap().name, "Configured Client");
        Ok(())
    }
}
