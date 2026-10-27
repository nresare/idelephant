//! OAuth endpoints forked from idElephant; idFrog owns browser and grant state.
use crate::{
    config::Config,
    error::BrokerError,
    protocol::{
        AuthorizationRequest, PendingAuthorizationRequest, allowed_scopes, build_redirect,
        valid_verifier, validate_authorization_request, validate_pending_client, verify_pkce,
    },
    state::{
        CodeGrant, RefreshGrant, Store, Transaction, random_token, token_hash, transaction_deadline,
    },
    upstream::{Upstream, UpstreamIdentity},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Form, Query, State},
    http::{HeaderMap, HeaderValue, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use idp_oauth::{
    client_metadata::ClientMetadataService,
    token::{
        AccessTokenRequest, IdTokenRequest, JwksResponse, Principal, SigningKey, TOKEN_TTL_HOURS,
        TokenIssuer,
    },
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct AppState {
    config: Arc<Config>,
    upstream: Arc<Upstream>,
    key: Arc<SigningKey>,
    tokens: TokenIssuer,
    clients: ClientMetadataService,
    store: Store,
    upstream_slots: Arc<Semaphore>,
}

impl AppState {
    pub fn new(config: Config, upstream: Upstream, key: SigningKey, store: Store) -> Self {
        Self {
            tokens: TokenIssuer::new(&config.origin),
            config: Arc::new(config),
            upstream: Arc::new(upstream),
            key: Arc::new(key),
            clients: ClientMetadataService::default(),
            store,
            upstream_slots: Arc::new(Semaphore::new(32)),
        }
    }
    fn cookie_name(&self) -> &'static str {
        if self.config.origin.starts_with("https://") {
            "__Host-idfrog-browser"
        } else {
            "idfrog-browser"
        }
    }
    fn binding<'a>(&self, jar: &'a CookieJar) -> Result<&'a str, BrokerError> {
        jar.get(self.cookie_name())
            .map(|c| c.value())
            .ok_or_else(|| BrokerError::rejected("invalid_request", "missing_browser_cookie"))
    }
    fn needs_groups(&self, scopes: &[String]) -> bool {
        scopes.iter().any(|s| s == "groups")
    }
}

pub fn router(state: AppState) -> Router {
    let browser = Router::new()
        .route("/authorize", get(authorize))
        .route("/oidc/callback", get(callback))
        .layer(axum::middleware::map_response(browser_error));
    Router::new().merge(browser)
        .route("/", get(|| async { Html("<!doctype html><title>idFrog</title><h1>idFrog</h1><p>OAuth for MCP, backed by your single sign-on provider. Connect through your MCP client to sign in.</p>") }))
        .route("/healthz", get(|| async { "ok" }))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/.well-known/openid-configuration", get(metadata))
        .route("/jwks.json", get(jwks))
        .route("/token", post(token))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(axum::middleware::map_response(response_headers))
        .layer(axum::middleware::from_fn(idp_server::http::request))
        .with_state(state)
}

async fn response_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"));
    response
}

async fn browser_error(response: Response) -> Response {
    let status = response.status();
    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }
    tracing::warn!(
        status = status.as_u16(),
        "Browser authorization request failed"
    );
    (status, Html("<!doctype html><title>Authorization failed · idFrog</title><h1>Authorization failed</h1><p>The request could not be completed. Start again from your MCP client. If this continues, contact the idFrog administrator to check the client, resource, and upstream sign-in configuration.</p>")).into_response()
}

async fn metadata(
    State(state): State<AppState>,
) -> Json<idp_oauth::discovery::OpenidConfiguration> {
    let mut metadata = idp_oauth::discovery::OpenidConfiguration::new(&state.config.origin);
    metadata.userinfo_endpoint = None;
    metadata.scopes_supported = allowed_scopes().into_iter().map(str::to_owned).collect();
    metadata.token_endpoint_auth_methods_supported = vec!["none".into()];
    Json(metadata)
}
async fn jwks(State(state): State<AppState>) -> Json<JwksResponse> {
    Json(JwksResponse {
        keys: vec![state.key.public_jwk()],
    })
}

async fn authorize(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(request): Query<AuthorizationRequest>,
) -> Result<(CookieJar, Redirect), BrokerError> {
    let client = state
        .clients
        .resolve(state.config.as_ref(), &request.client_id)
        .await?;
    let pending = validate_authorization_request(request, &client)?;
    if !pending.resource.as_ref().is_some_and(|resource| {
        state
            .config
            .resources
            .iter()
            .any(|configured| &configured.uri == resource)
    }) {
        return Err(BrokerError::OAuth("invalid_target"));
    }
    let binding = jar
        .get(state.cookie_name())
        .map(|c| c.value().to_string())
        .filter(|v| {
            v.len() == 43
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .unwrap_or_else(random_token);
    let cookie = Cookie::build((state.cookie_name(), binding.clone()))
        .path("/")
        .http_only(true)
        .secure(state.config.origin.starts_with("https://"))
        .same_site(SameSite::Lax)
        .build();
    let offline = pending.scopes.iter().any(|s| s == "offline_access");
    let (url, upstream_state, challenge) = state.upstream.start_login(
        offline,
        pending.resource.as_deref().ok_or(BrokerError::Internal)?,
    )?;
    state
        .store
        .insert_transaction(
            &upstream_state,
            Transaction {
                binding,
                request: pending,
                expires_at: transaction_deadline(),
                challenge,
            },
        )
        .await?;
    Ok((jar.add(cookie), Redirect::to(&url)))
}

#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
    iss: Option<String>,
}

async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(callback): Query<Callback>,
) -> Result<Response, BrokerError> {
    let binding = state.binding(&jar)?;
    let _slot = state
        .upstream_slots
        .try_acquire()
        .map_err(|_| BrokerError::Capacity)?;
    let transaction = state
        .store
        .take_transaction(&callback.state, binding)
        .await?;
    if callback
        .iss
        .as_ref()
        .is_some_and(|iss| iss != &state.config.upstream.issuer)
    {
        tracing::warn!(
            stage = "callback",
            reason = "issuer_mismatch",
            "Authorization failed"
        );
        return Err(BrokerError::Upstream);
    }
    if let Some(error) = callback.error {
        tracing::warn!(
            stage = "callback",
            reason = crate::upstream::safe_oauth_error(&error),
            "Upstream authorization rejected"
        );
        return Ok(Redirect::to(&deny_redirect(&state, &transaction.request)?).into_response());
    }
    let challenge = transaction.challenge;
    let code = callback
        .code
        .filter(|c| !c.is_empty())
        .ok_or_else(|| BrokerError::rejected("invalid_request", "missing_upstream_code"))?;
    let identity = state
        .upstream
        .finish_login(
            code,
            challenge,
            transaction
                .request
                .resource
                .as_deref()
                .ok_or(BrokerError::Internal)?,
            state.needs_groups(&transaction.request.scopes),
        )
        .await?;
    if transaction
        .request
        .scopes
        .iter()
        .any(|s| s == "offline_access")
        && identity.refresh_token.is_none()
    {
        return Err(BrokerError::rejected(
            "invalid_scope",
            "missing_upstream_refresh_token",
        ));
    }
    let client = state
        .clients
        .resolve(state.config.as_ref(), &transaction.request.client_id)
        .await?;
    validate_pending_client(&transaction.request, &client)?;
    let code = random_token();
    let redirect = build_redirect(
        &transaction.request.redirect_uri,
        &[
            ("code", Some(&code)),
            ("state", transaction.request.state.as_deref()),
            ("iss", Some(&state.config.origin)),
        ],
    )?;
    state
        .store
        .insert_code(
            &token_hash(&code),
            CodeGrant {
                request: transaction.request,
                identity,
                expires_at: transaction_deadline(),
            },
        )
        .await?;
    Ok(Redirect::to(&redirect).into_response())
}

fn deny_redirect(
    state: &AppState,
    pending: &PendingAuthorizationRequest,
) -> Result<String, BrokerError> {
    build_redirect(
        &pending.redirect_uri,
        &[
            ("error", Some("access_denied")),
            ("state", pending.state.as_deref()),
            ("iss", Some(&state.config.origin)),
        ],
    )
}

#[derive(Default, Deserialize)]
struct TokenRequest {
    grant_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    code_verifier: String,
    #[serde(default)]
    refresh_token: String,
    resource: Option<String>,
    scope: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<TokenRequest>, axum::extract::rejection::FormRejection>,
) -> Result<Json<TokenResponse>, BrokerError> {
    let Form(request) =
        form.map_err(|_| BrokerError::rejected("invalid_request", "malformed_token_form"))?;
    // idFrog accepts public downstream clients only; Entra authentication is separate.
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(BrokerError::rejected(
            "invalid_client",
            "downstream_client_authentication_not_supported",
        ));
    }
    if request.client_id.is_empty() {
        return Err(BrokerError::rejected("invalid_client", "missing_client_id"));
    }
    let client = state
        .clients
        .resolve(state.config.as_ref(), &request.client_id)
        .await?;
    if request.grant_type == "refresh_token" {
        return refresh(&state, request).await.map(Json);
    }
    if request.grant_type != "authorization_code" {
        return Err(BrokerError::rejected(
            "unsupported_grant_type",
            "unsupported_token_grant_type",
        ));
    }
    let grant = state
        .store
        .take_code(&token_hash(&request.code), |grant| {
            let pending = &grant.request;
            for (invalid, reason) in [
                (
                    pending.client_id != request.client_id,
                    "code_client_mismatch",
                ),
                (
                    pending.redirect_uri != request.redirect_uri,
                    "code_redirect_mismatch",
                ),
                (
                    !client.allows_redirect(&pending.redirect_uri),
                    "redirect_no_longer_registered",
                ),
                (
                    request.resource != pending.resource,
                    "code_resource_mismatch",
                ),
                (
                    !valid_verifier(&request.code_verifier),
                    "invalid_pkce_verifier",
                ),
                (
                    !verify_pkce(&request.code_verifier, &pending.code_challenge),
                    "pkce_mismatch",
                ),
            ] {
                if invalid {
                    return Err(BrokerError::rejected("invalid_grant", reason));
                }
            }
            Ok(())
        })
        .await?;
    let scopes = initial_scopes(&grant.identity, &grant.request.scopes);
    let claims_scopes: Vec<String> = grant
        .request
        .scopes
        .iter()
        .filter(|scope| allowed_scopes().contains(&scope.as_str()))
        .cloned()
        .collect();
    let refresh_token = if grant.request.scopes.iter().any(|s| s == "offline_access") {
        let raw = random_token();
        let family = RefreshGrant {
            client_id: grant.request.client_id.clone(),
            resource: grant
                .request
                .resource
                .clone()
                .ok_or(BrokerError::Internal)?,
            scopes: scopes.clone(),
            claims_scopes: claims_scopes.clone(),
            identity: grant.identity.clone(),
            expires_at: Utc::now() + Duration::days(30),
        };
        state
            .store
            .insert_refresh(&token_hash(&raw), family)
            .await?;
        Some(raw)
    } else {
        None
    };
    make_tokens(
        &state,
        TokenGrant {
            identity: &grant.identity,
            client_id: &grant.request.client_id,
            resource: grant.request.resource.as_deref(),
            scopes: &scopes,
            claims_scopes: &claims_scopes,
            nonce: grant.request.nonce.as_deref(),
        },
        true,
        refresh_token,
    )
    .map(Json)
}

fn initial_scopes(identity: &UpstreamIdentity, requested: &[String]) -> Vec<String> {
    let mut scopes: Vec<String> = requested
        .iter()
        .filter(|scope| allowed_scopes().contains(&scope.as_str()))
        .cloned()
        .collect();
    for scope in &identity.api_scopes {
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
        }
    }
    scopes
}

struct TokenGrant<'a> {
    identity: &'a UpstreamIdentity,
    client_id: &'a str,
    resource: Option<&'a str>,
    scopes: &'a [String],
    claims_scopes: &'a [String],
    nonce: Option<&'a str>,
}

fn make_tokens(
    state: &AppState,
    grant: TokenGrant<'_>,
    include_id: bool,
    refresh_token: Option<String>,
) -> Result<TokenResponse, BrokerError> {
    let principal = Principal {
        subject: &grant.identity.subject,
        email: grant
            .identity
            .email
            .as_deref()
            .filter(|_| grant.claims_scopes.iter().any(|s| s == "email")),
        groups: if grant.claims_scopes.iter().any(|s| s == "groups") {
            &grant.identity.groups
        } else {
            &[]
        },
    };
    let now = Utc::now();
    if grant.identity.permission_expires_at.timestamp() <= now.timestamp() {
        return Err(BrokerError::rejected(
            "invalid_grant",
            "upstream_permission_expired",
        ));
    }
    let access_token = state.tokens.mint_access_token_until(
        &state.key,
        &principal,
        AccessTokenRequest {
            client_id: grant.client_id,
            resource: grant.resource,
            scopes: grant.scopes,
        },
        now,
        grant.identity.permission_expires_at,
    )?;
    let id_token = if include_id && grant.claims_scopes.iter().any(|s| s == "openid") {
        Some(state.tokens.mint_id_token(
            &state.key,
            &principal,
            IdTokenRequest {
                audience: grant.client_id,
                nonce: grant.nonce,
                authenticated_at: grant.identity.authenticated_at,
                include_groups: grant.claims_scopes.iter().any(|s| s == "groups"),
            },
            now,
        )?)
    } else {
        None
    };
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: (grant.identity.permission_expires_at.timestamp() - now.timestamp())
            .min(TOKEN_TTL_HOURS * 3600),
        scope: grant.scopes.join(" "),
        id_token,
        refresh_token,
    })
}

async fn refresh(state: &AppState, request: TokenRequest) -> Result<TokenResponse, BrokerError> {
    if request.refresh_token.is_empty() {
        return Err(BrokerError::rejected(
            "invalid_grant",
            "missing_refresh_token",
        ));
    }
    let _slot = state
        .upstream_slots
        .try_acquire()
        .map_err(|_| BrokerError::Capacity)?;
    let hash = token_hash(&request.refresh_token);
    let requested = request.scope.clone();
    let (family_id, family, (mut scopes, claims_scopes)) = state
        .store
        .begin_refresh(
            &hash,
            &request.client_id,
            request.resource.as_deref(),
            |family| {
                let scopes = match requested {
                    Some(scope) => {
                        let scopes: Vec<String> =
                            scope.split_whitespace().map(str::to_string).collect();
                        if scopes.is_empty() || scopes.iter().any(|s| !family.scopes.contains(s)) {
                            return Err(BrokerError::rejected(
                                "invalid_scope",
                                "refresh_scope_widening_or_empty_scope",
                            ));
                        }
                        scopes
                    }
                    None => family.scopes.clone(),
                };
                let claims_scopes = family
                    .claims_scopes
                    .iter()
                    .filter(|scope| scopes.contains(scope))
                    .cloned()
                    .collect::<Vec<_>>();
                Ok((scopes, claims_scopes))
            },
        )
        .await?;
    let updated = match state
        .upstream
        .refresh(
            &family.identity,
            &family.resource,
            state.needs_groups(&claims_scopes),
        )
        .await
    {
        Ok(identity) => identity,
        Err(_) => {
            state.store.revoke_refresh(&family_id).await?;
            return Err(BrokerError::rejected(
                "invalid_grant",
                "upstream_refresh_validation_failed",
            ));
        }
    };
    // Retain only the requested subset of the original grant and permissions
    // still present in the newly verified API token. New rights require login.
    scopes.retain(|scope| claims_scopes.contains(scope) || updated.api_scopes.contains(scope));
    let replacement = random_token();
    let resource = family.resource.clone();
    state
        .store
        .finish_refresh(
            &family_id,
            RefreshGrant {
                identity: updated.clone(),
                scopes: scopes.clone(),
                claims_scopes: claims_scopes.clone(),
                ..family
            },
            &token_hash(&replacement),
        )
        .await?;
    make_tokens(
        state,
        TokenGrant {
            identity: &updated,
            client_id: &request.client_id,
            resource: Some(&resource),
            scopes: &scopes,
            claims_scopes: &claims_scopes,
            nonce: None,
        },
        false,
        Some(replacement),
    )
}
