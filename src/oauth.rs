use crate::auth::IDENTITY;
use crate::client_metadata::Client;
use crate::error::IdentityError;
use crate::oidc::{JwksResponse, OidcService, OpenidConfiguration};
use crate::persistence::{
    AuthorizationCode, CreateAuthorizationCode, Identity, OAuthClient, PersistenceService,
};
use crate::util::Token;
use crate::web::Templates;
use crate::AppState;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
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
        .route(
            "/oauth-client",
            get(list_oauth_clients)
                .post(create_oauth_client)
                .put(update_oauth_client)
                .delete(delete_oauth_client),
        )
        .route("/userinfo", get(userinfo))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/jwks.json", get(jwks))
        .route(
            "/.well-known/oauth-authorization-server",
            get(openid_configuration),
        )
}

pub const PENDING_AUTHORIZATION: &str = "idelephant.oauth.pending-authorization";

#[derive(Debug, Deserialize)]
struct AuthorizationRequest {
    #[serde(default)]
    resource: Option<String>,
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PendingAuthorizationRequest {
    #[serde(default)]
    resource: Option<String>,
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
    #[serde(default)]
    resource: Option<String>,
    grant_type: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    code_verifier: String,
    #[serde(default)]
    refresh_token: String,
    scope: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserinfoResponse {
    sub: String,
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<Vec<String>>,
}

async fn create_oauth_client(
    session: Session,
    State(persistence_service): State<PersistenceService>,
    Json(request): Json<CreateOAuthClientRequest>,
) -> Result<axum::http::StatusCode, IdentityError> {
    require_admin(&session, &persistence_service).await?;
    validate_client_registration_request(&request)?;
    if persistence_service
        .fetch_oauth_client(&request.client_id)
        .await?
        .is_some()
    {
        return Err(IdentityError::BadRequest(
            "Client ID is already registered".to_string(),
        ));
    }
    persistence_service
        .create_oauth_client(&request.client_id, &request.name, request.redirect_uris)
        .await?;
    Ok(axum::http::StatusCode::CREATED)
}

pub(crate) async fn current_admin(
    session: &Session,
    persistence: &PersistenceService,
) -> Result<bool, IdentityError> {
    let Some(identity): Option<Identity> = session.get(IDENTITY).await? else {
        return Ok(false);
    };
    Ok(persistence
        .fetch_identity(&identity.id()?)
        .await?
        .is_some_and(|identity| {
            identity.admin
                && matches!(
                    identity.state,
                    crate::persistence::IdentityState::Active { .. }
                )
        }))
}

pub(crate) async fn require_admin(
    session: &Session,
    persistence: &PersistenceService,
) -> Result<(), IdentityError> {
    if !current_admin(session, persistence).await? {
        return Err(IdentityError::Unauthorized(
            "An active admin login is required".to_string(),
        ));
    }
    Ok(())
}

async fn list_oauth_clients(
    session: Session,
    State(ps): State<PersistenceService>,
) -> Result<Json<Vec<OAuthClient>>, IdentityError> {
    require_admin(&session, &ps).await?;
    Ok(Json(ps.list_oauth_clients().await?))
}

async fn update_oauth_client(
    session: Session,
    State(ps): State<PersistenceService>,
    Json(request): Json<CreateOAuthClientRequest>,
) -> Result<axum::http::StatusCode, IdentityError> {
    require_admin(&session, &ps).await?;
    validate_client_registration_request(&request)?;
    if ps
        .update_oauth_client(&request.client_id, &request.name, request.redirect_uris)
        .await?
    {
        Ok(axum::http::StatusCode::NO_CONTENT)
    } else {
        Ok(axum::http::StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
struct DeleteOAuthClientRequest {
    client_id: String,
}

async fn delete_oauth_client(
    session: Session,
    State(ps): State<PersistenceService>,
    Json(request): Json<DeleteOAuthClientRequest>,
) -> Result<axum::http::StatusCode, IdentityError> {
    require_admin(&session, &ps).await?;
    if ps.delete_oauth_client(&request.client_id).await? {
        Ok(axum::http::StatusCode::NO_CONTENT)
    } else {
        Ok(axum::http::StatusCode::NOT_FOUND)
    }
}

async fn authorize(
    Query(request): Query<AuthorizationRequest>,
    session: Session,
    State(persistence_service): State<PersistenceService>,
    State(oidc_service): State<OidcService>,
    State(templates): State<Templates>,
) -> Result<Response, IdentityError> {
    let client = oidc_service
        .clients
        .resolve(&persistence_service, &request.client_id)
        .await?;
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

    let client = oidc_service
        .clients
        .resolve(&persistence_service, &pending.client_id)
        .await?;
    validate_pending_client(&pending, &client)?;
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
    State(oidc_service): State<OidcService>,
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

    let client = oidc_service
        .clients
        .resolve(&persistence_service, &pending.client_id)
        .await?;
    validate_pending_client(&pending, &client)?;
    if consent.decision == "deny" {
        session
            .remove::<PendingAuthorizationRequest>(PENDING_AUTHORIZATION)
            .await?;
        return Ok(Redirect::to(&build_redirect(
            &pending.redirect_uri,
            &[
                ("error", Some("access_denied")),
                ("state", pending.state.as_deref()),
                ("iss", Some(oidc_service.issuer())),
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
            pending.resource.as_deref(),
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
            resource: pending.resource.clone(),
            code_challenge: pending.code_challenge.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        })
        .await?;
    session
        .remove::<PendingAuthorizationRequest>(PENDING_AUTHORIZATION)
        .await?;

    Ok(Redirect::to(&build_redirect(
        &pending.redirect_uri,
        &[
            ("code", Some(&code)),
            ("state", pending.state.as_deref()),
            ("iss", Some(oidc_service.issuer())),
        ],
    )?))
}

async fn token(
    State(persistence_service): State<PersistenceService>,
    State(oidc_service): State<OidcService>,
    headers: HeaderMap,
    form: Result<Form<TokenRequest>, FormRejection>,
) -> Result<Response, IdentityError> {
    let Form(mut request) = form.map_err(|_| {
        IdentityError::BadRequest(
            "Invalid token request form; expected grant_type, code, redirect_uri and code_verifier"
                .to_string(),
        )
    })?;
    if request.grant_type == "refresh_token" {
        request.client_id = token_client_id(&headers, &request.client_id)
            .map_err(|_| IdentityError::OAuth("invalid_client"))?;
        let client = oidc_service
            .clients
            .resolve(&persistence_service, &request.client_id)
            .await?;
        if client.cimd && headers.contains_key(header::AUTHORIZATION) {
            return Err(IdentityError::OAuth("invalid_client"));
        }
        return refresh_tokens(&persistence_service, &oidc_service, request).await;
    }
    if request.grant_type != "authorization_code" {
        return Err(IdentityError::OAuth("unsupported_grant_type"));
    }
    if request.code.is_empty()
        || request.redirect_uri.is_empty()
        || request.code_verifier.is_empty()
    {
        return Err(IdentityError::BadRequest(
            "Invalid token request form; expected grant_type, code, redirect_uri and code_verifier"
                .to_string(),
        ));
    }
    request.client_id = token_client_id(&headers, &request.client_id)?;

    let Some(code) = persistence_service
        .fetch_authorization_code(&request.code)
        .await?
    else {
        return Err(IdentityError::BadRequest(
            "Unknown authorization code".to_string(),
        ));
    };

    validate_token_request(&request, &code)?;

    let client = oidc_service
        .clients
        .resolve(&persistence_service, &request.client_id)
        .await?;
    if !client.allows_redirect(&code.redirect_uri) {
        return Err(IdentityError::OAuth("invalid_grant"));
    }
    if client.cimd && headers.contains_key(header::AUTHORIZATION) {
        return Err(IdentityError::OAuth("invalid_client"));
    }
    if !verify_pkce(&request.code_verifier, &code.code_challenge) {
        return Err(IdentityError::BadRequest(
            "code_verifier did not match the PKCE challenge".to_string(),
        ));
    }

    if !persistence_service
        .delete_authorization_code(&request.code)
        .await?
    {
        return Err(IdentityError::BadRequest(
            "Unknown authorization code".to_string(),
        ));
    }
    let identity = persistence_service
        .fetch_identity(&code.subject_id)
        .await?
        .filter(|i| matches!(i.state, crate::persistence::IdentityState::Active { .. }))
        .ok_or(IdentityError::OAuth("invalid_grant"))?;
    let access_token = oidc_service
        .mint_access_token(
            &identity,
            &code.client_id,
            code.resource.as_deref(),
            &code.scopes,
        )
        .await?;
    let expires_in = chrono::Duration::hours(1);
    persistence_service
        .create_access_token(
            &access_token,
            &code.client_id,
            &code.subject_id,
            code.scopes.clone(),
            code.resource.clone(),
            chrono::Utc::now() + expires_in,
        )
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
        let groups = if code.scopes.iter().any(|scope| scope == "groups") {
            Some(
                persistence_service
                    .group_names_for_user(&code.subject_id)
                    .await?,
            )
        } else {
            None
        };
        Some(
            oidc_service
                .mint_id_token(
                    &code.subject_id,
                    &code.client_id,
                    code.nonce.as_deref(),
                    &identity.email,
                    groups.as_deref(),
                )
                .await?,
        )
    } else {
        None
    };

    let refresh_token = if code.scopes.iter().any(|scope| scope == "offline_access") {
        let refresh = Token::random().base64();
        persistence_service
            .create_refresh_token(
                &refresh,
                &code.client_id,
                &code.subject_id,
                code.scopes.clone(),
                code.resource.clone(),
                chrono::Utc::now() + chrono::Duration::days(30),
            )
            .await?;
        Some(refresh)
    } else {
        None
    };

    Ok(token_response(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: expires_in.num_seconds(),
        scope: code.scopes.join(" "),
        id_token,
        refresh_token,
    }))
}

fn token_response(tokens: TokenResponse) -> Response {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(tokens),
    )
        .into_response()
}

async fn refresh_tokens(
    persistence: &PersistenceService,
    oidc: &OidcService,
    request: TokenRequest,
) -> Result<Response, IdentityError> {
    if request.refresh_token.is_empty() {
        return Err(IdentityError::OAuth("invalid_request"));
    }
    oidc.clients
        .resolve(persistence, &request.client_id)
        .await?;
    let previous = persistence
        .fetch_refresh_token(&request.refresh_token)
        .await?
        .ok_or(IdentityError::OAuth("invalid_grant"))?;
    if previous.client_id != request.client_id
        || request
            .resource
            .as_ref()
            .is_some_and(|r| Some(r) != previous.resource.as_ref())
    {
        return Err(IdentityError::OAuth("invalid_grant"));
    }
    if previous
        .used_hashes
        .contains(&crate::persistence::refresh_token_hash(
            &request.refresh_token,
        ))
    {
        persistence.revoke_refresh_token(&previous).await?;
        return Err(IdentityError::OAuth("invalid_grant"));
    }
    if previous.expires_at <= chrono::Utc::now() {
        return Err(IdentityError::OAuth("invalid_grant"));
    }
    let Some(identity) = persistence
        .fetch_identity(&previous.subject_id)
        .await?
        .filter(|i| matches!(i.state, crate::persistence::IdentityState::Active { .. }))
    else {
        persistence.revoke_refresh_token(&previous).await?;
        return Err(IdentityError::OAuth("invalid_grant"));
    };
    let scopes = match request.scope {
        Some(scope) => {
            let scopes: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
            if scopes.is_empty() || scopes.iter().any(|scope| !previous.scopes.contains(scope)) {
                return Err(IdentityError::OAuth("invalid_scope"));
            }
            scopes
        }
        None => previous.scopes.clone(),
    };
    let refresh_token = Token::random().base64();
    if !persistence
        .rotate_refresh_token(&previous, &refresh_token, scopes.clone())
        .await?
    {
        persistence.revoke_refresh_token(&previous).await?;
        return Err(IdentityError::OAuth("invalid_grant"));
    }
    let access_token = oidc
        .mint_access_token(
            &identity,
            &previous.client_id,
            previous.resource.as_deref(),
            &scopes,
        )
        .await?;
    let lifetime = chrono::Duration::hours(1);
    persistence
        .create_access_token(
            &access_token,
            &previous.client_id,
            &previous.subject_id,
            scopes.clone(),
            previous.resource.clone(),
            chrono::Utc::now() + lifetime,
        )
        .await?;
    Ok(token_response(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: lifetime.num_seconds(),
        scope: scopes.join(" "),
        id_token: None,
        refresh_token: Some(refresh_token),
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
    if access_token.resource.is_some() {
        return Err(IdentityError::OAuth("invalid_token"));
    }
    if access_token.expires_at < chrono::Utc::now() {
        return Err(IdentityError::BadRequest(
            "access token has expired".to_string(),
        ));
    }
    let identity = persistence_service
        .fetch_identity(&access_token.subject_id)
        .await?
        .ok_or_else(|| IdentityError::BadRequest("Unknown identity".to_string()))?;
    let groups = if access_token.scopes.iter().any(|scope| scope == "groups") {
        Some(
            persistence_service
                .group_names_for_user(&access_token.subject_id)
                .await?,
        )
    } else {
        None
    };
    Ok(axum::Json(UserinfoResponse {
        sub: access_token.subject_id,
        email: identity.email,
        groups,
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
    client: &Client,
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
        .fetch_consent_grant(
            &identity.id()?,
            &pending.client_id,
            pending.resource.as_deref(),
        )
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
                resource: pending.resource.clone(),
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
            &[
                ("code", Some(&code)),
                ("state", pending.state.as_deref()),
                ("iss", Some(oidc_service.issuer())),
            ],
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
            "client_id": client.client_id,
            "redirect_uri": pending.redirect_uri,
            "resource": pending.resource,
            "idp_basename": oidc_service.issuer_basename(),
            "identity_email": identity.email,
            "scopes": pending.scopes,
            "requests_email": pending.scopes.iter().any(|scope| scope == "email"),
            "requests_groups": pending.scopes.iter().any(|scope| scope == "groups"),
            "requests_offline_access": pending.scopes.iter().any(|scope| scope == "offline_access"),
        }),
    )?;
    Ok(Html(body).into_response())
}

fn validate_authorization_request(
    request: AuthorizationRequest,
    client: &Client,
) -> Result<PendingAuthorizationRequest, IdentityError> {
    if request.response_type != "code" {
        return Err(IdentityError::BadRequest(
            "Only response_type=code is supported".to_string(),
        ));
    }
    if !client.allows_redirect(&request.redirect_uri) {
        return Err(IdentityError::BadRequest(
            "redirect_uri is not registered for this client".to_string(),
        ));
    }
    if let Some(resource) = request.resource.as_deref() {
        validate_resource(resource)?;
    }
    if client.cimd && request.resource.is_none() {
        return Err(IdentityError::OAuth("invalid_target"));
    }
    let scope = if request.scope.is_empty() && request.resource.is_some() {
        "email"
    } else {
        &request.scope
    };
    let scopes = parse_scopes(scope)?;
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
        resource: request.resource,
        redirect_uri: request.redirect_uri,
        scopes,
        state: request.state,
        nonce: request.nonce,
        code_challenge,
    })
}

fn validate_resource(resource: &str) -> Result<(), IdentityError> {
    let url = Url::parse(resource).map_err(|_| IdentityError::OAuth("invalid_target"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.fragment().is_some()
        || url.query().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(IdentityError::OAuth("invalid_target"));
    }
    Ok(())
}

fn validate_pending_client(
    pending: &PendingAuthorizationRequest,
    client: &Client,
) -> Result<(), IdentityError> {
    if !client.allows_redirect(&pending.redirect_uri) {
        return Err(IdentityError::OAuth("invalid_request"));
    }
    Ok(())
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
    Ok(scopes)
}

fn validate_token_request(
    request: &TokenRequest,
    code: &AuthorizationCode,
) -> Result<(), IdentityError> {
    if code.resource != request.resource {
        return Err(IdentityError::OAuth("invalid_target"));
    }
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
    if request.client_id.trim().is_empty() {
        return Err(IdentityError::BadRequest(
            "client_id must not be empty".to_string(),
        ));
    }
    if request.name.trim().is_empty() {
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

fn allowed_scopes() -> [&'static str; 5] {
    ["openid", "profile", "email", "groups", "offline_access"]
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

// Client secrets are deliberately ignored: all registered clients still require PKCE.
fn token_client_id(headers: &HeaderMap, form_client_id: &str) -> Result<String, IdentityError> {
    let invalid_header =
        || IdentityError::BadRequest("Invalid Basic Authorization header".to_string());
    let Some(authorization) = headers.get(header::AUTHORIZATION) else {
        if form_client_id.is_empty() {
            return Err(IdentityError::BadRequest("Missing client_id".to_string()));
        }
        return Ok(form_client_id.to_string());
    };
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(invalid_header());
    }
    let (scheme, credentials) = authorization
        .to_str()
        .map_err(|_| invalid_header())?
        .split_once(' ')
        .ok_or_else(invalid_header)?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(invalid_header());
    }
    let decoded = STANDARD.decode(credentials).map_err(|_| invalid_header())?;
    let credentials = std::str::from_utf8(&decoded).map_err(|_| invalid_header())?;
    let (username, _secret) = credentials.split_once(':').ok_or_else(invalid_header)?;
    // OAuth Basic usernames use application/x-www-form-urlencoded encoding.
    let query = format!("client_id={username}");
    let mut pairs = url::form_urlencoded::parse(query.as_bytes());
    let (_, client_id) = pairs.next().ok_or_else(invalid_header)?;
    if client_id.is_empty() || pairs.next().is_some() {
        return Err(invalid_header());
    }
    if !form_client_id.is_empty() && form_client_id != client_id {
        return Err(IdentityError::BadRequest(
            "Basic and form client_id do not match".to_string(),
        ));
    }
    Ok(client_id.into_owned())
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
        bearer_token, build_redirect, consent_satisfies_request, token_client_id,
        validate_authorization_request, validate_token_request, verify_pkce, AuthorizationRequest,
        CreateOAuthClientRequest, PendingAuthorizationRequest, TokenRequest, PENDING_AUTHORIZATION,
    };
    use crate::auth::IDENTITY;
    use crate::client_metadata::Client;
    use crate::config::EmailConfig;
    use crate::error::IdentityError;
    use crate::invite::InviteService;
    use crate::oidc::OidcService;
    use crate::persistence::{
        mem_db, AuthorizationCode, ConsentGrant, Credential, Identity, IdentityState,
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
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    use chrono::{Duration, Utc};
    use serde::Deserialize;
    use serde_json::{json, Value};
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
        refresh_token: Option<String>,
    }

    fn admin_identity() -> Identity {
        Identity {
            email: "root@example.com".to_string(),
            created: Utc::now(),
            admin: true,
            id: None,
            state: IdentityState::Active {
                credentials: vec![Credential::new(b"credential", b"public-key", -7, 0)],
            },
        }
    }

    fn client() -> Client {
        Client {
            client_id: "client-1".to_string(),
            name: "Example client".to_string(),
            redirect_uris: vec!["http://localhost:4000/callback".to_string()],
            cimd: false,
            application_type: crate::client_metadata::ApplicationType::Web,
        }
    }

    #[test]
    fn validate_authorization_request_accepts_valid_request() {
        let request = AuthorizationRequest {
            resource: None,
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
            resource: None,
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
    fn validate_authorization_request_accepts_oauth_without_openid() {
        let request = AuthorizationRequest {
            resource: None,
            response_type: "code".to_string(),
            client_id: "client-1".to_string(),
            redirect_uri: "http://localhost:4000/callback".to_string(),
            scope: "email".to_string(),
            state: None,
            nonce: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
        };

        assert!(validate_authorization_request(request, &client()).is_ok());
    }

    fn token_request() -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: "code-123".to_string(),
            redirect_uri: "http://localhost:4000/callback".to_string(),
            client_id: "client-1".to_string(),
            code_verifier: "verifier-123".to_string(),
            refresh_token: String::new(),
            scope: None,
            resource: None,
        }
    }

    fn authorization_code(code_challenge: String) -> AuthorizationCode {
        AuthorizationCode {
            resource: None,
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
            resource: None,
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
    fn token_client_id_accepts_basic_and_form_clients() {
        assert_eq!(
            token_client_id(&HeaderMap::new(), "client-1").unwrap(),
            "client-1"
        );
        for secret in ["anything", "different:secret", ""] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                format!("bAsIc {}", STANDARD.encode(format!("client-1:{secret}")))
                    .parse()
                    .unwrap(),
            );
            assert_eq!(token_client_id(&headers, "").unwrap(), "client-1");
            assert_eq!(token_client_id(&headers, "client-1").unwrap(), "client-1");
            assert!(token_client_id(&headers, "other-client").is_err());
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                STANDARD.encode("client%3Awith%2Bspecial+characters:secret")
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(
            token_client_id(&headers, "").unwrap(),
            "client:with+special characters"
        );
    }

    #[test]
    fn token_client_id_rejects_missing_or_malformed_credentials() {
        assert!(token_client_id(&HeaderMap::new(), "").is_err());
        for value in [
            "Basic !!!".to_string(),
            "Bearer token".to_string(),
            "Basic".to_string(),
            format!("Basic {}", STANDARD.encode("no-colon")),
            format!("Basic {}", STANDARD.encode(":secret")),
            format!("Basic {}", STANDARD.encode([0xff, b':'])),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, value.parse().unwrap());
            // A valid form client must not hide a malformed Authorization header.
            assert!(token_client_id(&headers, "client-1").is_err());
        }
        let mut headers = HeaderMap::new();
        let value: HeaderValue = format!("Basic {}", STANDARD.encode("client-1:secret"))
            .parse()
            .unwrap();
        headers.append(header::AUTHORIZATION, value.clone());
        headers.append(header::AUTHORIZATION, value);
        assert!(token_client_id(&headers, "").is_err());
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
            .layer(crate::make_session_layer(
                db.clone(),
                time::Duration::hours(1),
            ))
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
    async fn refresh_validates_client_scope_expiry_identity_and_deletion() -> anyhow::Result<()> {
        let ps = PersistenceService::new(mem_db().await?);
        let oidc = OidcService::new("https://issuer.example", ps.clone());
        let user = ps.persist_identity(admin_identity()).await?;
        for client in ["client-1", "other"] {
            ps.create_oauth_client(client, client, vec!["http://localhost/callback".into()])
                .await?;
        }
        let scopes = vec!["openid".into(), "email".into(), "offline_access".into()];
        ps.create_refresh_token(
            "valid",
            "client-1",
            &user,
            scopes.clone(),
            None,
            Utc::now() + Duration::days(30),
        )
        .await?;
        let refresh_request = |token: &str, client: &str, scope: Option<&str>| TokenRequest {
            grant_type: "refresh_token".into(),
            refresh_token: token.into(),
            client_id: client.into(),
            scope: scope.map(str::to_string),
            resource: None,
            ..token_request()
        };
        for (token, client, scope, expected) in [
            ("", "client-1", None, "invalid_request"),
            ("unknown", "client-1", None, "invalid_grant"),
            ("valid", "unregistered", None, "invalid_client"),
            ("valid", "other", None, "invalid_grant"),
            ("valid", "client-1", Some("openid groups"), "invalid_scope"),
            ("valid", "client-1", Some(""), "invalid_scope"),
        ] {
            let error = super::refresh_tokens(&ps, &oidc, refresh_request(token, client, scope))
                .await
                .unwrap_err();
            assert!(matches!(error, IdentityError::OAuth(code) if code == expected));
        }
        let response = super::refresh_tokens(
            &ps,
            &oidc,
            refresh_request("valid", "client-1", Some("email")),
        )
        .await?;
        let renewed: Value = serde_json::from_slice(&response_body(response).await)?;
        assert_eq!(renewed["scope"], "email");
        assert!(renewed.get("id_token").is_none());
        let new_refresh = renewed["refresh_token"].as_str().unwrap();
        assert_eq!(
            ps.fetch_refresh_token(new_refresh).await?.unwrap().scopes,
            vec!["email"]
        );
        assert!(matches!(
            super::refresh_tokens(
                &ps,
                &oidc,
                refresh_request(new_refresh, "client-1", Some("openid"))
            )
            .await,
            Err(IdentityError::OAuth("invalid_scope"))
        ));
        ps.delete_oauth_client("client-1").await?;
        ps.create_oauth_client(
            "client-1",
            "Recreated",
            vec!["http://localhost/callback".into()],
        )
        .await?;
        assert!(ps.fetch_refresh_token(new_refresh).await?.is_none());
        assert!(ps.fetch_refresh_token("valid").await?.is_none());
        ps.create_refresh_token(
            "expired",
            "client-1",
            &user,
            scopes.clone(),
            None,
            Utc::now() - Duration::seconds(1),
        )
        .await?;
        ps.create_refresh_token(
            "missing-user",
            "client-1",
            "missing",
            scopes.clone(),
            None,
            Utc::now() + Duration::days(1),
        )
        .await?;
        for token in ["expired", "missing-user"] {
            assert!(matches!(
                super::refresh_tokens(&ps, &oidc, refresh_request(token, "client-1", None)).await,
                Err(IdentityError::OAuth("invalid_grant"))
            ));
        }
        ps.create_refresh_token(
            "inactive",
            "client-1",
            &user,
            scopes,
            None,
            Utc::now() + Duration::days(1),
        )
        .await?;
        let mut identity = ps.fetch_identity(&user).await?.unwrap();
        identity.state = IdentityState::Invited {
            token: crate::util::Token::random(),
        };
        ps.update_identity(&identity).await?;
        assert!(matches!(
            super::refresh_tokens(&ps, &oidc, refresh_request("inactive", "client-1", None)).await,
            Err(IdentityError::OAuth("invalid_grant"))
        ));
        assert!(ps.fetch_refresh_token("inactive").await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn oidc_smoke_test() -> anyhow::Result<()> {
        for secret in [
            None,
            Some("arbitrary-secret"),
            Some("different:secret"),
            Some(""),
        ] {
            for offline in [false, true] {
                oidc_smoke_test_with_secret(secret, offline).await?;
            }
        }
        Ok(())
    }

    async fn oidc_smoke_test_with_secret(
        secret: Option<&str>,
        offline: bool,
    ) -> anyhow::Result<()> {
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
        let group = persistence
            .create_group("Engineering", "Builds the product")
            .await?;
        persistence.add_group_member(&group.id()?, &user_id).await?;
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
            bypass_authentication: false,
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
                        "/authorize?response_type=code&client_id=client-1&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback&scope=openid%20email%20groups{}&state=state-123&nonce=nonce-123&code_challenge={challenge}&code_challenge_method=S256", if offline { "%20offline_access" } else { "" }
                    ))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(authorize.status(), StatusCode::OK);
        let authorize_body = String::from_utf8(response_body(authorize).await)?;
        assert!(authorize_body
            .contains("Example client</strong> is requesting access using your account."));
        assert!(authorize_body.contains("requesting your group memberships"));

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

        // Invalid clients and PKCE proofs must not consume the code or bypass validation.
        for (username, proof) in [("other-client", verifier), ("client-1", "wrong-verifier")] {
            let rejected = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/token")
                        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .header(
                            header::AUTHORIZATION,
                            format!("Basic {}", STANDARD.encode(format!("{username}:any-secret"))),
                        )
                        .body(Body::from(format!(
                            "grant_type=authorization_code&code={code}&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback&code_verifier={proof}"
                        )))?,
                )
                .await?;
            assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        }
        let malformed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=authorization_code"))?,
            )
            .await?;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert!(String::from_utf8(response_body(malformed).await)?
            .contains("Invalid token request form"));

        let mut token_request = Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        let client_form = if let Some(secret) = secret {
            token_request = token_request.header(
                header::AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(format!("client-1:{secret}"))),
            );
            ""
        } else {
            "&client_id=client-1"
        };
        let token = app
            .clone()
            .oneshot(token_request.body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback{client_form}&code_verifier={verifier}"
            )))?)
            .await?;
        assert_eq!(token.status(), StatusCode::OK);
        assert_eq!(token.headers()[header::CACHE_CONTROL], "no-store");
        let token_json: TokenJson = serde_json::from_slice(&response_body(token).await)?;
        assert!(!token_json.access_token.is_empty());
        assert_eq!(token_json.id_token.as_ref().unwrap().split('.').count(), 3);
        let payload = token_json
            .id_token
            .as_ref()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
        assert_eq!(claims["groups"], json!(["Engineering"]));

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
        assert_eq!(userinfo_json["groups"], json!(["Engineering"]));

        assert_eq!(token_json.refresh_token.is_some(), offline);
        if let Some(refresh) = token_json.refresh_token {
            let stored = persistence.fetch_refresh_token(&refresh).await?.unwrap();
            assert_ne!(stored.token_hash, refresh);
            let mut request = Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if let Some(secret) = secret {
                request = request.header(
                    header::AUTHORIZATION,
                    format!("Basic {}", STANDARD.encode(format!("client-1:{secret}"))),
                );
            }
            let response = app.clone().oneshot(request.body(Body::from(format!(
                "grant_type=refresh_token&client_id=client-1&refresh_token={refresh}&client_secret=ignored"
            )))?).await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let renewed: Value = serde_json::from_slice(&response_body(response).await)?;
            assert_ne!(renewed["access_token"], token_json.access_token);
            assert_ne!(renewed["refresh_token"], refresh);
            assert_eq!(renewed["scope"], "openid email groups offline_access");
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/userinfo")
                        .header(
                            header::AUTHORIZATION,
                            format!("Bearer {}", renewed["access_token"].as_str().unwrap()),
                        )
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let new_refresh = renewed["refresh_token"].as_str().unwrap();
            assert_eq!(
                persistence
                    .fetch_refresh_token(new_refresh)
                    .await?
                    .unwrap()
                    .expires_at,
                stored.expires_at
            );
            // Reusing the old token revokes its replacement as well.
            for token in [&refresh, new_refresh] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/token")
                            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                            .body(Body::from(format!(
                                "grant_type=refresh_token&client_id=client-1&refresh_token={token}"
                            )))?,
                    )
                    .await?;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                let error: Value = serde_json::from_slice(&response_body(response).await)?;
                assert_eq!(error["error"], "invalid_grant");
            }
        }
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
                None,
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
            bypass_authentication: false,
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
            bypass_authentication: false,
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
            bypass_authentication: false,
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

        for (method, body, expected) in [
            ("GET", "", StatusCode::OK),
            (
                "POST",
                r#"{"client_id":"configured-client","name":"Duplicate","redirect_uris":["http://localhost/cb"]}"#,
                StatusCode::BAD_REQUEST,
            ),
            (
                "PUT",
                r#"{"client_id":"configured-client","name":"Updated","redirect_uris":["http://localhost/new"]}"#,
                StatusCode::NO_CONTENT,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/oauth-client")
                        .header(header::COOKIE, &cookie)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))?,
                )
                .await?;
            assert_eq!(response.status(), expected);
        }
        let updated = persistence
            .fetch_oauth_client("configured-client")
            .await?
            .unwrap();
        assert_eq!(updated.name, "Updated");
        assert_eq!(updated.redirect_uris, vec!["http://localhost/new"]);

        // Every operation requires login, including reads.
        for method in ["GET", "POST", "PUT", "DELETE"] {
            let response = app.clone().oneshot(Request::builder().method(method).uri("/oauth-client")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"client_id":"configured-client","name":"Unauthorized","redirect_uris":["http://localhost/cb"]}"#))?).await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // Revoking admin privileges takes effect even with the existing session.
        let mut admin = persistence.fetch_identity(&admin_id).await?.unwrap();
        admin.admin = false;
        persistence.update_identity(&admin).await?;
        for method in ["GET", "POST", "PUT", "DELETE"] {
            let response = app.clone().oneshot(Request::builder().method(method).uri("/oauth-client")
                .header(header::COOKIE, &cookie).header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"client_id":"configured-client","name":"Unauthorized","redirect_uris":["http://localhost/cb"]}"#))?).await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        admin.admin = true;
        persistence.update_identity(&admin).await?;
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/oauth-client")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"client_id":"configured-client"}"#))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(persistence
            .fetch_oauth_client("configured-client")
            .await?
            .is_none());
        Ok(())
    }
    #[tokio::test]
    async fn cimd_flow_binds_jwt_consent_and_refresh_to_resource() -> anyhow::Result<()> {
        for (application_type, registered, requested) in [
            (
                "web",
                "https://client.example/callback",
                "https://client.example/callback",
            ),
            (
                "native",
                "http://127.0.0.1/callback",
                "http://127.0.0.1:52889/callback",
            ),
            (
                "native",
                "http://[::1]/callback",
                "http://[::1]:52889/callback",
            ),
            (
                "native",
                "http://localhost/callback",
                "http://localhost:52889/callback",
            ),
        ] {
            cimd_flow_with_redirect(application_type, registered, requested).await?;
        }
        Ok(())
    }

    async fn cimd_flow_with_redirect(
        application_type: &str,
        registered: &str,
        requested: &str,
    ) -> anyhow::Result<()> {
        let db = mem_db().await?;
        let persistence = Arc::new(PersistenceService::new(db.clone()));
        let user_id = persistence.persist_identity(admin_identity()).await?;
        let issuer = "https://identity.example";
        let client_id = "https://client.example/oauth/client.json";
        let resource = "https://mcp.example/mcp";
        let oidc = Arc::new(OidcService::new(issuer, persistence.as_ref().clone()));
        // Seed a validated cached document, keeping the HTTP flow deterministic.
        oidc.clients
            .cache_document(
                client_id,
                &serde_json::to_vec(&json!({
                    "client_id": client_id, "client_name": "MCP client",
                    "redirect_uris": [registered],
                    "application_type": application_type,
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
                }))?,
            )
            .await?;
        let app = test_app(
            AppState {
                ps: persistence.clone(),
                is: Arc::new(InviteService::new(
                    persistence.clone(),
                    &EmailConfig {
                        relay_host: "localhost".into(),
                        username: None,
                        password_file: None,
                        sender_email: "test@example.com".into(),
                    },
                    issuer,
                )?),
                templates: Arc::new(Templates::new()?),
                oidc: oidc.clone(),
                rs: Arc::new(RegistrationService::new(issuer)?),
                bypass_authentication: false,
            },
            db,
        );
        assert!(persistence.fetch_oauth_client(client_id).await?.is_none());
        let discovery = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-authorization-server")
                    .body(Body::empty())?,
            )
            .await?;
        let metadata: Value = serde_json::from_slice(&response_body(discovery).await)?;
        assert_eq!(metadata["client_id_metadata_document_supported"], true);
        assert_eq!(
            metadata["authorization_response_iss_parameter_supported"],
            true
        );
        assert!(metadata.get("registration_endpoint").is_none());
        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/test-login?user_id={user_id}"))
                    .body(Body::empty())?,
            )
            .await?;
        let cookie = session_cookie(&login);
        let verifier = "a".repeat(43);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let authorize_url = |resource: &str| {
            let mut url = Url::parse(&format!("{issuer}/authorize")).unwrap();
            url.query_pairs_mut().extend_pairs([
                ("client_id", client_id),
                ("response_type", "code"),
                ("redirect_uri", requested),
                ("resource", resource),
                ("scope", "email groups offline_access"),
                ("state", "state-123"),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ]);
            format!("{}?{}", url.path(), url.query().unwrap())
        };
        let consent_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(authorize_url(resource))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(consent_page.status(), StatusCode::OK);
        let html = String::from_utf8(response_body(consent_page).await)?;
        assert!(html.contains(resource));
        assert!(html.contains(requested));
        let resumed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/authorize/resume")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(resumed.status(), StatusCode::OK);
        let approved = app
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
        assert_eq!(approved.status(), StatusCode::SEE_OTHER);
        let location = Url::parse(approved.headers()[header::LOCATION].to_str()?)?;
        let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(query["iss"], issuer);
        assert_eq!(query["state"], "state-123");
        let code = &query["code"];
        let form = |pairs: &[(&str, &str)]| -> anyhow::Result<Request<Body>> {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs.iter().copied())
                .finish();
            Ok(Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))?)
        };
        let unsupported = app
            .clone()
            .oneshot(form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("client_id", client_id),
            ])?)
            .await?;
        assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
        let error: Value = serde_json::from_slice(&response_body(unsupported).await)?;
        assert_eq!(error["error"], "unsupported_grant_type");
        for (audience, proof, expected) in [
            (
                "https://other.example/mcp",
                verifier.as_str(),
                "invalid_target",
            ),
            (resource, "wrong", "pkce"),
        ] {
            let rejected = app
                .clone()
                .oneshot(form(&[
                    ("grant_type", "authorization_code"),
                    ("client_id", client_id),
                    ("code", code),
                    ("redirect_uri", requested),
                    ("resource", audience),
                    ("code_verifier", proof),
                ])?)
                .await?;
            assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
            if expected != "pkce" {
                let body: Value = serde_json::from_slice(&response_body(rejected).await)?;
                assert_eq!(body["error"], expected);
            }
        }
        // Metadata permits a native client to choose its port at authorization,
        // but exchanging this code must use the exact chosen redirect URI.
        let mut wrong_redirect = Url::parse(requested)?;
        wrong_redirect.set_port(Some(52890)).unwrap();
        let rejected = app
            .clone()
            .oneshot(form(&[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("code", code),
                ("redirect_uri", wrong_redirect.as_str()),
                ("resource", resource),
                ("code_verifier", &verifier),
            ])?)
            .await?;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let exchanged = app
            .clone()
            .oneshot(form(&[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("code", code),
                ("redirect_uri", requested),
                ("resource", resource),
                ("code_verifier", &verifier),
            ])?)
            .await?;
        assert_eq!(exchanged.status(), StatusCode::OK);
        let tokens: TokenJson = serde_json::from_slice(&response_body(exchanged).await)?;
        assert!(tokens.id_token.is_none());
        let header = jsonwebtoken::decode_header(&tokens.access_token)?;
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        let jwks: jsonwebtoken::jwk::JwkSet =
            serde_json::from_value(serde_json::to_value(oidc.jwks().await?)?)?;
        let key = jsonwebtoken::DecodingKey::from_jwk(
            jwks.find(header.kid.as_deref().unwrap()).unwrap(),
        )?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[resource]);
        let claims = jsonwebtoken::decode::<Value>(&tokens.access_token, &key, &validation)?.claims;
        assert_eq!(claims["sub"], user_id);
        assert_eq!(claims["email"], "root@example.com");
        assert_eq!(claims["client_id"], client_id);
        assert_eq!(claims["groups"], json!([]));
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            3600
        );
        assert!(claims["jti"].as_str().is_some());
        validation.set_audience(&["https://other.example/mcp"]);
        assert!(jsonwebtoken::decode::<Value>(&tokens.access_token, &key, &validation).is_err());
        validation.set_audience(&[resource]);
        validation.set_issuer(&["https://other-issuer.example"]);
        assert!(jsonwebtoken::decode::<Value>(&tokens.access_token, &key, &validation).is_err());
        validation.set_issuer(&[issuer]);
        let mut tampered = tokens.access_token.clone();
        let pos = tampered.find('.').unwrap() + 1;
        tampered.replace_range(pos..pos + 1, "X");
        assert!(jsonwebtoken::decode::<Value>(&tampered, &key, &validation).is_err());
        let refresh = tokens.refresh_token.unwrap();
        let rejected = app
            .clone()
            .oneshot(form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", &refresh),
                ("resource", "https://other.example/mcp"),
            ])?)
            .await?;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        // Omitting resource on refresh retains its original audience.
        let renewed = app
            .clone()
            .oneshot(form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", &refresh),
            ])?)
            .await?;
        assert_eq!(renewed.status(), StatusCode::OK);
        let renewed: TokenJson = serde_json::from_slice(&response_body(renewed).await)?;
        let claims =
            jsonwebtoken::decode::<Value>(&renewed.access_token, &key, &validation)?.claims;
        assert_eq!(claims["aud"], resource);
        assert_eq!(claims["sub"], user_id);
        // Consent is reused for this resource, but never another MCP server.
        let same = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(authorize_url(resource))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(same.status(), StatusCode::SEE_OTHER);
        let other = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(authorize_url("https://other.example/mcp"))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(other.status(), StatusCode::OK);
        // A resource's JWT cannot be used as a credential at userinfo either.
        let userinfo = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/userinfo")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", tokens.access_token),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(userinfo.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }
}
