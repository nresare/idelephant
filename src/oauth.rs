use crate::auth::IDENTITY;
use crate::error::IdentityError;
use crate::persistence::{Identity, OAuthClient, PersistenceService};
use crate::web::Templates;
use crate::AppState;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_sessions::Session;

pub fn oauth_routes() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize))
        .route("/authorize/resume", get(resume_authorize))
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
    code_challenge_method: String,
}

async fn authorize(
    Query(request): Query<AuthorizationRequest>,
    session: Session,
    State(persistence_service): State<PersistenceService>,
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
    session.insert(PENDING_AUTHORIZATION, &pending).await?;
    continue_authorization(session, templates, &client, pending).await
}

async fn resume_authorize(
    session: Session,
    State(persistence_service): State<PersistenceService>,
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

    continue_authorization(session, templates, &client, pending).await
}

async fn continue_authorization(
    session: Session,
    templates: Templates,
    client: &OAuthClient,
    pending: PendingAuthorizationRequest,
) -> Result<Response, IdentityError> {
    let identity: Option<Identity> = session.get(IDENTITY).await?;
    if identity.is_none() {
        return Ok(Redirect::to("/").into_response());
    }

    let body = templates.render(
        "authorize",
        &json!({
            "client_name": client.name,
            "client_id": client.client_id,
            "redirect_uri": pending.redirect_uri,
            "scopes": pending.scopes,
            "state": pending.state,
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
        if !client.scopes.contains(scope) {
            return Err(IdentityError::BadRequest(format!(
                "scope '{scope}' is not allowed for this client"
            )));
        }
    }
    let code_challenge = request
        .code_challenge
        .ok_or_else(|| IdentityError::BadRequest("code_challenge is required".to_string()))?;
    let code_challenge_method = request.code_challenge_method.ok_or_else(|| {
        IdentityError::BadRequest("code_challenge_method is required".to_string())
    })?;
    if client.pkce_required && code_challenge_method != "S256" {
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
        code_challenge_method,
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

#[cfg(test)]
mod tests {
    use super::{validate_authorization_request, AuthorizationRequest};
    use crate::error::IdentityError;
    use crate::persistence::OAuthClient;
    use surrealdb::RecordId;

    fn client() -> OAuthClient {
        OAuthClient {
            client_id: "client-1".to_string(),
            name: "Example client".to_string(),
            redirect_uris: vec!["http://localhost:4000/callback".to_string()],
            scopes: vec!["openid".to_string(), "email".to_string()],
            pkce_required: true,
            id: RecordId::from(("oauth_client", "client-1")),
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
}
