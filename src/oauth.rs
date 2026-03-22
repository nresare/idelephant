use crate::auth::IDENTITY;
use crate::error::IdentityError;
use crate::persistence::{Identity, OAuthClient, PersistenceService};
use crate::util::Token;
use crate::web::Templates;
use crate::AppState;
use axum::extract::{Form, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_sessions::Session;
use url::Url;

pub fn oauth_routes() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize))
        .route("/authorize/resume", get(resume_authorize))
        .route("/authorize/consent", post(authorize_consent))
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

#[derive(Debug, Deserialize)]
struct ConsentRequest {
    decision: String,
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
    continue_authorization(session, persistence_service, templates, &client, pending).await
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

    continue_authorization(session, persistence_service, templates, &client, pending).await
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
        .create_authorization_code(
            &code,
            &pending.client_id,
            &identity.id()?,
            &pending.redirect_uri,
            pending.scopes.clone(),
            pending.nonce.clone(),
            &pending.code_challenge,
            &pending.code_challenge_method,
            chrono::Utc::now() + chrono::Duration::minutes(10),
        )
        .await?;
    session
        .remove::<PendingAuthorizationRequest>(PENDING_AUTHORIZATION)
        .await?;

    Ok(Redirect::to(&build_redirect(
        &pending.redirect_uri,
        &[("code", Some(&code)), ("state", pending.state.as_deref())],
    )?))
}

async fn continue_authorization(
    session: Session,
    persistence_service: PersistenceService,
    templates: Templates,
    client: &OAuthClient,
    pending: PendingAuthorizationRequest,
) -> Result<Response, IdentityError> {
    let Some(identity): Option<Identity> = session.get(IDENTITY).await? else {
        return Ok(Redirect::to("/").into_response());
    };

    let existing_consent = persistence_service
        .fetch_consent_grant(&identity.id()?, &pending.client_id)
        .await?;
    if consent_satisfies_request(existing_consent.as_ref(), &pending.scopes) {
        let code = Token::random().base64();
        persistence_service
            .create_authorization_code(
                &code,
                &pending.client_id,
                &identity.id()?,
                &pending.redirect_uri,
                pending.scopes.clone(),
                pending.nonce.clone(),
                &pending.code_challenge,
                &pending.code_challenge_method,
                chrono::Utc::now() + chrono::Duration::minutes(10),
            )
            .await?;
        session
            .remove::<PendingAuthorizationRequest>(PENDING_AUTHORIZATION)
            .await?;
        return Ok(Redirect::to(&build_redirect(
            &pending.redirect_uri,
            &[("code", Some(&code)), ("state", pending.state.as_deref())],
        )?)
        .into_response());
    }

    let body = templates.render(
        "authorize",
        &json!({
            "client_name": client.name,
            "client_id": client.client_id,
            "identity_email": identity.email,
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

#[cfg(test)]
mod tests {
    use super::{
        build_redirect, consent_satisfies_request, validate_authorization_request,
        AuthorizationRequest,
    };
    use crate::error::IdentityError;
    use crate::persistence::{ConsentGrant, OAuthClient};
    use chrono::Utc;
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
            id: RecordId::from(("consent_grant", "grant-1")),
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
}
