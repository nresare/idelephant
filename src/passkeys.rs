use crate::auth::current_identity;
use crate::error::IdentityError;
use crate::persistence::{
    Credential, Identity, IdentityState, PasskeyRegistration, PersistenceService,
};
use crate::register::RegistrationService;
use crate::util::make_token;
use crate::AppState;
use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use idelephant_webauthn::RegisterPublicKeyCredential;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_sessions::Session;

const CSRF: &str = "idelephant.passkeys-csrf";
const REGISTRATION: &str = "idelephant.passkey-registration";

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/passkeys", get(list))
        .route("/api/passkeys/register-start", post(start))
        .route("/api/passkeys/register-finish", post(finish))
        .route("/api/passkeys/{id}", put(rename).delete(delete))
}

#[derive(Serialize)]
pub(crate) struct PasskeySummary {
    id: String,
    name: String,
}

pub(crate) fn summaries(identity: &Identity) -> Vec<PasskeySummary> {
    match &identity.state {
        IdentityState::Active { credentials } => credentials
            .iter()
            .enumerate()
            .map(|(index, key)| PasskeySummary {
                id: URL_SAFE_NO_PAD.encode(&*key.id),
                name: if key.name.is_empty() {
                    format!("Passkey {}", index + 1)
                } else {
                    key.name.clone()
                },
            })
            .collect(),
        _ => vec![],
    }
}

pub(crate) async fn csrf_token(session: &Session) -> Result<String, IdentityError> {
    if let Some(token) = session.get::<String>(CSRF).await? {
        return Ok(token);
    }
    let token = URL_SAFE_NO_PAD.encode(make_token());
    session.insert(CSRF, &token).await?;
    Ok(token)
}

async fn require_identity(
    session: &Session,
    ps: &PersistenceService,
) -> Result<Identity, IdentityError> {
    current_identity(session, ps)
        .await?
        .ok_or_else(|| IdentityError::Unauthorized("Sign in to manage your passkeys.".into()))
}

async fn check_csrf(session: &Session, token: &str) -> Result<(), IdentityError> {
    if session.get::<String>(CSRF).await?.as_deref() != Some(token) {
        return Err(IdentityError::Unauthorized(
            "This form has expired. Reload the page and try again.".into(),
        ));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<String, IdentityError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
        return Err(IdentityError::BadRequest(
            "Use a passkey name between 1 and 80 characters, without control characters.".into(),
        ));
    }
    Ok(name.to_owned())
}

async fn list(
    session: Session,
    State(ps): State<PersistenceService>,
) -> Result<Json<Value>, IdentityError> {
    let identity = require_identity(&session, &ps).await?;
    Ok(Json(
        json!({"passkeys": summaries(&identity), "csrf_token": csrf_token(&session).await?}),
    ))
}

#[derive(Deserialize)]
struct NamedRequest {
    name: String,
    csrf_token: String,
}
#[derive(Deserialize)]
struct MutationRequest {
    csrf_token: String,
}
#[derive(Deserialize)]
struct FinishRequest {
    credential: Value,
    csrf_token: String,
}

async fn start(
    session: Session,
    State(ps): State<PersistenceService>,
    State(rs): State<RegistrationService>,
    Json(request): Json<NamedRequest>,
) -> Result<Json<Value>, IdentityError> {
    let identity = require_identity(&session, &ps).await?;
    check_csrf(&session, &request.csrf_token).await?;
    let name = validate_name(&request.name)?;
    let subject_id = identity.id()?;
    let id = URL_SAFE_NO_PAD.encode(make_token());
    let challenge = make_token();
    // Keep the account active throughout registration, and consume each challenge only once.
    if let Some(previous) = session.remove::<String>(REGISTRATION).await? {
        ps.take_passkey_registration(previous, subject_id.clone())
            .await?;
    }
    ps.begin_passkey_registration(
        id.clone(),
        PasskeyRegistration {
            subject_id: subject_id.clone(),
            challenge: challenge.clone().into(),
            name,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        },
    )
    .await?;
    session.insert(REGISTRATION, id).await?;
    Ok(Json(
        json!({"challenge": STANDARD_NO_PAD.encode(challenge), "user_id": STANDARD_NO_PAD.encode(subject_id),
        "email": identity.email, "rp_id": rs.relying_party_id(), "exclude_credentials": summaries(&identity)}),
    ))
}

async fn finish(
    session: Session,
    State(ps): State<PersistenceService>,
    State(rs): State<RegistrationService>,
    Json(request): Json<FinishRequest>,
) -> Result<(), IdentityError> {
    let identity = require_identity(&session, &ps).await?;
    check_csrf(&session, &request.csrf_token).await?;
    let invalid =
        || IdentityError::BadRequest("Passkey registration has expired. Start again.".into());
    let id = session
        .remove::<String>(REGISTRATION)
        .await?
        .ok_or_else(invalid)?;
    let pending = ps
        .take_passkey_registration(id, identity.id()?)
        .await?
        .ok_or_else(invalid)?;
    if pending.expires_at <= Utc::now() {
        return Err(invalid());
    }
    let credential = RegisterPublicKeyCredential::try_from(&request.credential)
        .map_err(|_| IdentityError::BadRequest("Invalid passkey response.".into()))?;
    rs.validate(&credential, &pending.challenge).map_err(|_| {
        IdentityError::BadRequest("Passkey verification failed. Start again.".into())
    })?;
    if credential.id().is_empty() || credential.response().public_key_algorithm != -7 {
        return Err(IdentityError::BadRequest("Unsupported passkey.".into()));
    }
    let mut key = Credential::new(
        credential.id(),
        &credential.response().public_key,
        credential.response().public_key_algorithm,
        credential.response().attestation.auth_data.sign_count,
    );
    key.name = pending.name;
    changed(
        ps.add_passkey(&identity.id()?, key).await?,
        "This passkey is already registered or the account is no longer active.",
    )
}

fn changed(updated: bool, message: &str) -> Result<(), IdentityError> {
    if updated {
        Ok(())
    } else {
        Err(IdentityError::BadRequest(message.into()))
    }
}

async fn rename(
    session: Session,
    State(ps): State<PersistenceService>,
    Path(id): Path<String>,
    Json(request): Json<NamedRequest>,
) -> Result<(), IdentityError> {
    let identity = require_identity(&session, &ps).await?;
    check_csrf(&session, &request.csrf_token).await?;
    changed(
        ps.rename_passkey(
            &identity.id()?,
            &URL_SAFE_NO_PAD.decode(id)?,
            validate_name(&request.name)?,
        )
        .await?,
        "Passkey not found.",
    )
}

async fn delete(
    session: Session,
    State(ps): State<PersistenceService>,
    Path(id): Path<String>,
    Json(request): Json<MutationRequest>,
) -> Result<(), IdentityError> {
    let identity = require_identity(&session, &ps).await?;
    check_csrf(&session, &request.csrf_token).await?;
    changed(
        ps.delete_passkey(&identity.id()?, &URL_SAFE_NO_PAD.decode(id)?)
            .await?,
        "Passkey not found.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EmailConfig;
    use crate::invite::InviteService;
    use crate::oidc::OidcService;
    use crate::persistence::mem_db;
    use crate::web::Templates;
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn login(
        session: Session,
        State(ps): State<PersistenceService>,
    ) -> Result<(), IdentityError> {
        session
            .insert(
                crate::auth::IDENTITY,
                ps.fetch_identity("alice").await?.unwrap(),
            )
            .await?;
        session
            .insert(
                "idelephant.register_id",
                ps.fetch_identity("alice").await?.unwrap(),
            )
            .await?;
        Ok(())
    }

    async fn setup() -> anyhow::Result<(Router, Arc<PersistenceService>, String)> {
        let db = mem_db().await?;
        let ps = Arc::new(PersistenceService::new(db.clone()));
        for subject in ["alice", "bob"] {
            ps.persist_identity_with_id(
                subject,
                Identity {
                    email: format!("{subject}@example.com"),
                    created: Utc::now(),
                    admin: false,
                    id: Some(surrealdb::types::RecordId::new("identity", subject)),
                    state: IdentityState::Active {
                        credentials: vec![Credential::new(subject.as_bytes(), b"key", -7, 0)],
                    },
                },
            )
            .await?;
        }
        let state = AppState {
            ps: ps.clone(),
            is: Arc::new(InviteService::new(
                ps.clone(),
                &EmailConfig {
                    relay_host: "localhost".into(),
                    username: None,
                    password_file: None,
                    sender_email: "test@example.com".into(),
                },
                "http://localhost:8080",
            )?),
            templates: Arc::new(Templates::new()?),
            oidc: Arc::new(OidcService::new(
                "http://localhost:8080",
                ps.as_ref().clone(),
            )),
            rs: Arc::new(RegistrationService::new("http://localhost:8080")?),
            bypass_authentication: false,
        };
        let app = Router::new()
            .route("/test-login", get(login))
            .merge(routes())
            .merge(crate::register::register_routes())
            .layer(crate::make_session_layer(db, time::Duration::hours(1)))
            .with_state(state);
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/test-login").body(Body::empty())?)
            .await?;
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        Ok((app, ps, cookie))
    }

    async fn call(
        app: &Router,
        cookie: &str,
        method: &str,
        path: &str,
        body: Value,
    ) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::COOKIE, cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    async fn data(response: axum::response::Response) -> Value {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 100_000).await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        serde_json::from_slice(&bytes).unwrap()
    }
    fn registration(id: &[u8], challenge: &[u8]) -> Value {
        use idelephant_webauthn::{
            AttestationObject, AuthenticatorAttestationResponse, AuthenticatorData, ClientData,
        };
        RegisterPublicKeyCredential::new(
            id,
            AuthenticatorAttestationResponse::new(
                Box::from(&b"public key"[..]),
                -7,
                AttestationObject::new_none(AuthenticatorData::new("localhost", true, false, 0)),
                ClientData::new(
                    "webauthn.create",
                    challenge.to_vec(),
                    "http://localhost:8080",
                    false,
                ),
            ),
        )
        .json()
    }

    #[tokio::test]
    async fn passkey_management_authenticates_and_preserves_other_accounts() -> anyhow::Result<()> {
        let (app, ps, cookie) = setup().await?;
        let denied = call(&app, "", "GET", "/api/passkeys", Value::Null).await;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let keys = data(call(&app, &cookie, "GET", "/api/passkeys", Value::Null).await).await;
        assert_eq!(keys["passkeys"][0]["name"], "Passkey 1");
        let csrf = keys["csrf_token"].as_str().unwrap();
        assert_eq!(
            call(&app, &cookie, "GET", "/register-start", Value::Null)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        let id = URL_SAFE_NO_PAD.encode(b"alice");
        let path = format!("/api/passkeys/{id}");
        let denied = call(
            &app,
            &cookie,
            "DELETE",
            &path,
            json!({"csrf_token":"wrong"}),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let renamed = call(
            &app,
            &cookie,
            "PUT",
            &path,
            json!({"csrf_token":csrf,"name":" Work laptop "}),
        )
        .await;
        assert_eq!(renamed.status(), StatusCode::OK);
        let keys = data(call(&app, &cookie, "GET", "/api/passkeys", Value::Null).await).await;
        assert_eq!(keys["passkeys"][0]["name"], "Work laptop");
        let other = format!("/api/passkeys/{}", URL_SAFE_NO_PAD.encode(b"bob"));
        assert_eq!(
            call(&app, &cookie, "DELETE", &other, json!({"csrf_token":csrf}))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        // The last key can be deleted while the session remains usable for registering another.
        assert_eq!(
            call(&app, &cookie, "DELETE", &path, json!({"csrf_token":csrf}))
                .await
                .status(),
            StatusCode::OK
        );
        let keys = data(call(&app, &cookie, "GET", "/api/passkeys", Value::Null).await).await;
        assert_eq!(keys["passkeys"], json!([]));
        assert!(
            matches!(ps.fetch_identity("bob").await?.unwrap().state, IdentityState::Active {credentials} if credentials.len() == 1)
        );
        let started = data(
            call(
                &app,
                &cookie,
                "POST",
                "/api/passkeys/register-start",
                json!({"csrf_token":csrf,"name":"Phone"}),
            )
            .await,
        )
        .await;
        let challenge = STANDARD_NO_PAD.decode(started["challenge"].as_str().unwrap())?;
        let payload = json!({"csrf_token":csrf,"credential":registration(b"phone", &challenge)});
        let finished = call(
            &app,
            &cookie,
            "POST",
            "/api/passkeys/register-finish",
            payload.clone(),
        )
        .await;
        let status = finished.status();
        let body = to_bytes(finished.into_body(), 100_000).await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            call(
                &app,
                &cookie,
                "POST",
                "/api/passkeys/register-finish",
                payload
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let keys = data(call(&app, &cookie, "GET", "/api/passkeys", Value::Null).await).await;
        assert_eq!(keys["passkeys"][0]["name"], "Phone");
        let started = data(
            call(
                &app,
                &cookie,
                "POST",
                "/api/passkeys/register-start",
                json!({"csrf_token":csrf,"name":"Laptop"}),
            )
            .await,
        )
        .await;
        assert_eq!(started["exclude_credentials"].as_array().unwrap().len(), 1);
        let challenge = STANDARD_NO_PAD.decode(started["challenge"].as_str().unwrap())?;
        assert_eq!(
            call(
                &app,
                &cookie,
                "POST",
                "/api/passkeys/register-finish",
                json!({"csrf_token":csrf,"credential":registration(b"laptop", &challenge)})
            )
            .await
            .status(),
            StatusCode::OK
        );
        let keys = data(call(&app, &cookie, "GET", "/api/passkeys", Value::Null).await).await;
        assert_eq!(keys["passkeys"].as_array().unwrap().len(), 2);
        assert_eq!(keys["passkeys"][0]["name"], "Phone");
        assert_eq!(keys["passkeys"][1]["name"], "Laptop");

        Ok(())
    }

    #[tokio::test]
    async fn registration_rejects_wrong_challenges_and_preserves_existing_keys(
    ) -> anyhow::Result<()> {
        let (app, ps, cookie) = setup().await?;
        let keys = data(call(&app, &cookie, "GET", "/api/passkeys", Value::Null).await).await;
        let csrf = keys["csrf_token"].clone();
        for name in ["", "\n", &"x".repeat(81)] {
            assert_eq!(
                call(
                    &app,
                    &cookie,
                    "POST",
                    "/api/passkeys/register-start",
                    json!({"csrf_token":csrf,"name":name})
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
        data(
            call(
                &app,
                &cookie,
                "POST",
                "/api/passkeys/register-start",
                json!({"csrf_token":csrf,"name":"Phone"}),
            )
            .await,
        )
        .await;
        assert_eq!(
            call(
                &app,
                &cookie,
                "POST",
                "/api/passkeys/register-finish",
                json!({"csrf_token":csrf,"credential":registration(b"phone", b"wrong challenge")})
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let identity = ps.fetch_identity("alice").await?.unwrap();
        assert!(
            matches!(identity.state, IdentityState::Active {credentials} if credentials.len() == 1 && credentials[0].id[..] == b"alice"[..])
        );
        Ok(())
    }
}
