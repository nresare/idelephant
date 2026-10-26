use crate::error::IdentityError;
use crate::persistence::IdentityState::Active;
use crate::persistence::{Identity, PersistenceService};
use crate::util::make_token;
use crate::AppState;
use anyhow::{anyhow, Context};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use idelephant_webauthn::PublicKeyCredentialAuthenticate;
use serde::Serialize;
use serde_json::Value;
use std::str;
use std::str::from_utf8;
use tower_sessions::Session;
use tracing::warn;

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/auth-start", get(auth_start))
        .route("/auth-finish", post(auth_finish))
}

#[derive(Serialize)]
struct AuthStart {
    challenge: String,
}

const AUTH_CHALLENGE: &str = "idelephant.auth-challenge";
pub const IDENTITY: &str = "idelephant.identity";
const LOGIN_TIME: &str = "idelephant.login-time";

pub async fn establish_login(session: &Session, identity: &Identity) -> Result<(), IdentityError> {
    session
        .insert(LOGIN_TIME, chrono::Utc::now().timestamp_millis())
        .await?;
    session.insert(IDENTITY, identity).await?;
    Ok(())
}

pub async fn enforce_max_login_time(
    State(max_login_time): State<time::Duration>,
    session: Session,
    request: Request,
    next: Next,
) -> Result<Response, IdentityError> {
    expire_login(
        &session,
        max_login_time,
        chrono::Utc::now().timestamp_millis(),
    )
    .await?;
    Ok(next.run(request).await)
}

async fn expire_login(
    session: &Session,
    max_login_time: time::Duration,
    now: i64,
) -> Result<(), IdentityError> {
    if session.get::<Identity>(IDENTITY).await?.is_some() {
        let login_time = session.get::<i64>(LOGIN_TIME).await?;
        // Sessions created before login times were recorded must authenticate again.
        let valid = login_time.is_some_and(|login_time| {
            login_time <= now
                && i128::from(now) - i128::from(login_time) < max_login_time.whole_milliseconds()
        });
        if !valid {
            session.remove_value(IDENTITY).await?;
            session.remove_value(LOGIN_TIME).await?;
        }
    }
    Ok(())
}

pub(crate) async fn current_identity(
    session: &Session,
    ps: &PersistenceService,
) -> Result<Option<Identity>, IdentityError> {
    let Some(cached) = session.get::<Identity>(IDENTITY).await? else {
        return Ok(None);
    };
    let identity = ps.fetch_identity(&cached.id()?).await?;
    if identity
        .as_ref()
        .is_some_and(|identity| matches!(identity.state, Active { .. }))
    {
        Ok(identity)
    } else {
        session.remove::<Identity>(IDENTITY).await?;
        Ok(None)
    }
}

async fn auth_start(session: Session) -> Result<Json<AuthStart>, IdentityError> {
    let challenge = make_token();
    session.insert(AUTH_CHALLENGE, &challenge).await?;
    Ok(Json(AuthStart {
        challenge: STANDARD_NO_PAD.encode(challenge),
    }))
}

async fn auth_finish(
    session: Session,
    State(persistence_service): State<PersistenceService>,
    Json(credential): Json<Value>,
) -> Result<String, IdentityError> {
    let Some(challenge): Option<Vec<u8>> = session.remove(AUTH_CHALLENGE).await? else {
        return Err(IdentityError::Anyhow(anyhow!(
            "Could not find challenge in session"
        )));
    };
    let credential: PublicKeyCredentialAuthenticate =
        PublicKeyCredentialAuthenticate::from_json(&credential)?;

    let user_handle = from_utf8(credential.response.user_handle.as_slice()).context(format!(
        "Could not convert user handle bytes {:?} to String",
        credential.response.user_handle
    ))?;

    let Some(identity) = persistence_service.fetch_identity(user_handle).await? else {
        warn!(
            "Authentication failed: unknown user handle '{}'",
            user_handle
        );
        return Err(IdentityError::Unauthorized(
            "This passkey is no longer linked to an account on this idElephant instance."
                .to_string(),
        ));
    };

    let key = find_key(&identity, &credential.id, user_handle)?;

    credential.verify(key, &challenge).map_err(|error| {
        warn!(
            "Authentication failed for user '{}': signature verification failed: {:#}",
            user_handle, error
        );
        IdentityError::Unauthorized("Authentication failed".to_string())
    })?;
    establish_login(&session, &identity).await?;
    Ok("OK".to_string())
}

fn find_key<'a>(
    identity: &'a Identity,
    credential_id: &[u8],
    user_handle: &str,
) -> Result<&'a [u8], IdentityError> {
    let Active { credentials } = &identity.state else {
        return Err(anyhow!("Identity is not in state active").into());
    };
    for credential in credentials {
        if credential.id.as_ref() == credential_id {
            return Ok(&credential.public_key);
        }
    }
    warn!(
        "Authentication failed for user '{}': unknown credential id '{}'",
        user_handle,
        STANDARD_NO_PAD.encode(credential_id)
    );
    Err(IdentityError::Unauthorized(
        "Authentication failed".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::find_key;
    use crate::error::IdentityError;
    use crate::persistence::{Credential, Identity, IdentityState};
    use chrono::Utc;

    fn active_identity() -> Identity {
        Identity {
            email: "alice@example.com".to_string(),
            created: Utc::now(),
            admin: false,
            id: None,
            state: IdentityState::Active {
                credentials: vec![Credential::new(
                    b"registered-credential",
                    b"public-key",
                    -7,
                    0,
                )],
            },
        }
    }

    async fn test_session() -> tower_sessions::Session {
        let db = crate::persistence::mem_db().await.unwrap();
        let store = tower_sessions_surrealdb_store::SurrealSessionStore::new(db, "sessions".into());
        tower_sessions::Session::new(None, std::sync::Arc::new(store), None)
    }

    #[tokio::test]
    async fn login_expires_at_absolute_limit_without_discarding_pending_authorization() {
        let session = test_session().await;
        super::establish_login(&session, &active_identity())
            .await
            .unwrap();
        let login_time = session
            .get::<i64>(super::LOGIN_TIME)
            .await
            .unwrap()
            .unwrap();
        let limit = time::Duration::days(30);
        let deadline = login_time + limit.whole_milliseconds() as i64;
        session
            .insert(crate::oauth::PENDING_AUTHORIZATION, "pending")
            .await
            .unwrap();

        // Repeated activity leaves the original login time intact.
        for now in [login_time, login_time + 5 * 86_400_000, deadline - 1] {
            super::expire_login(&session, limit, now).await.unwrap();
            assert!(session
                .get::<Identity>(super::IDENTITY)
                .await
                .unwrap()
                .is_some());
            assert_eq!(
                session.get::<i64>(super::LOGIN_TIME).await.unwrap(),
                Some(login_time)
            );
        }
        super::expire_login(&session, limit, deadline)
            .await
            .unwrap();
        assert!(session
            .get::<Identity>(super::IDENTITY)
            .await
            .unwrap()
            .is_none());
        assert!(session
            .get::<i64>(super::LOGIN_TIME)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            session
                .get::<String>(crate::oauth::PENDING_AUTHORIZATION)
                .await
                .unwrap()
                .as_deref(),
            Some("pending")
        );

        super::establish_login(&session, &active_identity())
            .await
            .unwrap();
        let new_login_time = session
            .get::<i64>(super::LOGIN_TIME)
            .await
            .unwrap()
            .unwrap();
        super::expire_login(&session, limit, new_login_time)
            .await
            .unwrap();
        assert!(session
            .get::<Identity>(super::IDENTITY)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn missing_or_future_login_times_require_authentication() {
        let session = test_session().await;
        for login_time in [None, Some(i64::MAX), Some(i64::MIN)] {
            session
                .insert(super::IDENTITY, active_identity())
                .await
                .unwrap();
            if let Some(login_time) = login_time {
                session.insert(super::LOGIN_TIME, login_time).await.unwrap();
            }
            super::expire_login(&session, time::Duration::days(30), 1_000)
                .await
                .unwrap();
            assert!(session
                .get::<Identity>(super::IDENTITY)
                .await
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn middleware_removes_expired_login_before_protected_handler() -> anyhow::Result<()> {
        use axum::{
            body::Body,
            http::{header, Request, StatusCode},
            routing::get,
            Router,
        };
        use tower::ServiceExt;
        use tower_sessions::Session;

        async fn seed(State(login_time): State<Option<i64>>, session: Session) {
            session
                .insert(super::IDENTITY, active_identity())
                .await
                .unwrap();
            if let Some(login_time) = login_time {
                session.insert(super::LOGIN_TIME, login_time).await.unwrap();
            }
        }
        async fn protected(session: Session) -> StatusCode {
            if session
                .get::<Identity>(super::IDENTITY)
                .await
                .unwrap()
                .is_some()
            {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            }
        }
        use axum::extract::State;
        let now = Utc::now().timestamp_millis();
        for (login_time, expected) in [
            (Some(now), StatusCode::OK),
            (Some(now - 31 * 86_400_000), StatusCode::UNAUTHORIZED),
            (None, StatusCode::UNAUTHORIZED),
        ] {
            let db = crate::persistence::mem_db().await?;
            let app = Router::new()
                .route("/seed", get(seed))
                .route("/protected", get(protected))
                .layer(axum::middleware::from_fn_with_state(
                    time::Duration::days(30),
                    super::enforce_max_login_time,
                ))
                .layer(crate::make_session_layer(db, time::Duration::days(5)))
                .with_state(login_time);
            let response = app
                .clone()
                .oneshot(Request::builder().uri("/seed").body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let cookie = response.headers()[header::SET_COOKIE]
                .to_str()?
                .split(';')
                .next()
                .unwrap()
                .to_string();
            // Activity can renew the idle timeout but cannot restore an expired login.
            for _ in 0..2 {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri("/protected")
                            .header(header::COOKIE, &cookie)
                            .body(Body::empty())?,
                    )
                    .await?;
                assert_eq!(response.status(), expected);
                if expected == StatusCode::OK {
                    assert!(
                        response.headers().contains_key(header::SET_COOKIE),
                        "read-only activity must renew the inactivity timeout"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn find_key_returns_matching_public_key() {
        let identity = active_identity();
        let result = find_key(&identity, b"registered-credential", "identity:alice").unwrap();
        assert_eq!(result, b"public-key");
    }

    #[test]
    fn find_key_returns_unauthorized_for_unknown_credential() {
        let identity = active_identity();
        let err = find_key(&identity, &[0xff, 0x00, 0x41], "identity:alice").unwrap_err();
        assert!(
            matches!(err, IdentityError::Unauthorized(message) if message == "Authentication failed")
        );
    }
}
