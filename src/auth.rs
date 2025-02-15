use crate::error::IdentityError;
use crate::persistence::IdentityState::Active;
use crate::persistence::{Identity, PersistenceService};
use crate::util::make_token;
use crate::AppState;
use anyhow::{anyhow, Context};
use axum::extract::State;
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

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/auth-start", get(auth_start))
        .route("/auth-finish", post(auth_finish))
}

#[derive(Serialize)]
struct AuthStart {
    challenge: String,
}

const AUTH_CHALLENGE: &str = "auth-challenge";

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
    let Some(challenge): Option<Vec<u8>> = session.get(AUTH_CHALLENGE).await? else {
        return Err(IdentityError::Anyhow(anyhow!(
            "Could not find challenge in session"
        )));
    };
    let credential: PublicKeyCredentialAuthenticate = (&credential).try_into()?;

    let user_handle = from_utf8(credential.response.user_handle.as_slice()).context(format!(
        "Could not convert user handle bytes {:?} to String",
        &credential.response.user_handle
    ))?;

    let Some(identity) = persistence_service.fetch(user_handle).await? else {
        return Err(IdentityError::Anyhow(anyhow!(
            "Could not find identity with id {user_handle}"
        )));
    };

    let key = find_key(identity, &credential.id)?;

    credential.verify(&key, &challenge)?;

    Ok("OK".to_string())
}

fn find_key(identity: Identity, credential_id: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let Active { credentials } = identity.state else {
        return Err(anyhow!("Identity is not in state active").into());
    };
    for credential in credentials {
        if credential.id == credential_id {
            return Ok(credential.public_key);
        }
    }
    Err(anyhow!("Could not find key with id for user").into())
}
