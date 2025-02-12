use crate::error::IdentityError;
use crate::persistence::IdentityState::Allocated;
use crate::persistence::{Credential, Identity, IdentityState};
use crate::util::make_token;
use crate::webauthn::PublicKeyCredentialRegister;
use crate::AppState;
use anyhow::anyhow;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str;
use tower_sessions::Session;
use tracing::info;

const ORIGIN: &str = "http://localhost:3000";

#[derive(Deserialize)]
pub(crate) struct RegisterStart {
    email: String,
}

#[derive(Serialize)]
pub(crate) struct RegisterStartResponse {
    challenge: String,
    user_id: String,
}

const REGISTERING_ID_KEY: &str = "registering_email";

pub(super) fn register_routes() -> Router<AppState> {
    Router::new()
        .route("/register-start", post(register_start))
        .route("/register-finish", post(register_finish))
}

async fn register_start(
    session: Session,
    State(state): State<AppState>,
    Json(register_start): Json<RegisterStart>,
) -> Result<Json<RegisterStartResponse>, IdentityError> {
    info!(register_start.email, "creating a challenge for user");
    let email = register_start.email;
    let challenge = make_token();
    let identity = Identity {
        email,
        state: Allocated {
            challenge: challenge.clone(),
        },
        created: Utc::now(),
    };
    let user_id = state.ps.persist(identity).await?;
    session.insert(REGISTERING_ID_KEY, &user_id).await?;
    info!(user_id, "user allocated");
    Ok(Json(RegisterStartResponse {
        challenge: STANDARD_NO_PAD.encode(challenge),
        user_id: STANDARD_NO_PAD.encode(user_id),
    }))
}

pub(super) async fn register_finish(
    session: Session,
    State(state): State<AppState>,
    Json(credential): Json<Value>,
) -> Result<(), IdentityError> {
    let credential: PublicKeyCredentialRegister = (&credential).try_into()?;

    let Some(id): Option<String> = session.get(REGISTERING_ID_KEY).await? else {
        return Err(IdentityError::Anyhow(anyhow!(
            "Could not find registration id in session"
        )));
    };

    let Some(mut identity) = state.ps.fetch(&id).await? else {
        return Err(IdentityError::Anyhow(anyhow!(
            "Could not find identity in persistent storage"
        )));
    };

    let Allocated { challenge } = identity.state else {
        return Err(IdentityError::Anyhow(anyhow!(
            "Trying to register identity not in state Allocated"
        )));
    };

    credential.validate(challenge, ORIGIN)?;

    identity.state = IdentityState::Active {
        credentials: vec![Credential {
            id: credential.id,
            public_key: credential.response.public_key,
            public_key_algorithm: credential.response.public_key_algorithm,
        }],
    };

    state.ps.update(&id, identity).await?;
    session.remove::<String>(REGISTERING_ID_KEY).await?;
    Ok(())
}
