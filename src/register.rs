use crate::error::IdentityError;
use crate::persistence::IdentityState::Allocated;
use crate::persistence::{Credential, Identity, IdentityState, PersistenceService};
use crate::util::make_token;
use crate::AppState;
use anyhow::anyhow;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use idelephant_webauthn::RegisterPublicKeyCredential;
use serde::Serialize;
use serde_json::Value;
use std::str;
use tower_sessions::Session;
use tracing::info;

const ORIGIN: &str = "http://localhost:3000";

#[derive(Serialize)]
pub(crate) struct RegisterStartResponse {
    challenge: String,
    user_id: String,
    email: String,
}

const REGISTERING_ID_KEY: &str = "registering_email";

pub(super) fn register_routes() -> Router<AppState> {
    Router::new()
        .route("/register-start", get(register_start))
        .route("/register-finish", post(register_finish))
}

async fn register_start(
    session: Session,
    State(persistence_service): State<PersistenceService>,
) -> Result<Json<RegisterStartResponse>, IdentityError> {
    let challenge = make_token();
    let Some(mut identity): Option<Identity> = session.get("idelephant.register_id").await? else {
        return Err(IdentityError::Anyhow(anyhow!(
            "attempted to register without verifying email"
        )));
    };

    identity.state = Allocated {
        challenge: challenge.clone(),
    };
    let user_id = identity.id()?;
    persistence_service.update_identity(&identity).await?;
    session.insert(REGISTERING_ID_KEY, &user_id).await?;
    info!("user allocated: {}", &user_id);
    Ok(Json(RegisterStartResponse {
        challenge: STANDARD_NO_PAD.encode(challenge),
        user_id: STANDARD_NO_PAD.encode(&user_id),
        email: identity.email,
    }))
}

pub(super) async fn register_finish(
    session: Session,
    State(persistence_service): State<PersistenceService>,
    Json(credential): Json<Value>,
) -> Result<(), IdentityError> {
    let credential: RegisterPublicKeyCredential = (&credential).try_into()?;

    let Some(id): Option<String> = session.get(REGISTERING_ID_KEY).await? else {
        return Err(IdentityError::Anyhow(anyhow!(
            "Could not find registration id in session"
        )));
    };

    let Some(mut identity) = persistence_service.fetch_identity(&id).await? else {
        return Err(IdentityError::Anyhow(anyhow!(
            "Could not find identity in persistent storage"
        )));
    };

    let Allocated { challenge } = identity.state else {
        return Err(IdentityError::Anyhow(anyhow!(
            "Trying to register identity not in state Allocated"
        )));
    };

    credential.validate(challenge, ORIGIN, "localhost", false)?;
    info!(
        "registered credential: {}",
        STANDARD_NO_PAD.encode(credential.id())
    );

    identity.state = IdentityState::Active {
        credentials: vec![Credential {
            id: credential.id().to_vec(),
            public_key: credential.response().public_key.to_vec(),
            public_key_algorithm: credential.response().public_key_algorithm,
            sign_count: credential.response().attestation.auth_data.sign_count,
        }],
    };

    persistence_service.update_identity(&identity).await?;
    session.remove::<String>(REGISTERING_ID_KEY).await?;
    Ok(())
}
