use axum::http::StatusCode;
use axum::response::IntoResponse;
use thiserror::Error;
use tracing::error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("catch-all error: {0}")]
    Anyhow(#[from] anyhow::Error),
    #[error("Failure related to interacting with the session: {0}")]
    Session(#[from] tower_sessions::session::Error),
    // this would be things like when the db driver returns None but succeeds to create()
    #[error("Logic error: {0}")]
    Logic(String),
    #[error("Persistent storage error: {0}")]
    PersistentStorage(#[from] surrealdb::Error),
    #[error("Attempting to parse data with an invalid format: {detail}")]
    InvalidInput {
        detail: String,
        source: Option<anyhow::Error>,
    },
}

impl IntoResponse for IdentityError {
    fn into_response(self) -> axum::response::Response {
        error!("{}", self);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", self)).into_response()
    }
}
