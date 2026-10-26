use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use idp_oauth::client_metadata::{MetadataError, ResolveError};

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("{0}")]
    BadRequest(String),
    #[error("OAuth error: {0}")]
    OAuth(&'static str),
    #[error("Upstream authentication failed")]
    Upstream,
    #[error("Transient state capacity exceeded")]
    Capacity,
    #[error("Internal broker error")]
    Internal,
}

impl BrokerError {
    pub(crate) fn rejected(code: &'static str, reason: &'static str) -> Self {
        tracing::warn!(oauth_error = code, reason, "OAuth request rejected");
        Self::OAuth(code)
    }
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        // Do not format BadRequest strings: some include caller-supplied values.
        let reason = match &self {
            Self::BadRequest(_) => "invalid_request_parameters",
            Self::OAuth(code) => code,
            Self::Upstream => "upstream_failure",
            Self::Capacity => "state_or_concurrency_limit",
            Self::Internal => "internal_error",
        };
        tracing::warn!(reason, "Request failed");
        let (status, code, description) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "invalid_request", message),
            Self::OAuth(code) => (
                StatusCode::BAD_REQUEST,
                code,
                "The authorization grant could not be accepted.".into(),
            ),
            Self::Upstream => (
                StatusCode::BAD_GATEWAY,
                "server_error",
                "Upstream sign-in could not be completed. Start authorization again.".into(),
            ),
            Self::Capacity => (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "The broker is busy. Try again later.".into(),
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The broker could not complete the request.".into(),
            ),
        };
        (
            status,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            axum::Json(serde_json::json!({"error":code,"error_description":description})),
        )
            .into_response()
    }
}

impl From<MetadataError> for BrokerError {
    fn from(_: MetadataError) -> Self {
        Self::rejected("invalid_client", "client_metadata_resolution_failed")
    }
}
impl From<ResolveError<std::convert::Infallible>> for BrokerError {
    fn from(error: ResolveError<std::convert::Infallible>) -> Self {
        match error {
            ResolveError::Metadata(error) => error.into(),
            ResolveError::Registry(never) => match never {},
        }
    }
}
impl From<idp_oauth::token::TokenError> for BrokerError {
    fn from(_: idp_oauth::token::TokenError) -> Self {
        tracing::error!(reason = "token_signing_failed", "Token issuance failed");
        Self::Internal
    }
}

impl From<idp_oauth::protocol::ProtocolError> for BrokerError {
    fn from(error: idp_oauth::protocol::ProtocolError) -> Self {
        match error {
            idp_oauth::protocol::ProtocolError::BadRequest(detail) => Self::BadRequest(detail),
            idp_oauth::protocol::ProtocolError::OAuth(code) => Self::OAuth(code),
        }
    }
}
