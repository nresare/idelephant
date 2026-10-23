use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::DecodeError;
use handlebars::RenderError;
use thiserror::Error;
use tracing::error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("catch-all error: {0:#}")]
    Anyhow(#[from] anyhow::Error),
    #[error("{0}")]
    BadRequest(String),
    #[error("OAuth error: {0}")]
    OAuth(&'static str),
    #[error("OAuth error: {code}: {detail}")]
    OAuthDetailed { code: &'static str, detail: String },
    #[error("{0}")]
    Unauthorized(String),
    #[error("Failure related to interacting with the session: {0}")]
    Session(#[from] tower_sessions::session::Error),
    // this would be things like when the db driver returns None but succeeds to create()
    #[error("Logic error: {0}")]
    Logic(String),
    #[error("Persistent storage error: {0}")]
    PersistentStorage(#[from] Box<surrealdb::Error>),
    #[error("Email already in use")]
    EmailAlreadyInUse,
    #[error("Failed to render html output")]
    Render(#[from] RenderError),
    #[error("Failed to parse token")]
    Token(#[from] DecodeError),
}

#[derive(Clone)]
pub(crate) struct BrowserErrorDetail {
    pub message: String,
    pub code: Option<&'static str>,
}

impl IdentityError {
    pub(crate) fn oauth_error_code(&self) -> Option<&'static str> {
        match self {
            Self::OAuth(code) | Self::OAuthDetailed { code, .. } => Some(code),
            _ => None,
        }
    }

    fn browser_detail(&self) -> BrowserErrorDetail {
        let message = match self {
            Self::OAuthDetailed { detail, .. } => detail.clone(),
            Self::BadRequest(message) | Self::Unauthorized(message) => message.clone(),
            Self::OAuth(code) => match *code {
                "invalid_client" => "The application could not be identified or its client metadata could not be validated.",
                "invalid_target" => "The requested resource is missing, invalid, or does not match the resource originally authorized.",
                "invalid_request" => "The authorization request is invalid or no longer matches the application's current configuration.",
                "invalid_scope" => "The application requested permissions that are not supported or have not been granted.",
                "access_denied" => "Authorization was declined.",
                _ => "The authorization request could not be completed.",
            }.into(),
            _ => "An internal error prevented authorization. The identity provider's administrator can find further details in the server logs.".into(),
        };
        BrowserErrorDetail {
            message,
            code: self.oauth_error_code(),
        }
    }
}

impl IntoResponse for IdentityError {
    fn into_response(self) -> axum::response::Response {
        error!("{:#}", self);
        let detail = self.browser_detail();
        let mut response = match self {
            IdentityError::OAuth(code) | IdentityError::OAuthDetailed { code, .. } => (
                StatusCode::BAD_REQUEST,
                [("cache-control", "no-store"), ("pragma", "no-cache")],
                axum::Json(serde_json::json!({"error": code})),
            )
                .into_response(),
            IdentityError::BadRequest(message) => {
                (StatusCode::BAD_REQUEST, message).into_response()
            }
            IdentityError::Unauthorized(message) => {
                (StatusCode::UNAUTHORIZED, message).into_response()
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", other)).into_response(),
        };
        response.extensions_mut().insert(detail);
        response
    }
}

impl From<surrealdb::Error> for IdentityError {
    fn from(err: surrealdb::Error) -> Self {
        IdentityError::PersistentStorage(Box::new(err))
    }
}
