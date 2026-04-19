use crate::config::IdmouseConfig;
use anyhow::{anyhow, Context};
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use tracing::debug;

#[derive(Clone)]
pub struct IdmouseClient {
    client: reqwest::Client,
    config: IdmouseConfig,
}

#[derive(Deserialize)]
struct IdmouseTokenResponse {
    access_token: String,
}

impl IdmouseClient {
    pub fn new(config: IdmouseConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
        }
    }

    pub async fn fetch_access_token(&self) -> anyhow::Result<String> {
        let bearer_token = self
            .config
            .bearer_token()
            .context("Failed to read idmouse bearer token")?;

        debug!(url = %self.config.url, "Requesting SurrealDB access token from idmouse");

        let response = self
            .client
            .post(&self.config.url)
            .bearer_auth(bearer_token)
            .send()
            .await
            .context("Failed to call idmouse")?
            .error_for_status()
            .context("idmouse returned an error response")?;

        let token: IdmouseTokenResponse = response
            .json()
            .await
            .context("Failed to decode idmouse token response")?;

        if token.access_token.is_empty() {
            return Err(anyhow!("idmouse returned an empty access_token"));
        }

        debug!(
            access_token_len = token.access_token.len(),
            "Received SurrealDB access token from idmouse"
        );

        Ok(token.access_token)
    }
}

pub fn jwt_claims(token: &str) -> anyhow::Result<Value> {
    let mut parts = token.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| anyhow!("JWT is missing a header segment"))?;
    let claims = parts
        .next()
        .ok_or_else(|| anyhow!("JWT is missing a claims segment"))?;

    if parts.next().is_none() {
        return Err(anyhow!("JWT is missing a signature segment"));
    }

    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims)
        .context("Failed to base64url decode JWT claims")?;

    serde_json::from_slice(&claims).context("Failed to parse JWT claims as JSON")
}

#[cfg(test)]
mod tests {
    use super::{jwt_claims, IdmouseClient};
    use crate::config::IdmouseConfig;
    use axum::extract::State;
    use axum::http::header::AUTHORIZATION;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use rand::random;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[derive(Clone)]
    struct TestState {
        expected_auth_header: Arc<String>,
    }

    #[tokio::test]
    async fn fetch_access_token_reads_local_bearer_token_and_posts_to_idmouse() -> anyhow::Result<()>
    {
        let token_file = write_temp_token_file("local-bearer-token\n")?;
        let state = TestState {
            expected_auth_header: Arc::new("Bearer local-bearer-token".to_string()),
        };

        async fn issue_token(
            State(state): State<TestState>,
            headers: HeaderMap,
        ) -> (StatusCode, Json<serde_json::Value>) {
            let actual = headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);

            if actual.as_deref() != Some(state.expected_auth_header.as_str()) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "missing bearer token" })),
                );
            }

            (
                StatusCode::OK,
                Json(json!({ "access_token": "surreal-jwt-token" })),
            )
        }

        let app = Router::new()
            .route("/", post(issue_token))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let client = IdmouseClient::new(IdmouseConfig {
            url: format!("http://{address}/"),
            bearer_token_file: token_file.into_boxed_path(),
        });

        let token = client.fetch_access_token().await?;
        assert_eq!(token, "surreal-jwt-token");

        server.abort();
        Ok(())
    }

    #[test]
    fn jwt_claims_decodes_middle_segment() -> anyhow::Result<()> {
        let token = "eyJhbGciOiJub25lIn0.eyJucyI6ImRlZmF1bHQiLCJkYiI6ImlkZWxlcGhhbnQiLCJhYyI6InNlcnZpY2UifQ.signature";
        let claims = jwt_claims(token)?;

        assert_eq!(claims["ns"], "default");
        assert_eq!(claims["db"], "idelephant");
        assert_eq!(claims["ac"], "service");

        Ok(())
    }

    fn write_temp_token_file(contents: &str) -> anyhow::Result<PathBuf> {
        let path =
            std::env::temp_dir().join(format!("idelephant-idmouse-test-{}", random::<u64>()));
        std::fs::write(&path, contents)?;
        Ok(path)
    }
}
