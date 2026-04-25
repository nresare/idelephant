use crate::config::IdmouseConfig;
use crate::later::{Do, LaterService};
use anyhow::{anyhow, Context};
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use surrealdb::engine::any::Any;
use surrealdb::Surreal;
use tracing::debug;
use tracing::{info, warn};

const RENEW_MARGIN: Duration = Duration::from_secs(10);
const INITIAL_RENEW_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRIES: usize = 5;

#[derive(Clone)]
pub struct IdmouseClient {
    client: reqwest::Client,
    config: IdmouseConfig,
}

#[derive(Deserialize)]
struct IdmouseTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdmouseTokenLease {
    pub access_token: String,
    pub expires_in: Duration,
}

impl IdmouseClient {
    pub fn new(config: IdmouseConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
        }
    }

    pub async fn fetch_token_lease(&self) -> anyhow::Result<IdmouseTokenLease> {
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

        if token.expires_in == 0 {
            return Err(anyhow!("idmouse returned an invalid expires_in of 0"));
        }

        Ok(IdmouseTokenLease {
            access_token: token.access_token,
            expires_in: Duration::from_secs(token.expires_in),
        })
    }

    pub async fn authenticate_db(
        &self,
        db: Arc<Surreal<Any>>,
        later: LaterService,
    ) -> anyhow::Result<()> {
        let lease = self.fetch_token_lease().await?;
        match jwt_claims(&lease.access_token) {
            Ok(claims) => debug!(claims = %claims, "Authenticating to SurrealDB with idmouse JWT"),
            Err(error) => debug!(?error, "Failed to decode idmouse JWT claims"),
        }
        db.authenticate(&lease.access_token).await?;
        later.later(
            RenewAuthentication::new(later.clone(), db, self.clone(), 0),
            renewal_delay(lease.expires_in),
        );
        Ok(())
    }
}

fn renewal_delay(expires_in: Duration) -> Duration {
    expires_in.saturating_sub(RENEW_MARGIN)
}

fn retry_delay(retry: usize) -> Duration {
    INITIAL_RENEW_RETRY_DELAY.saturating_mul(1u32 << retry)
}

struct RenewAuthentication {
    later: LaterService,
    db: Arc<Surreal<Any>>,
    client: IdmouseClient,
    retry: usize,
}

impl RenewAuthentication {
    fn new(
        later: LaterService,
        db: Arc<Surreal<Any>>,
        client: IdmouseClient,
        retry: usize,
    ) -> Self {
        Self {
            later,
            db,
            client,
            retry,
        }
    }

    async fn execute(self) {
        match self.try_renew().await {
            Ok(next_lease) => {
                info!("Renewed SurrealDB authentication from idmouse");
                self.later.later(
                    RenewAuthentication::new(
                        self.later.clone(),
                        self.db.clone(),
                        self.client.clone(),
                        0,
                    ),
                    renewal_delay(next_lease.expires_in),
                );
            }
            Err((error, message)) => self.retry_later_or_stop(error, message),
        }
    }

    async fn try_renew(&self) -> Result<IdmouseTokenLease, (String, &'static str)> {
        let next_lease = self
            .client
            .fetch_token_lease()
            .await
            .map_err(|error| (error.to_string(), "Failed to fetch renewed idmouse token"))?;
        match jwt_claims(&next_lease.access_token) {
            Ok(claims) => debug!(claims = %claims, "Authenticating to SurrealDB with idmouse JWT"),
            Err(error) => debug!(?error, "Failed to decode idmouse JWT claims"),
        }
        self.db
            .authenticate(next_lease.access_token.clone())
            .await
            .map_err(|error| {
                (
                    error.to_string(),
                    "Failed to renew SurrealDB authentication",
                )
            })?;
        Ok(next_lease)
    }

    fn retry_later_or_stop(self, error: String, message: &'static str) {
        if self.retry >= MAX_RETRIES {
            warn!(
                error = %error,
                max_retries = MAX_RETRIES,
                "{message}; giving up"
            );
            return;
        }

        let next_retry = self.retry + 1;
        warn!(
            error = %error,
            retry = next_retry,
            max_retries = MAX_RETRIES,
            "{message}; rescheduling with exponential backoff"
        );
        self.later.later(
            RenewAuthentication::new(
                self.later.clone(),
                self.db.clone(),
                self.client.clone(),
                next_retry,
            ),
            retry_delay(self.retry),
        );
    }
}

impl Do for RenewAuthentication {
    fn run(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            self.execute().await;
        })
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
    use super::{jwt_claims, renewal_delay, retry_delay, IdmouseClient, IdmouseTokenLease};
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
    use std::time::Duration;

    #[derive(Clone)]
    struct TestState {
        expected_auth_header: Arc<String>,
    }

    #[tokio::test]
    async fn fetch_token_lease_reads_local_bearer_token_and_posts_to_idmouse() -> anyhow::Result<()>
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
                Json(json!({
                    "access_token": "surreal-jwt-token",
                    "expires_in": 42
                })),
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
            token_path: token_file.into_boxed_path(),
        });

        let token = client.fetch_token_lease().await?;
        assert_eq!(
            token,
            IdmouseTokenLease {
                access_token: "surreal-jwt-token".to_string(),
                expires_in: std::time::Duration::from_secs(42),
            }
        );

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

    #[test]
    fn renewal_delay_renews_ten_seconds_before_expiry() {
        assert_eq!(
            renewal_delay(Duration::from_secs(45)),
            Duration::from_secs(35)
        );
    }

    #[test]
    fn renewal_delay_is_immediate_when_expiry_is_within_margin() {
        assert_eq!(renewal_delay(Duration::from_secs(10)), Duration::ZERO);
        assert_eq!(renewal_delay(Duration::from_secs(3)), Duration::ZERO);
    }

    #[test]
    fn retry_delay_uses_exponential_backoff_from_one_second() {
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(1), Duration::from_secs(2));
        assert_eq!(retry_delay(2), Duration::from_secs(4));
        assert_eq!(retry_delay(3), Duration::from_secs(8));
        assert_eq!(retry_delay(4), Duration::from_secs(16));
    }

    fn write_temp_token_file(contents: &str) -> anyhow::Result<PathBuf> {
        let path =
            std::env::temp_dir().join(format!("idelephant-idmouse-test-{}", random::<u64>()));
        std::fs::write(&path, contents)?;
        Ok(path)
    }
}
