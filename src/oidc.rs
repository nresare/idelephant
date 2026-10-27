use crate::error::IdentityError;
use crate::persistence::{JwkKey, PersistenceService};
use crate::AppState;
use anyhow::Context;
pub use authzoo_oauth::discovery::OpenidConfiguration;
pub use authzoo_oauth::token::JwksResponse;
use authzoo_oauth::token::{
    AccessTokenRequest, IdTokenRequest, Principal, SigningKey as TokenSigningKey, TokenIssuer,
    TOKEN_TTL_HOURS,
};
use axum::extract::FromRef;
use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use p256::pkcs8::EncodePrivateKey;
use std::ops::Deref;

const ROTATION_HOURS: i64 = 8;

#[derive(Clone)]
pub struct OidcService {
    tokens: TokenIssuer,
    persistence: PersistenceService,
    pub clients: crate::client_metadata::ClientResolver,
}

struct PreparedKey {
    kid: String,
    private_key_der: Vec<u8>,
}

impl OidcService {
    pub fn new(issuer: &str, persistence: PersistenceService) -> Self {
        Self {
            tokens: TokenIssuer::new(issuer),
            persistence,
            clients: crate::client_metadata::ClientResolver::default(),
        }
    }

    pub fn configuration(&self) -> OpenidConfiguration {
        OpenidConfiguration::new(self.issuer())
    }

    pub fn issuer_basename(&self) -> &str {
        self.issuer()
            .split("://")
            .nth(1)
            .unwrap_or(self.issuer())
            .split('/')
            .next()
            .unwrap_or(self.issuer())
    }

    pub async fn jwks(&self) -> Result<JwksResponse, IdentityError> {
        self.jwks_at(Utc::now()).await
    }

    pub async fn mint_id_token(
        &self,
        subject: &str,
        audience: &str,
        nonce: Option<&str>,
        email: &str,
        groups: Option<&[String]>,
    ) -> Result<String, IdentityError> {
        self.mint_id_token_at(subject, audience, nonce, email, groups, Utc::now())
            .await
    }

    pub fn issuer(&self) -> &str {
        self.tokens.issuer()
    }

    pub async fn mint_access_token(
        &self,
        identity: &crate::persistence::Identity,
        client_id: &str,
        resource: Option<&str>,
        scopes: &[String],
    ) -> Result<String, IdentityError> {
        let now = Utc::now();
        self.reconcile_keys(now).await?;
        let key = self
            .persistence
            .fetch_signing_key_for_time(now)
            .await?
            .ok_or_else(|| IdentityError::Logic("No active signing key".into()))?;
        let subject = identity.id()?;
        let groups = if scopes.iter().any(|s| s == "groups") {
            Some(self.persistence.group_names_for_user(&subject).await?)
        } else {
            None
        };
        Ok(self.tokens.mint_access_token(
            &TokenSigningKey::from_pkcs8(&key.kid, &key.private_key_der)?,
            &Principal {
                subject: &subject,
                email: Some(&identity.email),
                groups: groups.as_deref().unwrap_or_default(),
            },
            AccessTokenRequest {
                client_id,
                resource,
                scopes,
            },
            now,
        )?)
    }

    async fn jwks_at(&self, now: DateTime<Utc>) -> Result<JwksResponse, IdentityError> {
        self.reconcile_keys(now).await?;
        let keys = self
            .persistence
            .list_jwks_keys(now)
            .await?
            .into_iter()
            .map(|key| {
                TokenSigningKey::from_pkcs8(&key.kid, &key.private_key_der)
                    .map(|key| key.public_jwk())
            })
            .collect::<Result<_, _>>()?;
        Ok(JwksResponse { keys })
    }

    async fn mint_id_token_at(
        &self,
        subject: &str,
        audience: &str,
        nonce: Option<&str>,
        email: &str,
        groups: Option<&[String]>,
        now: DateTime<Utc>,
    ) -> Result<String, IdentityError> {
        self.reconcile_keys(now).await?;
        let signing_key = self
            .persistence
            .fetch_signing_key_for_time(now)
            .await?
            .ok_or_else(|| {
                IdentityError::Logic(
                    "No active JWK signing key available after reconciliation".to_string(),
                )
            })?;
        Ok(self.tokens.mint_id_token(
            &TokenSigningKey::from_pkcs8(&signing_key.kid, &signing_key.private_key_der)?,
            &Principal {
                subject,
                email: Some(email),
                groups: groups.unwrap_or_default(),
            },
            IdTokenRequest {
                audience,
                nonce,
                authenticated_at: now,
                include_groups: groups.is_some(),
            },
            now,
        )?)
    }

    async fn reconcile_keys(&self, now: DateTime<Utc>) -> Result<(), IdentityError> {
        self.persistence.delete_expired_jwk_keys(now).await?;
        let current_slot = slot_start(now)?;
        let next_slot = current_slot + Duration::hours(ROTATION_HOURS);
        self.ensure_key_for_slot(current_slot).await?;
        self.ensure_key_for_slot(next_slot).await?;
        Ok(())
    }

    async fn ensure_key_for_slot(
        &self,
        active_from: DateTime<Utc>,
    ) -> Result<JwkKey, IdentityError> {
        if let Some(existing) = self.persistence.fetch_jwk_key_by_slot(active_from).await? {
            return Ok(existing);
        }

        let prepared = prepare_key()?;
        match self
            .persistence
            .create_jwk_key(
                &prepared.kid,
                &prepared.private_key_der,
                active_from,
                active_from + Duration::hours(ROTATION_HOURS + TOKEN_TTL_HOURS),
                Utc::now(),
            )
            .await
        {
            Ok(created) => Ok(created),
            Err(err) if self.persistence.is_duplicate_jwk_key_error(&err) => self
                .persistence
                .fetch_jwk_key_by_slot(active_from)
                .await?
                .ok_or_else(|| {
                    IdentityError::Logic(
                        "JWK key insert raced but the winner row could not be reloaded".to_string(),
                    )
                }),
            Err(err) => Err(err),
        }
    }

    #[cfg(test)]
    pub(crate) async fn reconcile_keys_at(&self, now: DateTime<Utc>) -> Result<(), IdentityError> {
        self.reconcile_keys(now).await
    }

    #[cfg(test)]
    pub(crate) async fn jwks_for_time(
        &self,
        now: DateTime<Utc>,
    ) -> Result<JwksResponse, IdentityError> {
        self.jwks_at(now).await
    }

    #[cfg(test)]
    pub(crate) async fn mint_id_token_for_time(
        &self,
        subject: &str,
        audience: &str,
        nonce: Option<&str>,
        email: &str,
        groups: Option<&[String]>,
        now: DateTime<Utc>,
    ) -> Result<String, IdentityError> {
        self.mint_id_token_at(subject, audience, nonce, email, groups, now)
            .await
    }
}

impl FromRef<AppState> for OidcService {
    fn from_ref(input: &AppState) -> Self {
        input.oidc.deref().clone()
    }
}

fn prepare_key() -> Result<PreparedKey, anyhow::Error> {
    let signing_key = SigningKey::generate();
    let der = signing_key
        .to_pkcs8_der()
        .context("Could not encode OIDC signing key to PKCS8")?;
    Ok(PreparedKey {
        kid: crate::util::Token::random().base64(),
        private_key_der: der.as_bytes().to_vec(),
    })
}

fn slot_start(now: DateTime<Utc>) -> Result<DateTime<Utc>, IdentityError> {
    let hour = now.hour() as i64;
    let slot_hour = hour - (hour % ROTATION_HOURS);
    Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), slot_hour as u32, 0, 0)
        .single()
        .ok_or_else(|| IdentityError::Logic("Failed to calculate JWK rotation slot".to_string()))
}

#[cfg(test)]
mod tests {
    use super::{slot_start, OidcService};
    use crate::persistence::{mem_db, PersistenceService};
    use anyhow::Result;
    use base64::Engine;
    use chrono::{Duration, TimeZone, Utc};
    use jsonwebtoken::decode_header;

    #[tokio::test]
    async fn mint_id_token_produces_jwt() -> Result<()> {
        let db = mem_db().await?;
        let oidc = OidcService::new("http://localhost:8080", PersistenceService::new(db));
        let token = oidc
            .mint_id_token(
                "identity:alice",
                "client-1",
                Some("nonce-123"),
                "alice@example.com",
                None,
            )
            .await?;
        assert_eq!(token.split('.').count(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn groups_claim_is_only_included_when_supplied() -> Result<()> {
        let db = mem_db().await?;
        let oidc = OidcService::new("http://localhost:8080", PersistenceService::new(db));
        let groups = vec!["Engineering".to_string(), "Operations".to_string()];
        let with_groups = oidc
            .mint_id_token(
                "identity:alice",
                "client-1",
                None,
                "alice@example.com",
                Some(&groups),
            )
            .await?;
        let without_groups = oidc
            .mint_id_token(
                "identity:alice",
                "client-1",
                None,
                "alice@example.com",
                None,
            )
            .await?;
        let claims = |token: &str| -> Result<serde_json::Value> {
            let payload = token.split('.').nth(1).unwrap();
            Ok(serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?,
            )?)
        };
        assert_eq!(
            claims(&with_groups)?["groups"],
            serde_json::json!(["Engineering", "Operations"])
        );
        assert!(claims(&without_groups)?.get("groups").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn configuration_uses_issuer() {
        let db = mem_db().await.expect("mem db should initialize");
        let oidc = OidcService::new("http://localhost:8080", PersistenceService::new(db));
        let configuration = oidc.configuration();
        assert_eq!(
            configuration.authorization_endpoint,
            "http://localhost:8080/authorize"
        );
        assert_eq!(configuration.jwks_uri, "http://localhost:8080/jwks.json");
        assert_eq!(
            configuration.token_endpoint_auth_methods_supported,
            ["none", "client_secret_basic"]
        );
    }

    #[test]
    fn slot_start_rounds_down_to_8_hour_boundary() {
        let now = Utc.with_ymd_and_hms(2026, 4, 12, 15, 7, 11).unwrap();
        assert_eq!(
            slot_start(now).unwrap(),
            Utc.with_ymd_and_hms(2026, 4, 12, 8, 0, 0).unwrap()
        );
    }

    #[tokio::test]
    async fn jwks_contains_current_and_next_key() -> Result<()> {
        let db = mem_db().await?;
        let oidc = OidcService::new("http://localhost:8080", PersistenceService::new(db));
        let now = Utc.with_ymd_and_hms(2026, 4, 12, 10, 0, 0).unwrap();

        let jwks = oidc.jwks_for_time(now).await?;
        assert_eq!(jwks.keys.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn jwks_keeps_retired_key_for_token_ttl() -> Result<()> {
        let db = mem_db().await?;
        let oidc = OidcService::new("http://localhost:8080", PersistenceService::new(db));
        let before_rotation = Utc.with_ymd_and_hms(2026, 4, 12, 7, 59, 0).unwrap();
        oidc.reconcile_keys_at(before_rotation).await?;

        let after_rotation = Utc.with_ymd_and_hms(2026, 4, 12, 8, 1, 0).unwrap();
        let jwks = oidc.jwks_for_time(after_rotation).await?;
        assert_eq!(jwks.keys.len(), 3);

        let after_grace = Utc.with_ymd_and_hms(2026, 4, 12, 9, 1, 0).unwrap();
        let jwks = oidc.jwks_for_time(after_grace).await?;
        assert_eq!(jwks.keys.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn minted_token_uses_current_key_kid() -> Result<()> {
        let db = mem_db().await?;
        let oidc = OidcService::new("http://localhost:8080", PersistenceService::new(db));
        let now = Utc.with_ymd_and_hms(2026, 4, 12, 10, 0, 0).unwrap();

        let token = oidc
            .mint_id_token_for_time(
                "identity:alice",
                "client-1",
                Some("nonce-123"),
                "alice@example.com",
                None,
                now,
            )
            .await?;
        let kid = decode_header(&token)?.kid.unwrap();
        let jwks = oidc.jwks_for_time(now).await?;
        assert!(jwks.keys.iter().any(|key| key.kid == kid));
        Ok(())
    }

    #[tokio::test]
    async fn gap_recovery_creates_only_current_and_next_slots() -> Result<()> {
        let db = mem_db().await?;
        let persistence = PersistenceService::new(db);
        let oidc = OidcService::new("http://localhost:8080", persistence.clone());

        let now = Utc.with_ymd_and_hms(2026, 4, 13, 18, 0, 0).unwrap();
        oidc.reconcile_keys_at(now).await?;

        let keys = persistence.list_jwks_keys(now).await?;
        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys[0].active_from,
            Utc.with_ymd_and_hms(2026, 4, 13, 16, 0, 0).unwrap()
        );
        assert_eq!(
            keys[1].active_from,
            Utc.with_ymd_and_hms(2026, 4, 14, 0, 0, 0).unwrap()
        );
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_reconcile_creates_one_row_per_slot() -> Result<()> {
        let db = mem_db().await?;
        let persistence = PersistenceService::new(db);
        let oidc = OidcService::new("http://localhost:8080", persistence.clone());
        let now = Utc.with_ymd_and_hms(2026, 4, 12, 10, 0, 0).unwrap();

        let (first, second) =
            tokio::join!(oidc.reconcile_keys_at(now), oidc.reconcile_keys_at(now));
        first?;
        second?;

        let keys = persistence
            .list_jwks_keys(now + Duration::minutes(1))
            .await?;
        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys[0].active_from,
            Utc.with_ymd_and_hms(2026, 4, 12, 8, 0, 0).unwrap()
        );
        assert_eq!(
            keys[1].active_from,
            Utc.with_ymd_and_hms(2026, 4, 12, 16, 0, 0).unwrap()
        );
        Ok(())
    }
}
