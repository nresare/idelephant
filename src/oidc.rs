use crate::error::IdentityError;
use crate::persistence::{JwkKey, PersistenceService};
use crate::AppState;
use anyhow::{anyhow, Context};
use axum::extract::FromRef;
use base64::Engine;
use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde::Serialize;
use std::ops::Deref;

const ROTATION_HOURS: i64 = 8;
const TOKEN_TTL_HOURS: i64 = 1;

#[derive(Clone)]
pub struct OidcService {
    issuer: String,
    persistence: PersistenceService,
}

#[derive(Serialize, Clone)]
pub struct OpenidConfiguration {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    claims_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
}

#[derive(Serialize, Clone)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

#[derive(Serialize, Clone)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub kid: String,
    pub x: String,
    pub y: String,
}

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    auth_time: i64,
    nonce: Option<&'a str>,
    email: &'a str,
}

struct PreparedKey {
    kid: String,
    private_key_der: Vec<u8>,
}

impl OidcService {
    pub fn new(issuer: &str, persistence: PersistenceService) -> Self {
        Self {
            issuer: issuer.to_string(),
            persistence,
        }
    }

    pub fn configuration(&self) -> OpenidConfiguration {
        OpenidConfiguration {
            issuer: self.issuer.clone(),
            authorization_endpoint: format!("{}/authorize", self.issuer),
            token_endpoint: format!("{}/token", self.issuer),
            userinfo_endpoint: format!("{}/userinfo", self.issuer),
            jwks_uri: format!("{}/jwks.json", self.issuer),
            response_types_supported: vec!["code".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["ES256".to_string()],
            scopes_supported: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec!["none".to_string()],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "auth_time".to_string(),
                "nonce".to_string(),
                "email".to_string(),
            ],
            grant_types_supported: vec!["authorization_code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
        }
    }

    pub fn issuer_basename(&self) -> &str {
        self.issuer
            .split("://")
            .nth(1)
            .unwrap_or(&self.issuer)
            .split('/')
            .next()
            .unwrap_or(&self.issuer)
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
    ) -> Result<String, IdentityError> {
        self.mint_id_token_at(subject, audience, nonce, email, Utc::now())
            .await
    }

    async fn jwks_at(&self, now: DateTime<Utc>) -> Result<JwksResponse, IdentityError> {
        self.reconcile_keys(now).await?;
        let keys = self
            .persistence
            .list_jwks_keys(now)
            .await?
            .into_iter()
            .map(|key| key.public_jwk())
            .collect();
        Ok(JwksResponse { keys })
    }

    async fn mint_id_token_at(
        &self,
        subject: &str,
        audience: &str,
        nonce: Option<&str>,
        email: &str,
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
        let claims = IdTokenClaims {
            iss: &self.issuer,
            sub: subject,
            aud: audience,
            exp: (now + Duration::hours(TOKEN_TTL_HOURS)).timestamp(),
            iat: now.timestamp(),
            auth_time: now.timestamp(),
            nonce,
            email,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(signing_key.kid.clone());
        let encoding_key = EncodingKey::from_ec_der(&signing_key.private_key_der);
        jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(|e| anyhow!(e).into())
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
        now: DateTime<Utc>,
    ) -> Result<String, IdentityError> {
        self.mint_id_token_at(subject, audience, nonce, email, now)
            .await
    }
}

impl FromRef<AppState> for OidcService {
    fn from_ref(input: &AppState) -> Self {
        input.oidc.deref().clone()
    }
}

fn prepare_key() -> Result<PreparedKey, anyhow::Error> {
    let signing_key = SigningKey::random(&mut OsRng);
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

fn build_jwk(verifying_key: &VerifyingKey, kid: &str) -> Jwk {
    let encoded = verifying_key.to_encoded_point(false);
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        encoded
            .x()
            .expect("uncompressed P-256 points always have x"),
    );
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        encoded
            .y()
            .expect("uncompressed P-256 points always have y"),
    );
    Jwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        use_: "sig".to_string(),
        alg: "ES256".to_string(),
        kid: kid.to_string(),
        x,
        y,
    }
}

impl JwkKey {
    fn public_jwk(&self) -> Jwk {
        let signing_key = SigningKey::from_pkcs8_der(&self.private_key_der)
            .expect("stored JWK private key must decode as P-256 secret key");
        let verifying_key = VerifyingKey::from(&signing_key);
        build_jwk(&verifying_key, &self.kid)
    }
}

#[cfg(test)]
mod tests {
    use super::{slot_start, OidcService};
    use crate::persistence::{mem_db, PersistenceService};
    use anyhow::Result;
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
            )
            .await?;
        assert_eq!(token.split('.').count(), 3);
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
