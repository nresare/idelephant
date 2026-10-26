//! ES256 token issuance from application-supplied identity claims and keys.
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::ecdsa::{SigningKey as EcSigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use serde::Serialize;

pub const TOKEN_TTL_HOURS: i64 = 1;

/// Claims supplied by an application's local directory or upstream provider.
/// No account provisioning or database identifier is required.
pub struct Principal<'a> {
    pub subject: &'a str,
    pub email: Option<&'a str>,
    pub groups: &'a [String],
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

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("Invalid P-256 PKCS8 signing key")]
    InvalidSigningKey,
    #[error("Could not sign token: {0}")]
    Encoding(#[from] jsonwebtoken::errors::Error),
}

/// An ES256 key loaded from application-managed PKCS8 material.
/// Storage, key selection, rotation, and retention remain application concerns.
pub struct SigningKey {
    kid: String,
    encoding_key: EncodingKey,
    public_jwk: Jwk,
}

impl SigningKey {
    pub fn from_pkcs8(kid: &str, private_key_der: &[u8]) -> Result<Self, TokenError> {
        let key = EcSigningKey::from_pkcs8_der(private_key_der)
            .map_err(|_| TokenError::InvalidSigningKey)?;
        let verifying_key = VerifyingKey::from(&key);
        let encoded = verifying_key.to_sec1_point(false);
        let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let public_jwk = Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            use_: "sig".into(),
            alg: "ES256".into(),
            kid: kid.into(),
            x: base64.encode(encoded.x().expect("uncompressed P-256 point has x")),
            y: base64.encode(encoded.y().expect("uncompressed P-256 point has y")),
        };
        Ok(Self {
            kid: kid.into(),
            encoding_key: EncodingKey::from_ec_der(private_key_der),
            public_jwk,
        })
    }

    pub fn public_jwk(&self) -> Jwk {
        self.public_jwk.clone()
    }

    fn sign(&self, claims: &impl Serialize, token_type: &str) -> Result<String, TokenError> {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(token_type.into());
        header.kid = Some(self.kid.clone());
        Ok(jsonwebtoken::encode(&header, claims, &self.encoding_key)?)
    }
}

/// The client grant being represented by an access token.
pub struct AccessTokenRequest<'a> {
    pub client_id: &'a str,
    pub resource: Option<&'a str>,
    pub scopes: &'a [String],
}

pub struct IdTokenRequest<'a> {
    pub audience: &'a str,
    pub nonce: Option<&'a str>,
    pub authenticated_at: DateTime<Utc>,
    /// Whether consent grants disclosure of group membership.
    pub include_groups: bool,
}

#[derive(Clone)]
pub struct TokenIssuer {
    issuer: String,
}

impl TokenIssuer {
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.into(),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn mint_access_token(
        &self,
        key: &SigningKey,
        principal: &Principal<'_>,
        request: AccessTokenRequest<'_>,
        now: DateTime<Utc>,
    ) -> Result<String, TokenError> {
        self.mint_access_token_until(
            key,
            principal,
            request,
            now,
            now + Duration::hours(TOKEN_TTL_HOURS),
        )
    }

    /// Bound a resource token to the lifetime of its upstream authorization.
    pub fn mint_access_token_until(
        &self,
        key: &SigningKey,
        principal: &Principal<'_>,
        request: AccessTokenRequest<'_>,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<String, TokenError> {
        let has_scope = |scope| request.scopes.iter().any(|s| s == scope);
        let userinfo = format!("{}/userinfo", self.issuer);
        let claims = AccessTokenClaims {
            iss: &self.issuer,
            sub: principal.subject,
            aud: request.resource.unwrap_or(&userinfo),
            client_id: request.client_id,
            exp: expires_at
                .min(now + Duration::hours(TOKEN_TTL_HOURS))
                .timestamp(),
            iat: now.timestamp(),
            jti: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(rand::random::<[u8; 18]>()),
            scope: request.scopes.join(" "),
            email: principal.email.filter(|_| has_scope("email")),
            groups: has_scope("groups").then_some(principal.groups),
        };
        key.sign(&claims, "at+jwt")
    }

    pub fn mint_id_token(
        &self,
        key: &SigningKey,
        principal: &Principal<'_>,
        request: IdTokenRequest<'_>,
        now: DateTime<Utc>,
    ) -> Result<String, TokenError> {
        let claims = IdTokenClaims {
            iss: &self.issuer,
            sub: principal.subject,
            aud: request.audience,
            exp: (now + Duration::hours(TOKEN_TTL_HOURS)).timestamp(),
            iat: now.timestamp(),
            auth_time: request.authenticated_at.timestamp(),
            nonce: request.nonce,
            email: principal.email,
            groups: request.include_groups.then_some(principal.groups),
        };
        key.sign(&claims, "JWT")
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<&'a [String]>,
}

#[derive(Serialize)]
struct AccessTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    client_id: &'a str,
    exp: i64,
    iat: i64,
    jti: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<&'a [String]>,
}
