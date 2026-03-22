use crate::error::IdentityError;
use crate::AppState;
use anyhow::{anyhow, Context};
use axum::extract::FromRef;
use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::EncodePrivateKey;
use serde::Serialize;
use std::ops::Deref;

#[derive(Clone)]
pub struct OidcService {
    issuer: String,
    encoding_key: EncodingKey,
    kid: String,
    jwks: JwksResponse,
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

impl OidcService {
    pub fn new(issuer: &str) -> Result<Self, anyhow::Error> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let der = signing_key
            .to_pkcs8_der()
            .context("Could not encode OIDC signing key to PKCS8")?;
        let encoding_key = EncodingKey::from_ec_der(der.as_bytes());
        let kid = crate::util::Token::random().base64();
        let jwk = build_jwk(&verifying_key, &kid);

        Ok(Self {
            issuer: issuer.to_string(),
            encoding_key,
            kid,
            jwks: JwksResponse { keys: vec![jwk] },
        })
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

    pub fn jwks(&self) -> JwksResponse {
        self.jwks.clone()
    }

    pub fn mint_id_token(
        &self,
        subject: &str,
        audience: &str,
        nonce: Option<&str>,
        email: &str,
    ) -> Result<String, IdentityError> {
        let now = Utc::now().timestamp();
        let claims = IdTokenClaims {
            iss: &self.issuer,
            sub: subject,
            aud: audience,
            exp: now + 3600,
            iat: now,
            auth_time: now,
            nonce,
            email,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, &claims, &self.encoding_key).map_err(|e| anyhow!(e).into())
    }
}

impl FromRef<AppState> for OidcService {
    fn from_ref(input: &AppState) -> Self {
        input.oidc.deref().clone()
    }
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

#[cfg(test)]
mod tests {
    use super::OidcService;

    #[test]
    fn mint_id_token_produces_jwt() {
        let oidc = OidcService::new("http://localhost:8080").unwrap();
        let token = oidc
            .mint_id_token(
                "identity:alice",
                "client-1",
                Some("nonce-123"),
                "alice@example.com",
            )
            .unwrap();
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn configuration_uses_issuer() {
        let oidc = OidcService::new("http://localhost:8080").unwrap();
        let configuration = oidc.configuration();
        assert_eq!(
            configuration.authorization_endpoint,
            "http://localhost:8080/authorize"
        );
        assert_eq!(configuration.jwks_uri, "http://localhost:8080/jwks.json");
    }
}
