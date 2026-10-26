//! Authentication of idFrog itself at the upstream token endpoint.
use crate::{config::AuthenticationConfig, state::random_token, upstream::OidcClient};
use anyhow::{Context, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openidconnect::ClientSecret;
use rustls::{
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    sign::CertifiedKey,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_cert::{Certificate, der::Decode};

pub(crate) trait ClientAuthentication: Send + Sync {
    fn configure_client(&self, client: OidcClient) -> OidcClient;
    fn token_parameters(
        &self,
        client_id: &str,
        token_endpoint: &str,
    ) -> anyhow::Result<Vec<(&'static str, String)>>;
}

pub(crate) fn load_authentication(
    config: &AuthenticationConfig,
) -> anyhow::Result<Box<dyn ClientAuthentication>> {
    match config {
        AuthenticationConfig::ClientSecretPost { client_secret_file } => {
            let secret = std::fs::read_to_string(client_secret_file)
                .context("Could not read upstream client secret file")?;
            let secret = secret.trim_end_matches(['\r', '\n']).to_string();
            ensure!(
                !secret.is_empty(),
                "The upstream client secret file is empty"
            );
            Ok(Box::new(SecretPost { secret }))
        }
        AuthenticationConfig::PrivateKeyJwt {
            certificate_file,
            private_key_file,
        } => {
            let certificate = std::fs::read(certificate_file)
                .context("Could not read upstream certificate_file")?;
            let private_key = std::fs::read(private_key_file)
                .context("Could not read upstream private_key_file")?;
            Ok(Box::new(CertificateAssertion::from_pem(
                &certificate,
                &private_key,
            )?))
        }
    }
}

struct SecretPost {
    secret: String,
}
impl ClientAuthentication for SecretPost {
    fn configure_client(&self, client: OidcClient) -> OidcClient {
        client.set_client_secret(ClientSecret::new(self.secret.clone()))
    }
    fn token_parameters(
        &self,
        _client_id: &str,
        _token_endpoint: &str,
    ) -> anyhow::Result<Vec<(&'static str, String)>> {
        Ok(Vec::new())
    }
}

struct CertificateAssertion {
    key: EncodingKey,
    thumbprint: String,
    not_before: i64,
    not_after: i64,
}

impl CertificateAssertion {
    fn from_pem(certificate: &[u8], private_key: &[u8]) -> anyhow::Result<Self> {
        let certificates = CertificateDer::pem_slice_iter(certificate)
            .collect::<Result<Vec<_>, _>>()
            .context("Invalid upstream certificate PEM")?;
        let leaf = certificates
            .first()
            .context("certificate_file contains no X.509 certificate")?;
        let parsed =
            Certificate::from_der(leaf.as_ref()).context("Invalid upstream X.509 certificate")?;
        let validity = parsed.tbs_certificate.validity;
        let credential = Self {
            key: EncodingKey::from_rsa_pem(private_key)
                .context("private_key_jwt requires an RSA PEM private key")?,
            thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(leaf.as_ref())),
            not_before: validity
                .not_before
                .to_unix_duration()
                .as_secs()
                .try_into()?,
            not_after: validity.not_after.to_unix_duration().as_secs().try_into()?,
        };
        let key_der = PrivateKeyDer::from_pem_slice(private_key)
            .context("Invalid upstream private key PEM")?;
        let certified = CertifiedKey::from_der(certificates, key_der, &ring::default_provider())
            .context("Upstream certificate and private key do not form a usable key pair")?;
        certified
            .keys_match()
            .context("Upstream certificate does not match its private key")?;
        credential.check_validity(Utc::now().timestamp())?;
        Ok(credential)
    }

    fn check_validity(&self, now: i64) -> anyhow::Result<()> {
        ensure!(
            now >= self.not_before,
            "Upstream client certificate is not yet valid"
        );
        ensure!(
            now < self.not_after,
            "Upstream client certificate has expired"
        );
        Ok(())
    }

    fn assertion(&self, client_id: &str, token_endpoint: &str) -> anyhow::Result<String> {
        let now = Utc::now().timestamp();
        self.check_validity(now)?;
        let claims = AssertionClaims {
            iss: client_id,
            sub: client_id,
            aud: token_endpoint,
            iat: now,
            nbf: now,
            exp: (now + 300).min(self.not_after),
            jti: random_token(),
        };
        let mut header = Header::new(Algorithm::PS256);
        header.x5t_s256 = Some(self.thumbprint.clone());
        Ok(jsonwebtoken::encode(&header, &claims, &self.key)?)
    }
}

impl ClientAuthentication for CertificateAssertion {
    fn configure_client(&self, client: OidcClient) -> OidcClient {
        client
    }
    fn token_parameters(
        &self,
        client_id: &str,
        token_endpoint: &str,
    ) -> anyhow::Result<Vec<(&'static str, String)>> {
        Ok(vec![
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            ),
            (
                "client_assertion",
                self.assertion(client_id, token_endpoint)?,
            ),
        ])
    }
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
    use serde_json::Value;
    const CERTIFICATE: &[u8] = include_bytes!("../tests/fixtures/test-only-client-cert.pem");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/test-only-client-key.pem");

    #[test]
    fn assertion_is_ps256_bound_to_client_endpoint_and_certificate_with_fresh_jti() {
        let auth = CertificateAssertion::from_pem(CERTIFICATE, KEY).unwrap();
        let endpoint = "https://login.microsoftonline.com/tenant/oauth2/v2.0/token";
        let assertion = auth.assertion("app-client-id", endpoint).unwrap();
        let header = decode_header(&assertion).unwrap();
        assert_eq!(header.alg, Algorithm::PS256);
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        let der = CertificateDer::from_pem_slice(CERTIFICATE).unwrap();
        assert_eq!(
            header.x5t_s256,
            Some(URL_SAFE_NO_PAD.encode(Sha256::digest(der.as_ref())))
        );
        let key = DecodingKey::from_rsa_pem(CERTIFICATE).unwrap();
        let mut validation = Validation::new(Algorithm::PS256);
        validation.set_issuer(&["app-client-id"]);
        validation.set_audience(&[endpoint]);
        validation.sub = Some("app-client-id".into());
        validation.validate_nbf = true;
        let claims = decode::<Value>(&assertion, &key, &validation)
            .unwrap()
            .claims;
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            300
        );
        assert_eq!(claims["nbf"], claims["iat"]);
        let other = auth.assertion("app-client-id", endpoint).unwrap();
        let other = decode::<Value>(&other, &key, &validation).unwrap().claims;
        assert_ne!(claims["jti"], other["jti"]);
        validation.set_audience(&["https://other.example/token"]);
        assert!(decode::<Value>(&assertion, &key, &validation).is_err());
    }

    #[test]
    fn certificate_validity_is_checked_at_load_and_at_assertion_issuance() {
        let mut auth = CertificateAssertion::from_pem(CERTIFICATE, KEY).unwrap();
        assert!(auth.check_validity(auth.not_before - 1).is_err());
        assert!(auth.check_validity(auth.not_before).is_ok());
        assert!(auth.check_validity(auth.not_after).is_err());
        auth.not_after = Utc::now().timestamp() - 1;
        assert!(
            auth.assertion("client", "https://provider.example/token")
                .is_err()
        );
    }

    #[test]
    fn malformed_or_mismatched_credentials_are_rejected() {
        assert!(CertificateAssertion::from_pem(b"invalid certificate", KEY).is_err());
        assert!(CertificateAssertion::from_pem(CERTIFICATE, b"invalid key").is_err());
        use rsa::pkcs8::EncodePrivateKey as _;
        let other = rsa::RsaPrivateKey::new(&mut rand_legacy::rngs::OsRng, 2048).unwrap();
        let other = other.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        assert!(CertificateAssertion::from_pem(CERTIFICATE, other.as_bytes()).is_err());
    }
}
