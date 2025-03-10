extern crate core;

mod attestation;
mod client_data;
mod json;
mod registration;

pub use self::attestation::AttestationObject;
pub use self::attestation::AuthenticatorData;
pub use self::client_data::ClientData;
pub use self::registration::AuthenticatorAttestationResponse;
pub use self::registration::RegisterPublicKeyCredential;

use crate::json::ValueWrapper;
use anyhow::{anyhow, Context};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::{json, Value};
use spki::SubjectPublicKeyInfoRef;
use thiserror::Error;

#[derive(Error, Debug)]
enum WebauthnError {
    #[error("Attempting to parse data with an invalid format: {detail}")]
    InvalidInput {
        detail: String,
        source: Option<anyhow::Error>,
    },
}

pub struct PublicKeyCredentialAuthenticate {
    pub id: Vec<u8>,
    pub response: AuthenticatorAssertionResponse,
}

impl PublicKeyCredentialAuthenticate {
    pub fn new(id: Vec<u8>, response: AuthenticatorAssertionResponse) -> Self {
        PublicKeyCredentialAuthenticate { id, response }
    }

    pub fn verify(&self, public_key: &[u8], challenge: &[u8]) -> Result<(), anyhow::Error> {
        let mut to_verify = self.response.authenticator_data.clone();
        to_verify.extend_from_slice(self.response.client_data.get_hash());

        if self.response.client_data.challenge != challenge {
            return Err(anyhow!("challenge mismatch"));
        }

        let key = SubjectPublicKeyInfoRef::try_from(public_key)
            .context("Could not parse public key data as SPKI")?;
        let verifying_key =
            VerifyingKey::from_sec1_bytes(key.subject_public_key.as_bytes().unwrap())
                .context("Could not parse verifying key")?;
        let signature = Signature::from_der(self.response.signature.as_slice())
            .context("could not parse signature")?;

        verifying_key
            .verify(to_verify.as_slice(), &signature)
            .context("Signature verification failed")?;
        Ok(())
    }

    pub fn from_json(value: &Value) -> Result<Self, anyhow::Error> {
        Ok(PublicKeyCredentialAuthenticate {
            id: get_id(value)?,
            response: make_auth_response(&value["response"])?,
        })
    }

    pub fn json(&self) -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode(&self.id),
            "rawId": STANDARD_NO_PAD.encode(&self.id),
            "response": self.response.json(),
        })
    }
}

fn get_id(value: &Value) -> Result<Vec<u8>, anyhow::Error> {
    let vw = ValueWrapper::new(value, "credential");
    let id = vw.str("id")?;
    let id = URL_SAFE_NO_PAD.decode(id).context("Failed to parse id")?;
    let raw_id = STANDARD_NO_PAD.decode(vw.str("rawId")?)?;

    if raw_id != id {
        return Err(anyhow!("rawId {raw_id:?} and id {id:?} doesn't match"));
    }
    Ok(id)
}

pub struct AuthenticatorAssertionResponse {
    pub client_data: ClientData,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}
impl AuthenticatorAssertionResponse {
    pub fn new(
        client_data: ClientData,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Vec<u8>,
    ) -> Self {
        AuthenticatorAssertionResponse {
            client_data,
            authenticator_data,
            signature,
            user_handle,
        }
    }

    pub fn json(&self) -> Value {
        json!({
            "clientDataJSON": STANDARD_NO_PAD.encode::<Vec<u8>>((&self.client_data).into()),
            "authenticatorData": STANDARD_NO_PAD.encode(&self.authenticator_data),
            "signature": STANDARD_NO_PAD.encode(&self.signature),
            "userHandle": STANDARD_NO_PAD.encode(&self.user_handle),
        })
    }
}

fn make_auth_response(value: &Value) -> Result<AuthenticatorAssertionResponse, anyhow::Error> {
    let vw = ValueWrapper::new(value, "credential.response");
    let client_json = &STANDARD_NO_PAD.decode(vw.str("clientDataJSON")?)?;
    let client_data = ClientData::try_from(client_json.as_slice())?;

    Ok(AuthenticatorAssertionResponse {
        client_data,
        authenticator_data: STANDARD_NO_PAD.decode(vw.str("authenticatorData")?)?,
        signature: STANDARD_NO_PAD.decode(vw.str("signature")?)?,
        user_handle: STANDARD_NO_PAD.decode(vw.str("userHandle")?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::PublicKeyCredentialAuthenticate;
    use crate::registration::RegisterPublicKeyCredential;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::Engine;
    use serde_json::{from_str, Value};

    #[test]
    fn test_parse_register_response() -> anyhow::Result<()> {
        let register_response = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/sample_register_response.json",
        ));
        let value: Value = from_str(register_response)?;

        let credential = RegisterPublicKeyCredential::try_from(&value)?;
        assert_eq!(
            credential.id(),
            b"\xc67\xb5L\xf1b\x1fO\xf2QF\xe2\xa3\xe8?\xd7"
        );
        let response = credential.response();
        assert_eq!(response.public_key_algorithm, -7);

        let client_data = response.client_data();
        assert_eq!(client_data.request_type, "webauthn.create");
        assert_eq!(client_data.origin, "http://localhost:3000");
        assert!(!client_data.cross_origin);
        assert_eq!(
            client_data.challenge,
            b"hq\xb9\x17)\xe5\xe5\\\xa5\xb4\xfa[\x08(\xb2\x91^\x96"
        );

        Ok(())
    }

    #[test]
    fn test_parse_auth_response() -> anyhow::Result<()> {
        let auth_response = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/sample_auth_response.json",
        ));
        let value: Value = from_str(auth_response)?;

        let credential = PublicKeyCredentialAuthenticate::from_json(&value)?;
        assert_eq!(
            credential.id,
            b"^\xfeJ\xb7\xcc\xb2 \xca\xa8t\x1aNhQ\xcb\xdf"
        );
        let response = credential.response;

        let client_data = response.client_data;
        assert_eq!(client_data.request_type, "webauthn.get");
        assert_eq!(client_data.origin, "http://localhost:3000");
        assert!(!client_data.cross_origin);
        assert_eq!(
            client_data.challenge,
            b"D\x98\xb7\xb1\xd0F\xab\x10/\xc0Z2\xc5\x98\xed\xb6\x0bt"
        );

        Ok(())
    }

    #[test]
    fn test_verify_signature() -> anyhow::Result<()> {
        let register_response = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/sample_auth_response.json",
        ));
        let value: Value = from_str(register_response)?;
        let credential = PublicKeyCredentialAuthenticate::from_json(&value)?;

        let kb = get_key_bytes();
        credential.verify(
            &kb,
            b"D\x98\xb7\xb1\xd0F\xab\x10/\xc0Z2\xc5\x98\xed\xb6\x0bt",
        )?;

        Ok(())
    }

    const PUBLIC_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5TCLgR4qUc/utY0COS7N81QsdMU7xNDNe3VZ1wqUoIcdJ1USCoqU0IRBFHSsKs2c6wPY8GQu5LMQffzmUNQfow";

    fn get_key_bytes() -> Vec<u8> {
        STANDARD_NO_PAD
            .decode(PUBLIC_KEY)
            .expect("could not decode public key")
    }
}
