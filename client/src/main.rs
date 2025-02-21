use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::{NonZeroScalar, PrimeField};
use p256::{FieldBytes, NistP256, Scalar};
use rand::rngs::OsRng;
use rand::{RngCore, TryRngCore};
use reqwest::blocking::ClientBuilder;

use idelephant_webauthn::{AttestationObject, AuthenticatorAttestationResponse, ClientData, RegisterPublicKeyCredential};
use serde_json::Value;

const BASE: &str = "http://localhost:3000";

fn main() -> Result<()> {
    let client = ClientBuilder::new().cookie_store(true).build()?;

    let challenge = get_challenge(
        &client
            .get(format!("{BASE}/register-start"))
            .send()?
            .json::<Value>()
            .context("Could not parse response as json")?,
    )?;

    let identity = TestIdentity::new();

    let value: Value = make_register_finish_request(&challenge, BASE, &identity).into();
    let response = &client
        .get(format!("{BASE}/register-finish"))
        .json(&value)
        .send()?
        .json::<Value>()?;

    Ok(())
}

fn make_register_finish_request(
    challenge: &Vec<u8>,
    origin: &str,
    identity: &TestIdentity,
) -> RegisterPublicKeyCredential {

    let client_data = ClientData::new("webauthn.request", challenge.clone(), origin, false);
    let response = AuthenticatorAttestationResponse::new(
        identity.get_verifying_key().to_sec1_bytes().to_vec(),
        -7,
        AttestationObject{}
        client_data
    );
    let id = rand::random::<[u8; 32]>().as_ref();
    RegisterPublicKeyCredential::new(id, response)
}

fn get_challenge(value: &Value) -> Result<Vec<u8>> {
    let challenge = value
        .get("challenge")
        .context("field 'challenge' missing")?
        .as_str()
        .context("field 'challenge' not a string")?;
    STANDARD_NO_PAD
        .decode(challenge)
        .context("field 'challenge' not valid base64")
}

struct TestIdentity {
    email: String,
    signing_key: SigningKey,
}

impl TestIdentity {
    fn new() -> Self {
        let rng = OsRng.unwrap_err();
        let mut rng = rand::rng();
        TestIdentity {
            email: make_random_email(),
            signing_key: make_random_signing_key(),
        }
    }

    fn get_signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn get_verifying_key(&self) -> &VerifyingKey {
        self.signing_key.as_ref()
    }
}

fn make_random_email() -> String {
    let bytes = rand::random::<[u8; 8]>();
    format!("{}@example.com", STANDARD_NO_PAD.encode(bytes))
}

// Slightly adapted from https://github.com/RustCrypto/traits/blob/master/elliptic-curve/src/scalar/nonzero.rs#L50
// copied here to deal with incompatibility between rand versions
fn make_random_signing_key() -> SigningKey {
    let mut rng = rand::rng();
    let mut bytes = FieldBytes::default();

    loop {
        rng.fill_bytes(&mut bytes);
        if let Some(scalar) = Scalar::from_repr(bytes).into() {
            if let Some(nz) = NonZeroScalar::<NistP256>::new(scalar).into_option() {
                return nz.into();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::get_challenge;
    use serde_json::json;

    #[test]
    fn test_get_challenge() {
        let value = json!({});
        let result = get_challenge(&value);
        assert_eq!("field 'challenge' missing", result.unwrap_err().to_string());

        let value = json!({"challenge": 42});
        let result = get_challenge(&value);
        assert_eq!(
            "field 'challenge' not a string",
            result.unwrap_err().to_string()
        );

        let value = json!({"challenge": "!@£$%^"});
        let result = get_challenge(&value);
        assert_eq!(
            "field 'challenge' not valid base64",
            result.unwrap_err().to_string()
        );

        let value = json!({"challenge": "!@£$%^"});
        let result = get_challenge(&value);
        assert_eq!(
            "field 'challenge' not valid base64",
            result.unwrap_err().to_string()
        );

        let value = json!({"challenge": "c2F1c2FnZQ"});
        let result = get_challenge(&value);
        assert_eq!(b"sausage", result.unwrap().as_slice());
    }
}
