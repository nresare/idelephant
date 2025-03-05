use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::{NonZeroScalar, PrimeField};
use p256::{FieldBytes, NistP256, Scalar};
use rand::{random, RngCore};
use reqwest::blocking::ClientBuilder;
use reqwest::blocking::Client;
use idelephant_webauthn::{AttestationObject, AuthenticatorAttestationResponse, AuthenticatorData, ClientData, PublicKeyCredentialAuthenticate, RegisterPublicKeyCredential};
use serde_json::{json, Value};

const BASE: &str = "http://localhost:3000";

fn main() -> Result<()> {
    let client = ClientBuilder::new().cookie_store(true).build()?;
    let identity = TestIdentity::new();

    register_public_key(&client, identity.email.as_str())?;

    authenticate(&client, identity.get_signing_key())?;
    Ok(())
}

fn authenticate(client: &Client, signing_key: &SigningKey) -> Result<()> {
    let challenge = get_challenge(&client
        .get(format!("{BASE}/auth-start"))
        .send()?.json()?)?;

    let auth_finish_request = make_auth_finish_request(challenge, signing_key);

    Ok(())
}

fn make_auth_finish_request(challenge: Vec<u8>, key: &SigningKey) -> PublicKeyCredentialAuthenticate {
    PublicKeyCredentialAuthenticate::new(challenge,)
}

fn register_public_key(client: &Client, email: &str) -> Result<()> {


    let challenge = get_challenge(
        &client
            .post(format!("{BASE}/register-start"))
            .header("Content-Type", "application/json")
            .json(&json!({"email": email}))
            .send()?
            .json()?
    )?;

    let identity = TestIdentity::new();
    let identity_id = random::<[u8; 32]>();

    let response = client
        .post(format!("{BASE}/register-finish"))
        .header("Content-Type", "application/json")
        .json(&(&make_register_finish_request(&challenge, BASE, &identity, &identity_id)).json())
        .send()?;

    if !response.status().is_success() {
        return Err(anyhow!("Failed to register public key, server returned {}: {}", response.status(), response.text()?))
    }
    Ok(())
}

fn make_register_finish_request(
    challenge: &[u8],
    origin: &str,
    identity: &TestIdentity,
    id: &[u8]
) -> RegisterPublicKeyCredential {
    let client_data = ClientData::new("webauthn.create", challenge.to_vec(), origin, false);
    let authenticator_data = AuthenticatorData::new("localhost", true, false, 0);

    let response = AuthenticatorAttestationResponse::new(
        identity.get_verifying_key().to_sec1_bytes().to_vec(),
        -7,
        AttestationObject::new_none(authenticator_data),
        client_data,
    );
    RegisterPublicKeyCredential::new(id.as_ref(), response)
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
