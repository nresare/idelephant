use crate::credential::Credential;
use crate::BASE;
use anyhow::{anyhow, Context};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use idelephant_webauthn::{
    AttestationObject, AuthenticatorAttestationResponse, AuthenticatorData, ClientData,
    RegisterPublicKeyCredential,
};
use reqwest::blocking::Client;
use serde_json::{json, Value};

pub fn register_public_key(
    client: &Client,
    identity: &Credential,
    email: &str,
) -> anyhow::Result<Vec<u8>> {
    let (challenge, user_id) = get_register_challenge(
        &client
            .post(format!("{BASE}/register-start"))
            .header("Content-Type", "application/json")
            .json(&json!({"email": email}))
            .send()?
            .json()?,
    )?;

    let response = client
        .post(format!("{BASE}/register-finish"))
        .header("Content-Type", "application/json")
        .json(&make_register_finish_request(&challenge, BASE, identity).json())
        .send()?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to register public key, server returned {}: {}",
            response.status(),
            response.text()?
        ));
    }
    Ok(user_id)
}

fn make_register_finish_request(
    challenge: &[u8],
    origin: &str,
    credential: &Credential,
) -> RegisterPublicKeyCredential {
    let client_data = ClientData::new("webauthn.create", challenge.to_vec(), origin, false);
    let authenticator_data = AuthenticatorData::new("localhost", true, false, 0);
    let response = AuthenticatorAttestationResponse::new(
        credential.get_public_key_bytes(),
        -7,
        AttestationObject::new_none(authenticator_data),
        client_data,
    );
    RegisterPublicKeyCredential::new(credential.id(), response)
}

fn get_register_challenge(value: &Value) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let challenge = value
        .get("challenge")
        .context("field 'challenge' missing")?
        .as_str()
        .context("field 'challenge' not a string")?;
    let challenge = STANDARD_NO_PAD
        .decode(challenge)
        .context("field 'challenge' not valid base64")?;

    let user_id = value
        .get("user_id")
        .context("field 'user_id' missing")?
        .as_str()
        .context("field 'user_id' not a string")?;
    let user_id = STANDARD_NO_PAD
        .decode(user_id)
        .context("field 'user_id' not valid base64")?;
    Ok((challenge, user_id))
}
