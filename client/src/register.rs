use crate::identity::TestIdentity;
use crate::BASE;
use anyhow::{anyhow, Context};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use idelephant_webauthn::{
    AttestationObject, AuthenticatorAttestationResponse, AuthenticatorData, ClientData,
    RegisterPublicKeyCredential,
};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::der::asn1::BitStringRef;
use p256::pkcs8::der::Encode;
use p256::pkcs8::ObjectIdentifier;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

pub fn register_public_key(client: &Client, identity: &TestIdentity) -> anyhow::Result<Vec<u8>> {
    let (challenge, user_id) = get_register_challenge(
        &client
            .post(format!("{BASE}/register-start"))
            .header("Content-Type", "application/json")
            .json(&json!({"email": identity.get_email()}))
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
    identity: &TestIdentity,
) -> RegisterPublicKeyCredential {
    let client_data = ClientData::new("webauthn.create", challenge.to_vec(), origin, false);
    let authenticator_data = AuthenticatorData::new("localhost", true, false, 0);
    let response = AuthenticatorAttestationResponse::new(
        to_spki_bytes(identity.get_verifying_key()),
        -7,
        AttestationObject::new_none(authenticator_data),
        client_data,
    );
    RegisterPublicKeyCredential::new(identity.get_credential_id(), response)
}

pub fn to_spki_bytes(verifying_key: &VerifyingKey) -> Vec<u8> {
    let key_bytes = verifying_key.to_sec1_bytes();
    let spki: SubjectPublicKeyInfo<ObjectIdentifier, BitStringRef> = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            oid: "1.2.840.10045.2.1"
                .parse::<ObjectIdentifier>()
                .expect("Could not parse oid"),
            parameters: Some(
                "1.2.840.10045.3.1.7"
                    .parse::<ObjectIdentifier>()
                    .expect("Could not parse params"),
            ),
        },
        subject_public_key: BitStringRef::from_bytes(&key_bytes).expect("invalid BitString"),
    };
    spki.to_der().unwrap()
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
