use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use idelephant_webauthn::{
    AttestationObject, AuthenticatorAssertionResponse, AuthenticatorAttestationResponse,
    AuthenticatorData, ClientData, PublicKeyCredentialAuthenticate, RegisterPublicKeyCredential,
};
use log::info;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::{NonZeroScalar, PrimeField};
use p256::pkcs8::der::asn1::BitStringRef;
use p256::pkcs8::der::Encode;
use p256::pkcs8::ObjectIdentifier;
use p256::{FieldBytes, NistP256, Scalar};
use rand::{random, RngCore};
use reqwest::blocking::Client;
use reqwest::blocking::ClientBuilder;
use serde_json::{json, Value};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

const BASE: &str = "http://localhost:3000";

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new("idelephant=info"))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();
    info!("Connecting to {BASE}");

    let client = ClientBuilder::new().cookie_store(true).build()?;
    let identity = TestIdentity::new();

    let user_id = register_public_key(&client, &identity)?;

    authenticate(&client, &identity, user_id)?;
    info!("Successfully authenticated using the newly registered key");
    Ok(())
}

fn authenticate(client: &Client, identity: &TestIdentity, user_id: Vec<u8>) -> Result<()> {
    let challenge = get_auth_challenge(&client.get(format!("{BASE}/auth-start")).send()?.json()?)?;

    let auth_finish_request = make_auth_finish_request(
        challenge,
        user_id,
        identity.get_signing_key(),
        identity.get_credential_id(),
    )
    .json();
    let response = client
        .post(format!("{BASE}/auth-finish"))
        .json(&auth_finish_request)
        .send()?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to authenticate, server returned {}: {}",
            response.status(),
            response.text()?
        ));
    }
    Ok(())
}

fn make_auth_finish_request(
    challenge: Vec<u8>,
    user_id: Vec<u8>,
    key: &SigningKey,
    credential_id: &[u8],
) -> PublicKeyCredentialAuthenticate {
    let auth_data = AuthenticatorData::new("localhost", true, false, 0).to_binary_format();

    let client_data = ClientData::new("webauthn.get", challenge, "http://localhost:3000", false);

    let mut to_sign: Vec<u8> = auth_data.to_vec();
    to_sign.extend_from_slice(client_data.get_hash());

    let signature: Signature = key.sign(to_sign.as_slice());

    let response = AuthenticatorAssertionResponse::new(
        client_data,
        auth_data.to_vec(),
        signature.to_der().to_bytes().to_vec(),
        user_id.clone(),
    );
    PublicKeyCredentialAuthenticate::new(credential_id.to_vec(), response)
}

fn register_public_key(client: &Client, identity: &TestIdentity) -> Result<Vec<u8>> {
    let (challenge, user_id) = get_register_challenge(
        &client
            .post(format!("{BASE}/register-start"))
            .header("Content-Type", "application/json")
            .json(&json!({"email": identity.email}))
            .send()?
            .json()?,
    )?;

    let response = client
        .post(format!("{BASE}/register-finish"))
        .header("Content-Type", "application/json")
        .json(
            &make_register_finish_request(&challenge, BASE, identity, &identity.credential_id)
                .json(),
        )
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
    id: &[u8],
) -> RegisterPublicKeyCredential {
    let client_data = ClientData::new("webauthn.create", challenge.to_vec(), origin, false);
    let authenticator_data = AuthenticatorData::new("localhost", true, false, 0);
    let response = AuthenticatorAttestationResponse::new(
        to_spki_bytes(identity.get_verifying_key()),
        -7,
        AttestationObject::new_none(authenticator_data),
        client_data,
    );
    RegisterPublicKeyCredential::new(id, response)
}

fn to_spki_bytes(verifying_key: &VerifyingKey) -> Vec<u8> {
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

fn get_register_challenge(value: &Value) -> Result<(Vec<u8>, Vec<u8>)> {
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

fn get_auth_challenge(value: &Value) -> Result<Vec<u8>> {
    let challenge = value
        .get("challenge")
        .context("field 'challenge' missing")?
        .as_str()
        .context("field 'challenge' not a string")?;
    let challenge = STANDARD_NO_PAD
        .decode(challenge)
        .context("field 'challenge' not valid base64")?;

    Ok(challenge)
}

struct TestIdentity {
    credential_id: Box<[u8]>,
    email: String,
    signing_key: SigningKey,
}

impl TestIdentity {
    fn new() -> Self {
        TestIdentity {
            email: make_random_email(),
            signing_key: make_random_signing_key(),
            credential_id: Box::new(random::<[u8; 32]>()),
        }
    }

    fn get_signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn get_verifying_key(&self) -> &VerifyingKey {
        self.signing_key.as_ref()
    }

    fn get_credential_id(&self) -> &[u8] {
        self.credential_id.as_ref()
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
    use crate::{get_auth_challenge, make_random_signing_key, to_spki_bytes};
    use anyhow::Context;
    use hex_literal::hex;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use serde_json::json;
    use spki::SubjectPublicKeyInfoOwned;

    #[test]
    fn test_get_challenge() {
        let value = json!({});
        let result = get_auth_challenge(&value);
        assert_eq!("field 'challenge' missing", result.unwrap_err().to_string());

        let value = json!({"challenge": 42});
        let result = get_auth_challenge(&value);
        assert_eq!(
            "field 'challenge' not a string",
            result.unwrap_err().to_string()
        );

        let value = json!({"challenge": "!@£$%^"});
        let result = get_auth_challenge(&value);
        assert_eq!(
            "field 'challenge' not valid base64",
            result.unwrap_err().to_string()
        );

        let value = json!({"challenge": "!@£$%^"});
        let result = get_auth_challenge(&value);
        assert_eq!(
            "field 'challenge' not valid base64",
            result.unwrap_err().to_string()
        );

        let value = json!({"challenge": "c2F1c2FnZQ"});
        let result = get_auth_challenge(&value);
        assert_eq!(b"sausage", result.unwrap().as_slice());
    }

    #[test]
    fn test_sign_and_verify() -> anyhow::Result<()> {
        use p256::ecdsa::{signature::Signer, Signature};

        // Signing
        let signing_key = make_random_signing_key(); // Serialize with `::to_bytes()`
        let message =
            b"ECDSA proves knowledge of a secret number in the context of a single message";
        let signature: Signature = signing_key.sign(message);

        let key_bytes = to_spki_bytes(signing_key.as_ref());
        let signature_bytes = signature.to_der().to_bytes();

        let verifying_key = verifying_key_from_bytes(&key_bytes)?;

        verify(&key_bytes, &signature_bytes, &message[..])?;

        verifying_key.verify(message, &Signature::from_der(&signature_bytes)?)?;

        Ok(())
    }

    #[test]
    fn attempt_to_verify_using_only_bytes() -> anyhow::Result<()> {
        let key = hex!("3059301306072a8648ce3d020106082a8648ce3d03010703420004f70029a1fc78476843811038d8ebcf537cf70b289b9a2ccd5c63020e5621a6909a0a5593658fc897cb7399f9a195a9313a9123b4fb3bf0172fefd86d843144c9");
        let signature = hex!("3045022100847d7c0512a732023c2592de60137cea6f31850dffb0c90e11d3e7c6be46d3cf02202ed227d267485424fcdb2138024760de429a239d50344008534e65bc16309912");
        let data = hex!("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000000dc6d0e076dcc150085603c7ecd54bf596c5c9dd0b2d29d8f4fdf3fe0234d01c5");
        verify(&key, &signature, &data)?;
        Ok(())
    }

    fn verify(key: &[u8], signature: &[u8], data: &[u8]) -> anyhow::Result<()> {
        let key = verifying_key_from_bytes(key).context("Could not parse verifying key")?;
        let signature = Signature::from_der(signature).context("could not parse signature")?;
        Ok(key.verify(&data, &signature)?)
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> anyhow::Result<VerifyingKey> {
        let key = SubjectPublicKeyInfoOwned::try_from(bytes)
            .context("Could not parse public key data as SPKI")?;
        Ok(
            VerifyingKey::from_sec1_bytes(key.subject_public_key.as_bytes().unwrap())
                .context("Could not parse verifying key")?,
        )
    }
}
