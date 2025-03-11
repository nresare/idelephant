mod auth;
mod credential;
mod register;

use crate::credential::Credential;
use auth::authenticate;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use log::info;
use rand::random;
use reqwest::blocking::ClientBuilder;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

pub(crate) const BASE: &str = "http://localhost:3000";
fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new("idelephant=info"))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();
    info!("Connecting to {BASE}");

    let client = ClientBuilder::new().cookie_store(true).build()?;

    let credential = Credential::new();
    let email = make_random_email();

    let user_id = register::register_public_key(&client, &credential, &email)?;

    authenticate(&client, &credential, user_id)?;
    info!("Successfully authenticated using the newly registered key");
    Ok(())
}

fn make_random_email() -> String {
    let bytes: [u8; 8] = random();
    format!("{}@example.com", STANDARD_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use crate::credential::make_random_signing_key;
    use crate::credential::to_spki_bytes;
    use anyhow::Context;
    use hex_literal::hex;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use spki::SubjectPublicKeyInfoOwned;

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
        Ok(key.verify(data, &signature)?)
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> anyhow::Result<VerifyingKey> {
        let key = SubjectPublicKeyInfoOwned::try_from(bytes)
            .context("Could not parse public key data as SPKI")?;
        VerifyingKey::from_sec1_bytes(key.subject_public_key.as_bytes().unwrap())
            .context("Could not parse verifying key")
    }
}
