mod client_data;

use self::client_data::ClientData;
use crate::json::ValueWrapper;
use anyhow::{anyhow, Context};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value;
use spki::SubjectPublicKeyInfoRef;
// The naming in the spec is a bit confusing here, as the type of the return value
// of both credential creation and authentication are called PublicKeyCredential but
// is holding different subclasses of AuthenticatorResponse in their respective response
// field. To simplify things I have named them PublicKeyCredentialRegister for the one
// used for key creation and registration and PublicKeyCredentialAuthenticate for the variant
// holding an AuthenticatorAssertionResponse, used for user authentication.

pub struct PublicKeyCredentialRegister {
    pub id: Vec<u8>,
    pub response: AuthenticatorAttestationResponse,
}

pub struct PublicKeyCredentialAuthenticate {
    pub id: Vec<u8>,
    pub response: AuthenticatorAssertionResponse,
}

pub struct AuthenticatorAttestationResponse {
    pub public_key: Vec<u8>,
    pub public_key_algorithm: i32,
    //pub attestation: Vec<u8>,
    pub client_data: ClientData,
    //pub authenticator_data: Vec<u8>,
}

pub struct AuthenticatorAssertionResponse {
    pub client_data: ClientData,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

impl PublicKeyCredentialRegister {
    // This method maps to the steps in
    // https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
    pub fn validate(&self, challenge: Vec<u8>, origin: impl AsRef<str>) -> anyhow::Result<()> {
        // todo: have a look at extensions
        if self.response.client_data.request_type != "webauthn.create" {
            return Err(anyhow!(
                "type is '{}' is not 'webauthn.create'",
                self.response.client_data.request_type
            ));
        }
        if self.response.client_data.challenge != challenge {
            return Err(anyhow!("Challenge mismatch"));
        }
        if self.response.client_data.origin != origin.as_ref() {
            return Err(anyhow!("origin mismatch"));
        }
        Ok(())
    }
}

// The format of value is whatever gets emitted from response_as_json() in resources/script.js
impl TryFrom<&Value> for PublicKeyCredentialRegister {
    type Error = anyhow::Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        Ok(PublicKeyCredentialRegister {
            id: get_id(value)?,
            response: make_register_response(&value["response"])?,
        })
    }
}

impl TryFrom<&Value> for PublicKeyCredentialAuthenticate {
    type Error = anyhow::Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        Ok(PublicKeyCredentialAuthenticate {
            id: get_id(value)?,
            response: make_auth_response(&value["response"])?,
        })
    }
}

impl PublicKeyCredentialAuthenticate {
    pub fn verify(&self, public_key: &[u8], challenge: &[u8]) -> Result<(), anyhow::Error> {
        let mut to_verify = self.response.authenticator_data.clone();
        to_verify.extend_from_slice(self.response.client_data.get_sha256());

        if self.response.client_data.challenge != challenge {
            return Err(anyhow!("challenge mismatch"));
        }

        let key = SubjectPublicKeyInfoRef::try_from(public_key)?;
        let verifying_key =
            VerifyingKey::from_sec1_bytes(key.subject_public_key.as_bytes().unwrap())?;
        let signature = Signature::from_der(self.response.signature.as_slice())?;
        verifying_key.verify(&to_verify, &signature)?;
        Ok(())
    }
}

fn get_id(value: &Value) -> Result<Vec<u8>, anyhow::Error> {
    let vw = ValueWrapper::new(value, "credential");
    let id = URL_SAFE_NO_PAD
        .decode(vw.str("id")?)
        .context("Failed to parse id")?;
    let raw_id = STANDARD_NO_PAD.decode(vw.str("rawId")?)?;

    if raw_id != id {
        return Err(anyhow!("rawId {raw_id:?} and id {id:?} doesn't match"));
    }
    Ok(id)
}

fn make_register_response(
    value: &Value,
) -> Result<AuthenticatorAttestationResponse, anyhow::Error> {
    let vw = ValueWrapper::new(value, "credential.response");

    let client_json = STANDARD_NO_PAD.decode(vw.str("clientDataJSON")?)?;

    Ok(AuthenticatorAttestationResponse {
        public_key: STANDARD_NO_PAD.decode(vw.str("publicKey")?)?,
        public_key_algorithm: vw.num("publicKeyAlgorithm")?,
        // TODO: uncomment this when we add the attestation validation stuff
        //attestation: STANDARD_NO_PAD.decode(vw.str("attestationObject")?)?,
        client_data: ClientData::try_from(client_json.as_ref())?,
        //authenticator_data: STANDARD_NO_PAD.decode(vw.str("authenticatorData")?)?,
    })
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
    use super::{PublicKeyCredentialAuthenticate, PublicKeyCredentialRegister};
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

        let credential = PublicKeyCredentialRegister::try_from(&value)?;
        assert_eq!(
            credential.id,
            b"\xc67\xb5L\xf1b\x1fO\xf2QF\xe2\xa3\xe8?\xd7"
        );
        let response = credential.response;
        assert_eq!(response.public_key_algorithm, -7);

        let client_data = response.client_data;
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
    fn test_validate_register_response() -> anyhow::Result<()> {
        let value = from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/sample_register_response.json",
        )))?;
        let credential = PublicKeyCredentialRegister::try_from(&value)?;
        credential.validate(
            Vec::from(b"hq\xb9\x17)\xe5\xe5\\\xa5\xb4\xfa[\x08(\xb2\x91^\x96"),
            "http://localhost:3000".to_string(),
        )?;
        Ok(())
    }

    #[test]
    fn test_parse_auth_response() -> anyhow::Result<()> {
        let auth_response = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/sample_auth_response.json",
        ));
        let value: Value = from_str(auth_response)?;

        let credential = PublicKeyCredentialAuthenticate::try_from(&value)?;
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
        let credential = PublicKeyCredentialAuthenticate::try_from(&value)?;

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
