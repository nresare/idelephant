use crate::attestation::AttestationObject;
use crate::client_data::ClientData;
use crate::json::ValueWrapper;
use anyhow::anyhow;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::signature::digest::Digest;
use serde_json::{json, Value};
use sha2::Sha256;

pub struct RegisterPublicKeyCredential {
    id: Vec<u8>,
    response: AuthenticatorAttestationResponse,
}

impl RegisterPublicKeyCredential {
    pub fn new(id: &[u8], response: AuthenticatorAttestationResponse) -> Self {
        RegisterPublicKeyCredential {
            id: id.to_vec(),
            response,
        }
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    pub fn response(&self) -> &AuthenticatorAttestationResponse {
        &self.response
    }

    pub fn json(&self) -> Value {
        json!({
            "id": URL_SAFE_NO_PAD.encode(&self.id),
            "rawId": STANDARD_NO_PAD.encode(&self.id),
            "response": self.response.json(),
        })
    }
}

pub struct AuthenticatorAttestationResponse {
    pub public_key: Box<[u8]>,
    pub public_key_algorithm: i32,
    pub attestation: AttestationObject,
    pub client_data: ClientData,
    //pub authenticator_data: Vec<u8>,
}

impl AuthenticatorAttestationResponse {
    pub fn new(
        public_key: Box<[u8]>,
        public_key_algorithm: i32,
        attestation: AttestationObject,
        client_data: ClientData,
    ) -> Self {
        AuthenticatorAttestationResponse {
            public_key,
            public_key_algorithm,
            attestation,
            client_data,
        }
    }

    pub fn json(&self) -> Value {
        let client_data: Vec<u8> = self.client_data().into();

        json!( {
            "publicKey": STANDARD_NO_PAD.encode(&self.public_key),
            "publicKeyAlgorithm": self.public_key_algorithm,
            "attestationObject": STANDARD_NO_PAD.encode(self.attestation.to_cbor()),
            "clientDataJSON": STANDARD_NO_PAD.encode(client_data),
        })
    }

    pub fn client_data(&self) -> &ClientData {
        &self.client_data
    }
}

impl RegisterPublicKeyCredential {
    // This method maps to the steps in
    // https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
    pub fn validate(
        &self,
        challenge: impl AsRef<[u8]>,
        origin: impl AsRef<str>,
        relying_party_id: impl AsRef<str>,
        require_user_verified: bool,
    ) -> anyhow::Result<()> {
        // todo: have a look at extensions
        let client_data = &self.response.client_data;
        if client_data.request_type != "webauthn.create" {
            return Err(anyhow!(
                "type is '{}' is not 'webauthn.create'",
                self.response.client_data.request_type
            ));
        }
        if client_data.challenge != challenge.as_ref() {
            return Err(anyhow!("Challenge mismatch"));
        }
        if client_data.origin != origin.as_ref() {
            return Err(anyhow!("origin mismatch"));
        }
        let origin_sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(relying_party_id.as_ref());
            hasher.finalize()
        };
        let attestation = &self.response.attestation;
        if attestation.auth_data.relying_party_id_hash != origin_sha256.as_slice() {
            return Err(anyhow!("rpID mismatch"));
        }
        if attestation.format != "none" {
            return Err(anyhow!(
                "Don't know how to handle attestation formats other than 'none' yet"
            ));
        }

        if !attestation.attestation_statement.is_empty() {
            return Err(anyhow!(
                "With attestation format 'none', attestation statement should be empty"
            ));
        }

        if !attestation.auth_data.user_present {
            return Err(anyhow!("Invalid registration, 'User Present' flag not set"));
        }

        if require_user_verified && !attestation.auth_data.user_verified {
            return Err(anyhow!("Invalid registration, 'User Present' flag not set"));
        }

        Ok(())
    }
}

// The format of value is whatever gets emitted from response_as_json() in resources/script.js
impl TryFrom<&Value> for RegisterPublicKeyCredential {
    type Error = anyhow::Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        Ok(RegisterPublicKeyCredential {
            id: crate::get_id(value)?,
            response: make_register_response(&value["response"])?,
        })
    }
}

fn make_register_response(
    value: &Value,
) -> Result<AuthenticatorAttestationResponse, anyhow::Error> {
    let vw = ValueWrapper::new(value, "credential.response");

    let client_json = STANDARD_NO_PAD.decode(vw.str("clientDataJSON")?)?;

    let attestation = STANDARD_NO_PAD.decode(vw.str("attestationObject")?)?;

    Ok(AuthenticatorAttestationResponse {
        public_key: STANDARD_NO_PAD
            .decode(vw.str("publicKey")?)?
            .into_boxed_slice(),
        public_key_algorithm: vw.num("publicKeyAlgorithm")?,
        // TODO: uncomment this when we add the attestation validation stuff
        attestation: AttestationObject::from_cbor(attestation.as_slice())?,
        client_data: ClientData::try_from(client_json.as_ref())?,
        //authenticator_data: STANDARD_NO_PAD.decode(vw.str("authenticatorData")?)?,
    })
}

#[cfg(test)]
mod tests {
    use crate::registration::RegisterPublicKeyCredential;
    use serde_json::from_str;

    #[test]
    fn test_validate_register_response() -> anyhow::Result<()> {
        let value = from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/sample_register_response.json",
        )))?;
        let credential = RegisterPublicKeyCredential::try_from(&value)?;
        credential.validate(
            b"hq\xb9\x17)\xe5\xe5\\\xa5\xb4\xfa[\x08(\xb2\x91^\x96",
            "http://localhost:3000",
            "localhost",
            true,
        )?;
        Ok(())
    }
}
