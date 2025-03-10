use crate::WebauthnError;
use anyhow::{anyhow, Context};
use ciborium::{cbor, into_writer, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub struct AttestationObject {
    pub(crate) format: String,
    pub attestation_statement: HashMap<String, String>,
    pub auth_data: AuthenticatorData,
}

impl AttestationObject {
    pub fn new_none(auth_data: AuthenticatorData) -> Self {
        AttestationObject {
            format: "none".to_string(),
            attestation_statement: HashMap::new(),
            auth_data,
        }
    }

    pub fn from_cbor(data: &[u8]) -> Result<Self, anyhow::Error> {
        let value: Value = ciborium::from_reader(data)
            .invalid("Could not parse AttestationObject, wrong CBOR format")?;
        let m = to_map(&value)
            .invalid("AttestationObject data could not be read as Map<String, Value>")?;

        let format = m
            .get("fmt")
            .invalid("AttestationObject is missing 'fmt' value")?;
        let format = format
            .as_text()
            .invalid("Failed to parse AttestationObject")?
            .to_string();

        let auth_data = m
            .get("authData")
            .invalid("AttestationObject is missing 'authData' value")?;
        let auth_data = auth_data
            .as_bytes()
            .invalid("authData field not bytes")?
            .as_slice();
        let auth_data = AuthenticatorData::try_from(auth_data)?;

        Ok(AttestationObject {
            format,
            attestation_statement: HashMap::new(),
            auth_data,
        })
    }

    pub fn to_cbor(&self) -> Box<[u8]> {
        // todo figure out how this can go wrong
        let value = cbor!({
            "fmt" => "none",
            "authData" => Value::Bytes(self.auth_data.to_binary_format().to_vec()),
            "attStmt" => {},
        })
        .expect("Failed to build cbor Value");
        let mut buf = Vec::new();
        into_writer(&value, &mut buf).expect("failed to serialize to buffer");
        buf.into_boxed_slice()
    }
}

#[derive(Debug, PartialEq)]
pub struct AuthenticatorData {
    pub relying_party_id_hash: Vec<u8>,
    pub user_present: bool,
    pub user_verified: bool,
    pub sign_count: u32,
    // todo: deal with the COSE encoded keys. For now we are relying on the SubjectPublicKeyInfo
    // formatted public key as described in https://www.w3.org/TR/webauthn-2/#sctn-public-key-easy
    // attested_credential_data: Option<Vec<u8>>,
}

impl AuthenticatorData {
    pub fn new(
        relying_party_id: &str,
        user_present: bool,
        user_verified: bool,
        sign_count: u32,
    ) -> Self {
        AuthenticatorData {
            relying_party_id_hash: Sha256::digest(relying_party_id).to_vec(),
            user_present,
            user_verified,
            sign_count,
        }
    }

    pub fn to_binary_format(&self) -> Box<[u8]> {
        let mut result = Vec::with_capacity(MIN_SIZE);
        result.extend_from_slice(self.relying_party_id_hash.as_slice());

        let mut flags = 0u8;
        if self.user_present {
            flags |= 1;
        }
        if self.user_verified {
            flags |= 1 << 2;
        }
        // todo: for now we always have the Attested Credential Data present, and never the extensions
        flags |= 1 << 6;
        result.push(flags);
        result.extend(self.sign_count.to_be_bytes());
        Box::from(result)
    }
}

const AUTH_DATA_MIN_SIZE: usize = 32 + 1 + 4;
trait Invalid<T> {
    fn invalid(self, detail: &'static str) -> Result<T, WebauthnError>;
}

impl<T, E> Invalid<T> for Result<T, E>
where
    E: Into<anyhow::Error>,
{
    fn invalid(self, detail: &'static str) -> Result<T, WebauthnError> {
        match self {
            Ok(value) => Ok(value),
            Err(err) => {
                let detail = detail.to_string();
                Err(WebauthnError::InvalidInput {
                    detail,
                    source: Some(err.into()),
                })
            }
        }
    }
}

impl<T> Invalid<T> for Option<T> {
    fn invalid(self, detail: &'static str) -> Result<T, WebauthnError> {
        match self {
            Some(value) => Ok(value),
            None => {
                let detail = detail.to_string();
                Err(WebauthnError::InvalidInput {
                    detail,
                    source: None,
                })
            }
        }
    }
}

const MIN_SIZE: usize = 32 + 1 + 4;

impl TryFrom<&[u8]> for AuthenticatorData {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < AUTH_DATA_MIN_SIZE {
            return Err(anyhow!(
                "Invalid AuthenticatorData length, < {AUTH_DATA_MIN_SIZE} bytes"
            ));
        }
        let relying_party_id_hash = bytes[..32].to_vec();
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes(
            bytes[33..37]
                .try_into()
                .context("Invalid AuthenticatorData sign_count value")?,
        );
        let user_present = flags & 1 != 0;
        let user_verified = flags & (1 << 2) != 0;
        Ok(AuthenticatorData {
            relying_party_id_hash,
            user_present,
            user_verified,
            sign_count,
        })
    }
}

fn to_map(value: &Value) -> Result<HashMap<&str, &Value>, anyhow::Error> {
    value
        .as_map()
        .context("unexpected CBOR data")?
        .iter()
        .map(|(k, v)| Ok((k.as_text().context("map key is not text")?, v)))
        .collect::<Result<HashMap<&str, &Value>, anyhow::Error>>()
}

#[cfg(test)]
mod tests {
    use crate::attestation::{AttestationObject, AuthenticatorData};
    use crate::WebauthnError;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    const ATTESTATION: &str = "
    o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAA
    LraVWanqkAfvZZFYZpVEg0AEMqdPQDfR6geoNBBph67G0+lAQIDJiABIVggMOIltT+Kgfk6PjrsMJqOR2aZpsEj/c
    hMMCcdln/Z/Y0iWCAljT8BmxWVU+SEQYVIEFhx8EBKT66q57vVw3SXln8Ozw";

    #[test]
    fn test_attestation() -> anyhow::Result<()> {
        let attestation = ATTESTATION
            .bytes()
            .filter(|b| !b" \n".contains(b))
            .collect::<Vec<_>>();
        let attestation = STANDARD_NO_PAD.decode(attestation)?;
        let decoded = AttestationObject::from_cbor(attestation.as_slice())?;

        assert_eq!(decoded.format, "none");
        assert_eq!(0, decoded.attestation_statement.len());
        assert_eq!(
            Sha256::digest("localhost").as_slice(),
            decoded.auth_data.relying_party_id_hash
        );
        assert_eq!(0, decoded.auth_data.sign_count);
        assert!(decoded.auth_data.user_present);
        assert!(decoded.auth_data.user_verified);

        Ok(())
    }

    #[test]
    fn test_invalid_input() -> anyhow::Result<()> {
        let result = AttestationObject::from_cbor(b"foobar".as_slice());
        let result = result.unwrap_err();
        let result = result.downcast_ref::<WebauthnError>().unwrap();
        assert!(matches!(result, WebauthnError::InvalidInput { .. }));
        Ok(())
    }

    #[test]
    fn test_authenticator_data_roundtrip() -> anyhow::Result<()> {
        let ad = &AuthenticatorData::new("localhost", true, true, 0);
        assert_eq!(
            ad,
            &AuthenticatorData::try_from(ad.to_binary_format().as_ref())?
        );

        let ad = &AuthenticatorData::new("sausage.com", false, false, 4247);
        assert_eq!(
            ad,
            &AuthenticatorData::try_from(ad.to_binary_format().as_ref())?
        );

        Ok(())
    }

    #[test]
    fn test_attestation_object_roundtrip() -> anyhow::Result<()> {
        let ad = AuthenticatorData::new("localhost", true, true, 0);

        let attestation = AttestationObject::new_none(ad);

        let cbor = attestation.to_cbor();

        assert_eq!(attestation, AttestationObject::from_cbor(cbor.as_ref())?);
        Ok(())
    }
}
