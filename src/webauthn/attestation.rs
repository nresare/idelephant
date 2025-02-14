use crate::error::IdentityError;
use anyhow::{anyhow, Context};
use ciborium::Value;
use std::collections::HashMap;

#[derive(Debug)]
pub struct AttestationObject {
    pub(crate) format: String,
    pub attestation_statement: HashMap<String, String>,
    pub auth_data: AuthenticatorData,
}

#[derive(Debug)]
pub struct AuthenticatorData {
    pub relaying_party_id_hash: Vec<u8>,
    pub user_present: bool,
    pub user_verified: bool,
    pub sign_count: u32,
    // todo: deal with the COSE encoded keys. For now we are relying on the SubjectPublicKeyInfo
    // formatted public key as described in https://www.w3.org/TR/webauthn-2/#sctn-public-key-easy
    // attested_credential_data: Option<Vec<u8>>,
}

impl TryFrom<&[u8]> for AttestationObject {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let value: Value = ciborium::from_reader(bytes)
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
}

trait Invalid<T> {
    fn invalid(self, detail: &'static str) -> Result<T, IdentityError>;
}

impl<T, E> Invalid<T> for Result<T, E>
where
    E: Into<anyhow::Error>,
{
    fn invalid(self, detail: &'static str) -> Result<T, IdentityError> {
        match self {
            Ok(value) => Ok(value),
            Err(err) => {
                let detail = detail.to_string();
                Err(IdentityError::InvalidInput {
                    detail,
                    source: Some(err.into()),
                })
            }
        }
    }
}

impl<T> Invalid<T> for Option<T> {
    fn invalid(self, detail: &'static str) -> Result<T, IdentityError> {
        match self {
            Some(value) => Ok(value),
            None => {
                let detail = detail.to_string();
                Err(IdentityError::InvalidInput {
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
        if bytes.len() < MIN_SIZE {
            return Err(anyhow!(
                "Invalid AuthenticatorData length, < {MIN_SIZE} bytes"
            ));
        }
        let relaying_party_id_hash = bytes[..32].to_vec();
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes(
            bytes[33..37]
                .try_into()
                .context("Invalid AuthenticatorData sign_count value")?,
        );
        let user_present = flags & 1 != 0;
        let user_verified = flags & 1 << 2 != 0;
        Ok(AuthenticatorData {
            relaying_party_id_hash,
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
    use crate::error::IdentityError;
    use crate::webauthn::attestation::AttestationObject;
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
        let decoded = AttestationObject::try_from(attestation.as_slice())?;

        assert_eq!(decoded.format, "none");
        assert_eq!(0, decoded.attestation_statement.len());
        let origin_sha256 = {
            let mut hasher = Sha256::new();
            hasher.update("localhost");
            hasher.finalize()
        };
        assert_eq!(
            origin_sha256.as_slice(),
            decoded.auth_data.relaying_party_id_hash
        );
        assert_eq!(0, decoded.auth_data.sign_count);
        assert!(decoded.auth_data.user_present);
        assert!(decoded.auth_data.user_verified);

        Ok(())
    }

    #[test]
    fn test_invalid_input() -> anyhow::Result<()> {
        let result = AttestationObject::try_from(b"foobar".as_slice());
        let result = result.unwrap_err();
        let result = result.downcast_ref::<IdentityError>().unwrap();
        assert!(matches!(result, IdentityError::InvalidInput { .. }));
        Ok(())
    }
}
