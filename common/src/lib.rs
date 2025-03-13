use anyhow::{Result, anyhow};
use const_oid::ObjectIdentifier;
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1};
use spki::der::Encode;
use spki::der::asn1::BitString;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use ssh_key::PublicKey;
use ssh_key::public::{EcdsaPublicKey, KeyData};

pub fn convert_key(key: &PublicKey) -> Result<SubjectPublicKeyInfo<ObjectIdentifier, BitString>> {
    Ok(match key.key_data() {
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(key)) => {
            let algorithm = AlgorithmIdentifier {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(SECP_256_R_1),
            };
            let subject_public_key =
                BitString::new(0, key.to_bytes().to_vec()).expect("Could not wrap bytes");
            SubjectPublicKeyInfo {
                algorithm,
                subject_public_key,
            }
        }
        _ => return Err(anyhow!("Unsupported key type")),
    })
}

pub trait ToBoxedSlice {
    fn to_boxed_slice(&self) -> Box<[u8]>;
}

impl ToBoxedSlice for SubjectPublicKeyInfo<ObjectIdentifier, BitString> {
    fn to_boxed_slice(&self) -> Box<[u8]> {
        self.to_der()
            .expect("Failed to encode subject public key into der")
            .into_boxed_slice()
    }
}

#[cfg(test)]
mod tests {
    use crate::{ToBoxedSlice, convert_key};
    use anyhow::Result;
    use hex_literal::hex;
    use ssh_key::PublicKey;

    #[test]
    fn test_convert_key() -> Result<()> {
        let key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMOmfeR5oaRJvme4/uFNitESVwdHwACESMqdTSxxIP+UytIBlUU+37/7qyCKkkRWFlvsRyjSQbfnLRE+UZTlH8Y=";
        let ssh_key = PublicKey::from_openssh(key)?;
        let public_key = convert_key(&ssh_key)?;

        let expected_bytes = hex!(
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004c3a67de479a1a449be67b8fee14d8ad112570747c0008448ca9d4d2c7120ff94cad20195453edfbffbab208a924456165bec4728d241b7e72d113e5194e51fc6"
        );
        assert_eq!(expected_bytes, *public_key.to_boxed_slice(),);
        Ok(())
    }
}
