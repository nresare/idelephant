use anyhow::{anyhow, Result};
use p256::ecdsa::signature::{SignatureEncoding, Signer};
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::{NonZeroScalar, PrimeField};
use p256::pkcs8::der::asn1::BitStringRef;
use p256::pkcs8::ObjectIdentifier;
use p256::{FieldBytes, NistP256, Scalar};
use rand::RngCore;
use sha2::{Digest, Sha256};
use spki::der::Encode;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use ssh_agent_client_rs::Client;
use ssh_key::public::{EcdsaPublicKey, KeyData};
use ssh_key::Fingerprint;
use std::env;
use std::path::Path;

pub trait Credential {
    fn sign(&mut self, message: &[u8]) -> Box<[u8]>;
    fn get_public_key_bytes(&self) -> Box<[u8]>;

    fn id(&self) -> &[u8];
}

pub struct P256Random {
    id: Box<[u8]>,
    key: SigningKey,
}

impl P256Random {
    pub fn new() -> Self {
        let key = make_random_signing_key();
        let id = Sha256::digest(key.to_bytes()).to_vec().into_boxed_slice();
        Self { key, id }
    }
}

impl Credential for P256Random {
    fn sign(&mut self, message: &[u8]) -> Box<[u8]> {
        let signature: Signature = self.key.sign(message);
        signature.to_der().to_bytes()
    }

    fn get_public_key_bytes(&self) -> Box<[u8]> {
        to_spki_bytes(&self.key.as_ref().to_sec1_bytes())
    }

    fn id(&self) -> &[u8] {
        self.id.as_ref()
    }
}

pub struct SshAgentBackedCredential {
    client: Client,
    key: ssh_key::PublicKey,
    fingerprint: Fingerprint,
}

impl SshAgentBackedCredential {
    pub fn new() -> Result<Self> {
        let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
        let mut client = Client::connect(Path::new(path.as_str()))?;
        let mut keys = client.list_identities()?.into_iter();
        let key = keys.next().ok_or_else(|| {
            anyhow!("For now we only handle the case when the ssh-agent provides one key")
        })?;
        let fingerprint = key.fingerprint(Default::default());

        Ok(Self {
            client,
            key,
            fingerprint,
        })
    }
}

impl Credential for SshAgentBackedCredential {
    fn sign(&mut self, message: &[u8]) -> Box<[u8]> {
        let signature = self
            .client
            .sign(&self.key, message)
            .expect("signature failed");
        let signature =
            p256::ecdsa::Signature::try_from(signature).expect("Signature conversion failed");
        signature.to_der().to_vec().into_boxed_slice()
    }

    fn get_public_key_bytes(&self) -> Box<[u8]> {
        let KeyData::Ecdsa(EcdsaPublicKey::NistP256(key)) = self.key.key_data() else {
            todo!("For now we don't handle any other keys but P256")
        };
        to_spki_bytes(&key.to_bytes())
    }

    fn id(&self) -> &[u8] {
        self.fingerprint.as_ref()
    }
}

fn to_spki_bytes(p256_key_bytes: &[u8]) -> Box<[u8]> {
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
        subject_public_key: BitStringRef::from_bytes(p256_key_bytes).expect("invalid BitString"),
    };
    spki.to_der().unwrap().into_boxed_slice()
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
    use crate::credential::{
        make_random_signing_key, to_spki_bytes, Credential, SshAgentBackedCredential,
    };
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

        let key_bytes = to_spki_bytes(&signing_key.as_ref().to_sec1_bytes());
        let signature_bytes = signature.to_der().to_bytes();

        let verifying_key = verifying_key_from_bytes(&key_bytes)?;

        verify(&key_bytes, &signature_bytes, &message[..])?;

        verifying_key.verify(message, &Signature::from_der(&signature_bytes)?)?;

        Ok(())
    }

    #[ignore] // not self-contained as it reaches out to the ssh-agent
    #[test]
    fn test_ssh_agent_backed_credential() -> anyhow::Result<()> {
        let credential = &mut SshAgentBackedCredential::new()?;
        assert_eq!(
            hex!("a64fbd604bf458a534ab0d21f6596b62fde9e9c3baef47fc68edb326f6f3f7f9"),
            credential.id()
        );
        let key = credential.get_public_key_bytes();
        assert_eq!(hex!("3059301306072a8648ce3d020106082a8648ce3d03010703420004c3a67de479a1a449be67b8fee14d8ad112570747c0008448ca9d4d2c7120ff94cad20195453edfbffbab208a924456165bec4728d241b7e72d113e5194e51fc6"), *key);
        let message = b"just a message to be signed";

        let signature = credential.sign(message);

        verify(&key, &signature, message)?;

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
