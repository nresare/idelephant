use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::{NonZeroScalar, PrimeField};
use p256::pkcs8::der::asn1::BitStringRef;
use p256::pkcs8::ObjectIdentifier;
use p256::{FieldBytes, NistP256, Scalar};
use rand::RngCore;
use sha2::{Digest, Sha256};
use spki::der::Encode;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

pub struct Credential {
    id: Box<[u8]>,
    key: SigningKey,
}

impl Credential {
    pub fn new() -> Self {
        let key = make_random_signing_key();
        let id = Sha256::digest(key.to_bytes()).to_vec().into_boxed_slice();
        Credential { key, id }
    }

    pub fn sign(&self, message: &[u8]) -> Box<[u8]> {
        let signature: Signature = self.key.sign(message);
        signature.to_der().to_bytes()
    }

    pub fn get_public_key_bytes(&self) -> Box<[u8]> {
        to_spki_bytes(self.key.as_ref())
    }

    pub fn id(&self) -> &[u8] {
        self.id.as_ref()
    }
}

pub fn to_spki_bytes(verifying_key: &VerifyingKey) -> Box<[u8]> {
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
    spki.to_der().unwrap().into_boxed_slice()
}

// Slightly adapted from https://github.com/RustCrypto/traits/blob/master/elliptic-curve/src/scalar/nonzero.rs#L50
// copied here to deal with incompatibility between rand versions
pub fn make_random_signing_key() -> SigningKey {
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
