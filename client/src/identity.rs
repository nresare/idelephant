use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::{NonZeroScalar, PrimeField};
use p256::{FieldBytes, NistP256, Scalar};
use rand::{random, RngCore};

pub struct TestIdentity {
    credential_id: Box<[u8]>,
    email: String,
    signing_key: SigningKey,
}

impl TestIdentity {
    pub fn new() -> Self {
        TestIdentity {
            email: make_random_email(),
            signing_key: make_random_signing_key(),
            credential_id: Box::new(random::<[u8; 32]>()),
        }
    }

    pub fn get_signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn get_verifying_key(&self) -> &VerifyingKey {
        self.signing_key.as_ref()
    }

    pub fn get_credential_id(&self) -> &[u8] {
        self.credential_id.as_ref()
    }

    pub fn get_email(&self) -> &str {
        self.email.as_str()
    }
}

fn make_random_email() -> String {
    let bytes = rand::random::<[u8; 8]>();
    format!("{}@example.com", STANDARD_NO_PAD.encode(bytes))
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
