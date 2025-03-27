use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::{random, rng, RngCore};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use surrealdb::sql::Bytes;

// According to the spec(1) this needs to be at least 16 bytes. We go with 18
// as we will base64 encode the value and lengths not evenly divisible by 3 will
// have padding.
// 1) https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
const CHALLENGE_BYTE_COUNT: usize = 18;

pub fn make_token() -> Vec<u8> {
    random::<[u8; CHALLENGE_BYTE_COUNT]>().into()
}

#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Debug, Clone)]
pub struct Token(Bytes);

impl Token {
    pub fn random() -> Self {
        let mut buf = [0u8; CHALLENGE_BYTE_COUNT];
        rng().fill_bytes(&mut buf);
        Token(Bytes::from(buf.to_vec()))
    }

    pub fn base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.deref())
    }
}

#[cfg(test)]
mod tests {
    use crate::util::Token;

    #[test]
    fn test_make_token() {
        let token = Token::random();
        assert_eq!(24, token.base64().len());
    }
}
