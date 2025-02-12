use crate::json::ValueWrapper;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::str;

pub struct ClientData {
    pub request_type: String,
    pub challenge: Vec<u8>,
    pub origin: String,
    // I don't know the use case for cross_origin. If you need it, please let me know your
    // use-case, and I'll re-introduce it and add some relevant test cases.
    #[cfg(test)]
    pub cross_origin: bool,
    hash: Vec<u8>,
}

impl ClientData {
    pub(crate) fn get_sha256(&self) -> &[u8] {
        &self.hash
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Vec::from(hasher.finalize().as_slice())
}

impl TryFrom<&[u8]> for ClientData {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let hash = sha256(value);
        let value: Value = serde_json::from_str(from_utf8(value)?)?;
        let vw = ValueWrapper::new(&value, "credential.response.clientDataJSON");
        Ok(ClientData {
            request_type: vw.str("type")?.to_string(),
            challenge: URL_SAFE_NO_PAD.decode(vw.str("challenge")?)?,
            origin: vw.str("origin")?.to_string(),
            // remove this when we have an actual use case for this
            #[cfg(test)]
            cross_origin: vw.bool("crossOrigin")?,
            hash,
        })
    }
}

// according to https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
// step 5 we need to ensure that we skip the BOM at the beginning of input if present
fn from_utf8(mut slice: &[u8]) -> Result<&str, anyhow::Error> {
    if &slice[..3] == b"\xef\xbb\xbf" {
        slice = &slice[3..]
    }
    Ok(str::from_utf8(slice)?)
}

#[cfg(test)]
mod tests {
    use super::from_utf8;

    #[test]
    fn test_from_utf8() -> anyhow::Result<()> {
        assert_eq!(from_utf8(b"\xef\xbb\xbfhorse")?, "horse");
        assert_eq!(from_utf8(b"stable")?, "stable");
        Ok(())
    }
}
