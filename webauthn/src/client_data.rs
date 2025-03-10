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
    pub cross_origin: bool,
    hash: Vec<u8>,
}

impl ClientData {
    pub fn get_hash(&self) -> &[u8] {
        self.hash.as_slice()
    }

    /// Construct a new ClientData object with a hash value that matches the output of
    /// the conversion into Vec<u8>
    pub fn new(
        request_type: impl ToString,
        challenge: Vec<u8>,
        origin: impl ToString,
        cross_origin: bool,
    ) -> Self {
        let value = make_value(
            &request_type.to_string(),
            &challenge,
            &origin.to_string(),
            cross_origin,
        );
        let bytes = serde_json::to_vec(&value).expect("our own json could not be serialized");
        ClientData {
            request_type: request_type.to_string(),
            challenge,
            origin: origin.to_string(),
            cross_origin,
            hash: Sha256::digest(bytes.as_slice()).to_vec(),
        }
    }
}

fn make_value(request_type: &str, challenge: &[u8], origin: &str, cross_origin: bool) -> Value {
    let mut top = serde_json::Map::new();
    top.insert("type".to_string(), request_type.into());
    top.insert(
        "challenge".to_string(),
        URL_SAFE_NO_PAD.encode(challenge).into(),
    );
    top.insert("origin".to_string(), origin.into());
    top.insert("crossOrigin".to_string(), cross_origin.into());
    Value::Object(top)
}

impl From<&ClientData> for Vec<u8> {
    fn from(client_data: &ClientData) -> Vec<u8> {
        let value = make_value(
            client_data.request_type.as_str(),
            &client_data.challenge,
            client_data.origin.as_str(),
            client_data.cross_origin,
        );
        serde_json::to_vec(&value).expect("our own json could not be serialized")
    }
}

impl TryFrom<&[u8]> for ClientData {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let hash = Sha256::digest(value).to_vec();
        let value: Value = serde_json::from_str(from_utf8(value)?)?;
        let vw = ValueWrapper::new(&value, "credential.response.clientDataJSON");
        Ok(ClientData {
            request_type: vw.str("type")?.to_string(),
            challenge: URL_SAFE_NO_PAD.decode(vw.str("challenge")?)?,
            origin: vw.str("origin")?.to_string(),
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
    use super::{from_utf8, ClientData};
    use hex_literal::hex;

    #[test]
    fn test_from_utf8() -> anyhow::Result<()> {
        assert_eq!(from_utf8(b"\xef\xbb\xbfhorse")?, "horse");
        assert_eq!(from_utf8(b"stable")?, "stable");
        Ok(())
    }

    const CHALLENGE: &[u8] = &hex!("6871b91729e5e55ca5b4fa5b0828b2915e96");

    #[test]
    fn test_hash() -> anyhow::Result<()> {
        let client_data = ClientData::new(
            "authn.create",
            CHALLENGE.into(),
            "http://localhost:3000",
            false,
        );
        assert_eq!(
            hex!("85c000d7213de409e3c413ad59ad539601c9f911f84d039d6e740f89d6a696a9"),
            client_data.get_hash(),
        );
        Ok(())
    }

    #[test]
    fn test_json_input_gives_correct_hash() -> anyhow::Result<()> {
        // this input is functionally the same as the data from above
        const CLIENT_DATA: &[u8] = b"{\"type\":\"webauthn.create\",\"challenge\":\"aHG5Fynl5VyltPpbCCiykV6W\",\"origin\":\"http://localhost:3000\",\"crossOrigin\":false}";
        let client_data = ClientData::try_from(CLIENT_DATA)?;
        assert_eq!(client_data.challenge, CHALLENGE);
        assert_eq!(
            hex!("b1251b47a98ef5d2f247fcf39794e8f7752559e872f8525a439399a698fe1649"),
            client_data.get_hash(),
        );
        Ok(())
    }
}
