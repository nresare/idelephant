use crate::credential::Credential;
use anyhow::{anyhow, Context};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use idelephant_webauthn::{
    AuthenticatorAssertionResponse, AuthenticatorData, ClientData, PublicKeyCredentialAuthenticate,
};
use reqwest::blocking::Client;
use serde_json::Value;

use crate::BASE;
pub fn authenticate(
    client: &Client,
    credential: &mut dyn Credential,
    user_id: Vec<u8>,
) -> anyhow::Result<()> {
    let challenge = get_auth_challenge(&client.get(format!("{BASE}/auth-start")).send()?.json()?)?;

    let auth_finish_request = make_auth_finish_request(challenge, user_id, credential).json();
    let response = client
        .post(format!("{BASE}/auth-finish"))
        .json(&auth_finish_request)
        .send()?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to authenticate, server returned {}: {}",
            response.status(),
            response.text()?
        ));
    }
    Ok(())
}

fn make_auth_finish_request(
    challenge: Vec<u8>,
    user_id: Vec<u8>,
    credential: &mut dyn Credential,
) -> PublicKeyCredentialAuthenticate {
    let auth_data = AuthenticatorData::new("localhost", true, false, 0).to_binary_format();

    let client_data = ClientData::new("webauthn.get", challenge, "http://localhost:3000", false);

    let mut to_sign: Vec<u8> = auth_data.to_vec();
    to_sign.extend_from_slice(client_data.get_hash());

    let response = AuthenticatorAssertionResponse::new(
        client_data,
        auth_data.to_vec(),
        credential.sign(to_sign.as_slice()).to_vec(),
        user_id.clone(),
    );
    PublicKeyCredentialAuthenticate::new(credential.id().to_vec(), response)
}

pub fn get_auth_challenge(value: &Value) -> anyhow::Result<Vec<u8>> {
    let challenge = value
        .get("challenge")
        .context("field 'challenge' missing")?
        .as_str()
        .context("field 'challenge' not a string")?;
    let challenge = STANDARD_NO_PAD
        .decode(challenge)
        .context("field 'challenge' not valid base64")?;

    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use crate::auth::get_auth_challenge;
    use serde_json::json;

    #[test]
    fn test_get_challenge() {
        let value = json!({});
        let result = get_auth_challenge(&value);
        assert_eq!("field 'challenge' missing", result.unwrap_err().to_string());

        let value = json!({"challenge": 42});
        let result = get_auth_challenge(&value);
        assert_eq!(
            "field 'challenge' not a string",
            result.unwrap_err().to_string()
        );

        let value = json!({"challenge": "!@£$%^"});
        let result = get_auth_challenge(&value);
        assert_eq!(
            "field 'challenge' not valid base64",
            result.unwrap_err().to_string()
        );

        let value = json!({"challenge": "!@£$%^"});
        let result = get_auth_challenge(&value);
        assert_eq!(
            "field 'challenge' not valid base64",
            result.unwrap_err().to_string()
        );

        let value = json!({"challenge": "c2F1c2FnZQ"});
        let result = get_auth_challenge(&value);
        assert_eq!(b"sausage", result.unwrap().as_slice());
    }
}
