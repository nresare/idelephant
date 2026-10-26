//! OAuth authorization-code request validation, S256 PKCE, and redirects.
use crate::client_metadata::Client;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationRequest {
    #[serde(default)]
    pub resource: Option<String>,
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingAuthorizationRequest {
    #[serde(default)]
    pub resource: Option<String>,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
}

/// Application policy for the same authorization-code protocol.
pub struct AuthorizationPolicy<'a> {
    pub scopes: ScopePolicy<'a>,
    pub resource_requirement: ResourceRequirement,
}

/// Static authorization servers can enumerate scopes; brokers validate resource
/// permissions against their upstream grant after sign-in.
pub enum ScopePolicy<'a> {
    Supported(&'a [&'a str]),
    ResourceDefined,
}

/// RFC 6749 scope-token syntax (space separates tokens).
pub fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

#[derive(Clone, Copy)]
pub enum ResourceRequirement {
    Always,
    MetadataClients,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("{0}")]
    BadRequest(String),
    #[error("OAuth error: {0}")]
    OAuth(&'static str),
}

pub fn validate_authorization_request(
    request: AuthorizationRequest,
    client: &Client,
    policy: AuthorizationPolicy<'_>,
) -> Result<PendingAuthorizationRequest, ProtocolError> {
    if request.client_id != client.client_id {
        return Err(ProtocolError::OAuth("invalid_client"));
    }
    if request.response_type != "code" {
        return Err(ProtocolError::BadRequest(
            "Only response_type=code is supported".to_string(),
        ));
    }
    if !client.allows_redirect(&request.redirect_uri) {
        return Err(ProtocolError::BadRequest(
            "redirect_uri is not registered for this client".to_string(),
        ));
    }
    if let Some(resource) = request.resource.as_deref() {
        validate_resource(resource)?;
    }
    if request.resource.is_none()
        && (client.cimd || matches!(policy.resource_requirement, ResourceRequirement::Always))
    {
        return Err(ProtocolError::OAuth("invalid_target"));
    }
    let scope = if request.scope.is_empty() && request.resource.is_some() {
        "email"
    } else {
        &request.scope
    };
    let scopes = parse_scopes(scope)?;
    for scope in &scopes {
        if !valid_scope(scope)
            || matches!(&policy.scopes, ScopePolicy::Supported(allowed) if !allowed.contains(&scope.as_str()))
        {
            return Err(ProtocolError::BadRequest(format!(
                "scope '{scope}' is not supported"
            )));
        }
    }
    let code_challenge = request
        .code_challenge
        .ok_or_else(|| ProtocolError::BadRequest("code_challenge is required".to_string()))?;
    let code_challenge_method = request.code_challenge_method.ok_or_else(|| {
        ProtocolError::BadRequest("code_challenge_method is required".to_string())
    })?;
    if code_challenge_method != "S256" {
        return Err(ProtocolError::BadRequest(
            "Only PKCE code_challenge_method=S256 is supported".to_string(),
        ));
    }
    if code_challenge.len() != 43
        || !code_challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ProtocolError::BadRequest(
            "code_challenge must be a base64url-encoded S256 digest".to_string(),
        ));
    }

    Ok(PendingAuthorizationRequest {
        client_id: client.client_id.clone(),
        resource: request.resource,
        redirect_uri: request.redirect_uri,
        scopes,
        state: request.state,
        nonce: request.nonce,
        code_challenge,
    })
}

fn validate_resource(resource: &str) -> Result<(), ProtocolError> {
    let url = Url::parse(resource).map_err(|_| ProtocolError::OAuth("invalid_target"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.fragment().is_some()
        || url.query().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ProtocolError::OAuth("invalid_target"));
    }
    Ok(())
}

pub fn validate_pending_client(
    pending: &PendingAuthorizationRequest,
    client: &Client,
) -> Result<(), ProtocolError> {
    if client.client_id != pending.client_id || !client.allows_redirect(&pending.redirect_uri) {
        return Err(ProtocolError::OAuth("invalid_request"));
    }
    Ok(())
}

fn parse_scopes(scope: &str) -> Result<Vec<String>, ProtocolError> {
    let scopes: Vec<String> = scope
        .split(' ')
        .filter(|scope| !scope.is_empty())
        .map(ToString::to_string)
        .collect();
    if scopes.is_empty() {
        return Err(ProtocolError::BadRequest(
            "scope must not be empty".to_string(),
        ));
    }
    Ok(scopes)
}

/// RFC 7636 syntax for a public client's code verifier.
pub fn valid_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

pub fn verify_pkce(code_verifier: &str, expected_challenge: &str) -> bool {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    use subtle::ConstantTimeEq;
    bool::from(
        Sha256::digest(challenge.as_bytes()).ct_eq(&Sha256::digest(expected_challenge.as_bytes())),
    )
}

pub fn build_redirect(
    redirect_uri: &str,
    params: &[(&str, Option<&str>)],
) -> Result<String, ProtocolError> {
    let mut redirect = Url::parse(redirect_uri)
        .map_err(|e| ProtocolError::BadRequest(format!("Invalid redirect URI: {e}")))?;
    {
        let mut pairs = redirect.query_pairs_mut();
        for (key, value) in params {
            if let Some(value) = value {
                pairs.append_pair(key, value);
            }
        }
    }
    Ok(redirect.to_string())
}
