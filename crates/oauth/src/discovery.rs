//! Discovery metadata describing application endpoints and capabilities.
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct OpenidConfiguration {
    pub issuer: String,
    pub client_id_metadata_document_supported: bool,
    pub authorization_response_iss_parameter_supported: bool,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    pub response_modes_supported: Vec<String>,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

impl OpenidConfiguration {
    /// Defaults for the endpoint layout and flows currently served by idElephant.
    /// Applications must adjust the public fields to advertise only capabilities
    /// they implement; this metadata does not install handlers or enable flows.
    pub fn new(issuer: &str) -> Self {
        OpenidConfiguration {
            issuer: issuer.to_string(),
            client_id_metadata_document_supported: true,
            authorization_response_iss_parameter_supported: true,
            authorization_endpoint: format!("{}/authorize", issuer),
            token_endpoint: format!("{}/token", issuer),
            userinfo_endpoint: Some(format!("{}/userinfo", issuer)),
            response_modes_supported: vec!["query".to_string()],
            jwks_uri: format!("{}/jwks.json", issuer),
            response_types_supported: vec!["code".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["ES256".to_string()],
            scopes_supported: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
                "groups".to_string(),
                "offline_access".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "none".to_string(),
                "client_secret_basic".to_string(),
            ],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "auth_time".to_string(),
                "nonce".to_string(),
                "email".to_string(),
                "groups".to_string(),
            ],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            code_challenge_methods_supported: vec!["S256".to_string()],
        }
    }
}
