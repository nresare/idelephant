//! Broker policy around the shared authorization-code protocol.
use crate::error::BrokerError;
pub use idp_oauth::protocol::{
    AuthorizationRequest, PendingAuthorizationRequest, valid_verifier, verify_pkce,
};
use idp_oauth::{
    client_metadata::Client,
    protocol::{self, AuthorizationPolicy, ResourceRequirement, ScopePolicy},
};

pub fn allowed_scopes() -> [&'static str; 4] {
    ["openid", "email", "groups", "offline_access"]
}

pub fn validate_authorization_request(
    request: AuthorizationRequest,
    client: &Client,
) -> Result<PendingAuthorizationRequest, BrokerError> {
    Ok(protocol::validate_authorization_request(
        request,
        client,
        AuthorizationPolicy {
            scopes: ScopePolicy::ResourceDefined,
            resource_requirement: ResourceRequirement::Always,
        },
    )?)
}

pub fn validate_pending_client(
    pending: &PendingAuthorizationRequest,
    client: &Client,
) -> Result<(), BrokerError> {
    Ok(protocol::validate_pending_client(pending, client)?)
}

pub fn build_redirect(uri: &str, params: &[(&str, Option<&str>)]) -> Result<String, BrokerError> {
    Ok(protocol::build_redirect(uri, params)?)
}
