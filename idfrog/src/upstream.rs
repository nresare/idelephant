//! idFrog's upstream OIDC relying-party implementation.
use crate::{
    client_auth::{ClientAuthentication, load_authentication},
    config::{Config, Resource, UpstreamConfig, validate_endpoint},
    error::BrokerError,
    state::{secrets_equal, token_hash},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use openidconnect::{
    AccessTokenHash, AuthType, AuthorizationCode, ClaimsVerificationError, ClientId, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, RequestTokenError, Scope,
    SignatureVerificationError, StandardErrorResponse, TokenResponse,
    core::{
        CoreAuthenticationFlow, CoreClient, CoreErrorResponseType, CoreIdTokenVerifier,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreTokenResponse,
    },
    reqwest,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration as StdDuration};

pub(crate) type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub struct Upstream {
    config: UpstreamConfig,
    authentication: Box<dyn ClientAuthentication>,
    redirect_uri: RedirectUrl,
    http: reqwest::Client,
    metadata: CoreProviderMetadata,
    resources: Vec<Resource>,
}

#[derive(Serialize, Deserialize)]
pub struct LoginChallenge {
    pub nonce: String,
    pub verifier: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpstreamIdentity {
    pub subject: String,
    pub upstream_subject: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub api_scopes: Vec<String>,
    pub authenticated_at: DateTime<Utc>,
    pub permission_expires_at: DateTime<Utc>,
    pub refresh_token: Option<String>,
    pub login_nonce: String,
}

impl Upstream {
    pub async fn discover(config: &Config) -> anyhow::Result<Self> {
        let authentication = load_authentication(&config.upstream.authentication)?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(StdDuration::from_secs(15))
            .build()?;
        let metadata = Self::discover_metadata(&http, &config.upstream.issuer)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Upstream OIDC discovery failed; check the issuer and network connectivity"
                )
            })?;
        Ok(Self {
            config: config.upstream.clone(),
            authentication,
            redirect_uri: RedirectUrl::new(format!("{}/oidc/callback", config.origin))?,
            http,
            metadata,
            resources: config.resources.clone(),
        })
    }

    async fn discover_metadata(
        http: &reqwest::Client,
        issuer: &str,
    ) -> Result<CoreProviderMetadata, BrokerError> {
        let issuer = IssuerUrl::new(issuer.into())
            .map_err(|_| upstream_failure("invalid_discovery_issuer"))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, http)
            .await
            .map_err(|error| {
                use openidconnect::DiscoveryError;
                let (reason, status) = match error {
                    DiscoveryError::Request(_) => ("discovery_transport_error", None),
                    DiscoveryError::Response(status, _, _) => {
                        ("discovery_http_error", Some(status.as_u16()))
                    }
                    DiscoveryError::Parse(_) => ("malformed_discovery_or_jwks_response", None),
                    DiscoveryError::Validation(_) => ("discovery_metadata_validation_failed", None),
                    DiscoveryError::UrlParse(_) => ("invalid_discovery_url", None),
                    _ => ("unexpected_discovery_response", None),
                };
                tracing::warn!(
                    stage = "oidc_discovery",
                    reason,
                    status,
                    "Upstream discovery failed"
                );
                BrokerError::Upstream
            })?;
        validate_endpoint(metadata.authorization_endpoint().as_str())
            .map_err(|_| upstream_failure("unsafe_authorization_endpoint"))?;
        validate_endpoint(metadata.jwks_uri().as_str())
            .map_err(|_| upstream_failure("unsafe_jwks_endpoint"))?;
        validate_endpoint(
            metadata
                .token_endpoint()
                .ok_or_else(|| upstream_failure("missing_token_endpoint"))?
                .as_str(),
        )
        .map_err(|_| upstream_failure("unsafe_token_endpoint"))?;
        Ok(metadata)
    }

    fn client(&self, metadata: CoreProviderMetadata) -> OidcClient {
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.config.client_id.clone()),
            None,
        )
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_uri(self.redirect_uri.clone());
        self.authentication.configure_client(client)
    }

    fn authentication_parameters(
        &self,
        client: &OidcClient,
    ) -> Result<Vec<(&'static str, String)>, BrokerError> {
        self.authentication
            .token_parameters(
                &self.config.client_id,
                client
                    .token_uri()
                    .ok_or_else(|| upstream_failure("missing_token_endpoint"))?
                    .as_str(),
            )
            .map_err(|_| upstream_failure("client_authentication"))
    }

    fn resource(&self, resource: &str) -> Result<&Resource, BrokerError> {
        self.resources
            .iter()
            .find(|configured| configured.uri == resource)
            .ok_or(BrokerError::OAuth("invalid_target"))
    }

    pub fn start_login(
        &self,
        offline: bool,
        resource: &str,
    ) -> Result<(String, String, LoginChallenge), BrokerError> {
        let resource = self.resource(resource)?;
        let client = self.client(self.metadata.clone());
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".into()))
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new(resource.default_scope()))
            .set_pkce_challenge(challenge)
            .add_extra_param("response_mode", "query");
        if offline {
            request = request.add_scope(Scope::new("offline_access".into()));
        }
        let (url, state, nonce) = request.url();
        Ok((
            url.into(),
            state.secret().clone(),
            LoginChallenge {
                nonce: nonce.secret().clone(),
                verifier: verifier.secret().clone(),
            },
        ))
    }

    pub async fn finish_login(
        &self,
        code: String,
        challenge: LoginChallenge,
        resource: &str,
        needs_groups: bool,
    ) -> Result<UpstreamIdentity, BrokerError> {
        // Discover again for current keys, including provider signing-key rollover.
        let metadata = Self::discover_metadata(&self.http, &self.config.issuer).await?;
        let client = self.client(metadata.clone());
        let parameters = self.authentication_parameters(&client)?;
        let mut request = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| BrokerError::Upstream)?
            .set_pkce_verifier(PkceCodeVerifier::new(challenge.verifier));
        for (name, value) in parameters {
            request = request.add_extra_param(name, value);
        }
        let response = request
            .request_async(&self.http)
            .await
            .map_err(|error| token_exchange_failure("authorization_code_exchange", error))?;
        let mut identity = self.verify(
            &response,
            &client.id_token_verifier(),
            &challenge.nonce,
            true,
            needs_groups,
        )?;
        let grant = self.verify_access(&response, &metadata, resource).await?;
        identity.permission_expires_at = grant.expires_at;
        identity.api_scopes = grant.scopes;
        Ok(identity)
    }

    pub async fn refresh(
        &self,
        previous: &UpstreamIdentity,
        resource: &str,
        needs_groups: bool,
    ) -> Result<UpstreamIdentity, BrokerError> {
        let refresh = RefreshToken::new(
            previous
                .refresh_token
                .clone()
                .ok_or(BrokerError::OAuth("invalid_grant"))?,
        );
        let metadata = Self::discover_metadata(&self.http, &self.config.issuer).await?;
        let client = self.client(metadata.clone());
        let parameters = self.authentication_parameters(&client)?;
        let mut request = client
            .exchange_refresh_token(&refresh)
            .map_err(|_| BrokerError::Upstream)?
            .add_scope(Scope::new(self.resource(resource)?.default_scope()))
            .add_scope(Scope::new("openid".into()))
            .add_scope(Scope::new("profile".into()))
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new("offline_access".into()));
        for (name, value) in parameters {
            request = request.add_extra_param(name, value);
        }
        let response = request
            .request_async(&self.http)
            .await
            .map_err(|error| token_exchange_failure("refresh_exchange", error))?;
        let mut identity = self.verify(
            &response,
            &client.id_token_verifier(),
            &previous.login_nonce,
            false,
            needs_groups,
        )?;
        let grant = self.verify_access(&response, &metadata, resource).await?;
        identity.permission_expires_at = grant.expires_at;
        identity.api_scopes = grant.scopes;
        if identity.upstream_subject != previous.upstream_subject {
            return Err(BrokerError::rejected(
                "invalid_grant",
                "upstream_subject_changed_on_refresh",
            ));
        }
        if identity.refresh_token.is_none() {
            identity.refresh_token = previous.refresh_token.clone();
        }
        identity.authenticated_at = previous.authenticated_at;
        Ok(identity)
    }

    async fn verify_access(
        &self,
        response: &CoreTokenResponse,
        metadata: &CoreProviderMetadata,
        resource: &str,
    ) -> Result<crate::access::AccessGrant, BrokerError> {
        // The ID token has already been verified by verify(); its provider claims
        // bind this API token to the same signed-in user.
        let id_token = response
            .id_token()
            .ok_or(BrokerError::Upstream)?
            .to_string();
        crate::access::verify(
            &self.http,
            metadata,
            &self.config,
            self.resource(resource)?,
            response.access_token().secret(),
            &id_token,
        )
        .await
        .map_err(|error| {
            // access::verify exposes only fixed diagnostic messages; never its
            // source chain, token contents, or provider response bodies.
            tracing::warn!(stage = "access_token_validation", reason = %error,
                resource, "Upstream API authorization failed");
            BrokerError::Upstream
        })
    }

    fn verify(
        &self,
        response: &CoreTokenResponse,
        verifier: &CoreIdTokenVerifier<'_>,
        original_nonce: &str,
        require_nonce: bool,
        needs_groups: bool,
    ) -> Result<UpstreamIdentity, BrokerError> {
        let token = response
            .id_token()
            .ok_or_else(|| upstream_failure("missing_id_token"))?;
        let verifier = verifier
            .clone()
            .set_allowed_algs([
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            ])
            .set_issue_time_verifier_fn(|issued_at| {
                if issued_at > Utc::now() + Duration::seconds(60) {
                    Err("ID token issued in the future".into())
                } else {
                    Ok(())
                }
            });
        let claims = token
            .claims(&verifier, |nonce: Option<&Nonce>| match nonce {
                Some(nonce) if secrets_equal(nonce.secret(), original_nonce) => Ok(()),
                None if !require_nonce => Ok(()),
                _ => Err("ID token nonce mismatch".into()),
            })
            .map_err(|error| {
                tracing::warn!(
                    stage = "id_token_validation",
                    reason = claims_failure_reason(&error),
                    "Upstream ID token rejected"
                );
                BrokerError::Upstream
            })?;
        if claims.subject().as_str().is_empty() {
            return Err(upstream_failure("empty_subject"));
        }
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                response.access_token(),
                token
                    .signing_alg()
                    .map_err(|_| upstream_failure("invalid_id_token_signing_algorithm"))?,
                token
                    .signing_key(&verifier)
                    .map_err(|_| upstream_failure("id_token_hash_signing_key_unavailable"))?,
            )
            .map_err(|_| upstream_failure("id_token_hash_computation_failed"))?;
            if actual != *expected {
                return Err(upstream_failure("access_token_hash_mismatch"));
            }
        }
        // Only read provider-specific claims after the OIDC library has verified
        // the exact signed token's signature, issuer, audience, expiry and nonce.
        let encoded = token.to_string();
        let payload = encoded.split('.').nth(1).ok_or(BrokerError::Upstream)?;
        let raw: ProviderClaims = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| upstream_failure("invalid_provider_claim_encoding"))?,
        )
        .map_err(|_| upstream_failure("invalid_provider_claims"))?;
        if needs_groups
            && (raw.hasgroups == Some(true)
                || raw
                    .claim_names
                    .as_ref()
                    .is_some_and(|claims| claims.contains_key("groups")))
        {
            tracing::warn!(
                reason = "group_overage",
                "Upstream group claims are unavailable"
            );
            return Err(BrokerError::OAuth("access_denied"));
        }
        let groups = raw.groups.unwrap_or_default();
        let authenticated_at = raw.auth_time.unwrap_or(claims.issue_time());
        if authenticated_at > Utc::now() + Duration::seconds(60) {
            return Err(upstream_failure("authentication_time_in_future"));
        }
        Ok(UpstreamIdentity {
            subject: token_hash(&format!(
                "{}\0{}",
                self.config.issuer,
                claims.subject().as_str()
            )),
            upstream_subject: claims.subject().to_string(),
            email: claims.email().map(|email| email.as_str().to_string()),
            groups,
            api_scopes: Vec::new(),
            authenticated_at,
            permission_expires_at: claims.expiration(),
            refresh_token: response.refresh_token().map(|t| t.secret().clone()),
            login_nonce: original_nonce.into(),
        })
    }
}

#[derive(Deserialize)]
struct ProviderClaims {
    #[serde(default)]
    groups: Option<Vec<String>>,
    hasgroups: Option<bool>,
    #[serde(rename = "_claim_names")]
    claim_names: Option<HashMap<String, String>>,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    auth_time: Option<DateTime<Utc>>,
}

fn upstream_failure(stage: &'static str) -> BrokerError {
    // Never log provider responses, requests, codes, tokens, or client secrets.
    tracing::warn!(stage, "Upstream OIDC operation failed");
    BrokerError::Upstream
}

/// Provider text is untrusted and may contain credentials or personal data.
pub(crate) fn safe_oauth_error(code: &str) -> &'static str {
    match code {
        "invalid_client" => "invalid_client",
        "invalid_grant" => "invalid_grant",
        "invalid_request" => "invalid_request",
        "invalid_scope" => "invalid_scope",
        "unauthorized_client" => "unauthorized_client",
        "access_denied" => "access_denied",
        "unsupported_grant_type" => "unsupported_grant_type",
        "server_error" => "server_error",
        "temporarily_unavailable" => "temporarily_unavailable",
        "interaction_required" => "interaction_required",
        "consent_required" => "consent_required",
        "login_required" => "login_required",
        _ => "unrecognized_upstream_error",
    }
}

fn token_exchange_failure<E: std::error::Error + 'static>(
    stage: &'static str,
    error: RequestTokenError<E, StandardErrorResponse<CoreErrorResponseType>>,
) -> BrokerError {
    let reason = match &error {
        RequestTokenError::ServerResponse(response) => safe_oauth_error(response.error().as_ref()),
        RequestTokenError::Request(_) => "upstream_transport_error",
        RequestTokenError::Parse(_, _) => "malformed_token_response",
        RequestTokenError::Other(_) => "unexpected_token_response",
    };
    let aadsts_code = match &error {
        RequestTokenError::ServerResponse(response) => {
            response.error_description().and_then(|description| {
                let digits: String = description
                    .split("AADSTS")
                    .nth(1)?
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .take(10)
                    .collect();
                (!digits.is_empty()).then_some(digits)
            })
        }
        _ => None,
    };
    tracing::warn!(stage, reason, aadsts_code, "Upstream token exchange failed");
    BrokerError::Upstream
}

fn claims_failure_reason(error: &ClaimsVerificationError) -> &'static str {
    match error {
        ClaimsVerificationError::Expired(_) => "id_token_expired",
        ClaimsVerificationError::InvalidAudience(_) => "id_token_audience_mismatch",
        ClaimsVerificationError::InvalidIssuer(_) => "id_token_issuer_mismatch",
        ClaimsVerificationError::InvalidNonce(_) => "id_token_nonce_mismatch",
        ClaimsVerificationError::InvalidSubject(_) => "id_token_subject_mismatch",
        ClaimsVerificationError::InvalidAuthTime(_) => "id_token_authentication_time_invalid",
        ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::NoMatchingKey,
        ) => "id_token_signing_key_not_found",
        ClaimsVerificationError::SignatureVerification(_) => "id_token_signature_invalid",
        _ => "id_token_claims_invalid",
    }
}
