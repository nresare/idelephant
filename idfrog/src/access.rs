//! Validation of delegated API permissions before minting downstream tokens.
use crate::config::{Resource, UpstreamConfig, validate_endpoint};
use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use openidconnect::{core::CoreProviderMetadata, reqwest};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
    oid: Option<String>,
    tid: Option<String>,
    ver: Option<String>,
    azp: Option<String>,
    appid: Option<String>,
    scp: Option<String>,
}

fn payload(token: &str) -> anyhow::Result<Claims> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Invalid JWT"))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .context("Malformed token payload encoding")?;
    serde_json::from_slice(&decoded).context("Malformed or missing token claims")
}

/// Token content can select a pinned metadata version, never a discovery URL.
fn entra_tenant(issuer: &str) -> Option<&str> {
    issuer
        .strip_prefix("https://login.microsoftonline.com/")?
        .strip_suffix("/v2.0")
        .filter(|tenant| !tenant.is_empty() && !tenant.contains('/'))
}

pub(crate) struct AccessGrant {
    pub expires_at: DateTime<Utc>,
    pub scopes: Vec<String>,
}

pub(crate) async fn verify(
    http: &reqwest::Client,
    metadata: &CoreProviderMetadata,
    upstream: &UpstreamConfig,
    resource: &Resource,
    access_token: &str,
    verified_id_token: &str,
) -> anyhow::Result<AccessGrant> {
    let mut issuer = upstream.issuer.clone();
    let mut keys: JwkSet = serde_json::from_value(
        serde_json::to_value(metadata.jwks()).context("Invalid provider signing keys")?,
    )
    .context("Invalid provider signing keys")?;
    if let Some(tenant) = entra_tenant(&upstream.issuer) {
        // API registrations choose token version independently of the v2 login
        // endpoint. The v1 metadata and expected issuer come from our tenant.
        match payload(access_token)?.ver.as_deref() {
            Some("1.0") => {
                issuer = format!("https://sts.windows.net/{tenant}/");
                #[derive(Deserialize)]
                struct Metadata {
                    issuer: String,
                    jwks_uri: String,
                }
                let response = http.get(format!(
                    "https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration"
                )).send().await.context("Entra v1 discovery request failed")?
                    .error_for_status().context("Entra v1 discovery HTTP error")?
                    .bytes().await.context("Entra v1 discovery body read failed")?;
                let v1: Metadata = serde_json::from_slice(&response)
                    .context("Malformed Entra v1 discovery response")?;
                anyhow::ensure!(v1.issuer == issuer, "Unexpected v1 issuer");
                validate_endpoint(&v1.jwks_uri).context("Unsafe Entra v1 signing keys endpoint")?;
                let response = http
                    .get(v1.jwks_uri)
                    .send()
                    .await
                    .context("Entra v1 signing keys request failed")?
                    .error_for_status()
                    .context("Entra v1 signing keys HTTP error")?
                    .bytes()
                    .await
                    .context("Entra v1 signing keys body read failed")?;
                keys =
                    serde_json::from_slice(&response).context("Malformed Entra v1 signing keys")?;
            }
            Some("2.0") => {}
            _ => anyhow::bail!("Unsupported Entra access token version"),
        }
    }
    let claims = validate(
        access_token,
        &keys,
        &issuer,
        std::slice::from_ref(&resource.application_id),
    )?;
    let identity = payload(verified_id_token)?;
    let expires_at = DateTime::from_timestamp(claims.exp, 0)
        .ok_or_else(|| anyhow::anyhow!("Invalid access token expiry"))?;
    let scopes = authorize(claims, identity, upstream, resource)?;
    Ok(AccessGrant { expires_at, scopes })
}

fn authorize(
    claims: Claims,
    identity: Claims,
    upstream: &UpstreamConfig,
    resource: &Resource,
) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(
        claims.iat <= Utc::now().timestamp() + 60,
        "Future access token"
    );
    let prefix = resource.scope_prefix();
    let mut scopes = Vec::new();
    for scope in claims.scp.as_deref().unwrap_or_default().split_whitespace() {
        let scope = match scope.strip_prefix(&prefix) {
            Some(scope) => scope,
            None if !scope.contains("://") => scope,
            None => continue,
        };
        if scope != ".default"
            && idp_oauth::protocol::valid_scope(scope)
            && !scopes.iter().any(|existing| existing == scope)
        {
            scopes.push(scope.to_owned());
        }
    }
    anyhow::ensure!(!scopes.is_empty(), "Missing delegated API scopes");
    if let Some(tenant) = entra_tenant(&upstream.issuer) {
        // Entra sub is pairwise per API; oid + tid bind tokens across audiences.
        anyhow::ensure!(
            claims.tid.as_deref() == Some(tenant) && identity.tid == claims.tid,
            "Wrong tenant"
        );
        anyhow::ensure!(
            claims.oid.as_ref().is_some_and(|oid| !oid.is_empty()) && claims.oid == identity.oid,
            "Wrong user"
        );
        let client = if claims.ver.as_deref() == Some("1.0") {
            claims.appid
        } else {
            claims.azp
        };
        anyhow::ensure!(
            client.as_deref() == Some(&upstream.client_id),
            "Wrong client"
        );
    } else {
        anyhow::ensure!(
            claims.sub == identity.sub && !claims.sub.is_empty(),
            "Wrong user"
        );
        anyhow::ensure!(
            claims.azp.as_deref() == Some(&upstream.client_id),
            "Wrong client"
        );
    }
    Ok(scopes)
}

fn validate(
    token: &str,
    keys: &JwkSet,
    issuer: &str,
    audiences: &[String],
) -> anyhow::Result<Claims> {
    let header = decode_header(token).context("Malformed access token header")?;
    anyhow::ensure!(
        matches!(header.alg, Algorithm::RS256 | Algorithm::ES256),
        "Unsupported algorithm"
    );
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("Missing kid"))?;
    let jwk = keys
        .find(&kid)
        .ok_or_else(|| anyhow::anyhow!("Unknown key"))?;
    anyhow::ensure!(
        jwk.common
            .public_key_use
            .as_ref()
            .is_none_or(|usage| *usage == jsonwebtoken::jwk::PublicKeyUse::Signature),
        "Not a signing key"
    );
    if let Some(algorithm) = jwk.common.key_algorithm {
        anyhow::ensure!(
            algorithm.to_string() == format!("{:?}", header.alg),
            "Key algorithm mismatch"
        );
    }
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(audiences);
    validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
    validation.validate_nbf = true;
    validation.leeway = 0;
    let key = DecodingKey::from_jwk(jwk).context("Invalid provider signing key")?;
    decode::<Claims>(token, &key, &validation)
        .map(|token| token.claims)
        .map_err(|error| {
            use jsonwebtoken::errors::ErrorKind;
            anyhow::anyhow!(match error.kind() {
                ErrorKind::InvalidAudience => "Access token audience mismatch",
                ErrorKind::InvalidIssuer => "Access token issuer mismatch",
                ErrorKind::ExpiredSignature => "Access token expired",
                ErrorKind::ImmatureSignature => "Access token not yet valid",
                ErrorKind::InvalidSignature => "Access token signature mismatch",
                ErrorKind::MissingRequiredClaim(claim) => match claim.as_str() {
                    "exp" => "Access token missing exp",
                    "nbf" => "Access token missing nbf",
                    "iss" => "Access token missing iss",
                    "aud" => "Access token missing aud",
                    "sub" => "Access token missing sub",
                    _ => "Access token missing required claim",
                },
                _ => "Invalid access token claims or signature",
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthenticationConfig;
    use serde_json::json;

    #[test]
    fn entra_requires_tenant_user_client_and_delegated_scope_for_both_token_versions() {
        let upstream = UpstreamConfig {
            issuer: "https://login.microsoftonline.com/tenant-id/v2.0".into(),
            client_id: "broker-client".into(),
            authentication: AuthenticationConfig::ClientSecretPost {
                client_secret_file: "unused".into(),
            },
        };
        let resource = Resource {
            uri: "https://mcp.example".into(),
            application_id: "api".into(),
        };
        let identity = json!({"sub":"id-token-pairwise", "iat":Utc::now().timestamp(), "exp":Utc::now().timestamp()+3600, "oid":"alice", "tid":"tenant-id"});
        for (version, client_claim) in [("1.0", "appid"), ("2.0", "azp")] {
            let mut token = json!({"sub":"api-token-pairwise", "iat":Utc::now().timestamp(), "exp":Utc::now().timestamp()+3600, "oid":"alice", "tid":"tenant-id", "scp":"Read Full", "ver":version});
            token[client_claim] = json!("broker-client");
            assert!(
                authorize(
                    serde_json::from_value(token.clone()).unwrap(),
                    serde_json::from_value(identity.clone()).unwrap(),
                    &upstream,
                    &resource
                )
                .is_ok()
            );
            for (claim, value) in [
                ("oid", "bob"),
                ("tid", "another-tenant"),
                (client_claim, "other-client"),
                ("scp", ""),
            ] {
                let mut invalid = token.clone();
                invalid[claim] = json!(value);
                assert!(
                    authorize(
                        serde_json::from_value(invalid).unwrap(),
                        serde_json::from_value(identity.clone()).unwrap(),
                        &upstream,
                        &resource
                    )
                    .is_err(),
                    "{version}/{claim}"
                );
            }
            for claim in ["oid", "tid", client_claim, "scp"] {
                let mut invalid = token.clone();
                invalid.as_object_mut().unwrap().remove(claim);
                assert!(
                    authorize(
                        serde_json::from_value(invalid).unwrap(),
                        serde_json::from_value(identity.clone()).unwrap(),
                        &upstream,
                        &resource
                    )
                    .is_err(),
                    "missing {version}/{claim}"
                );
            }
        }
    }
}
