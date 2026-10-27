//! Resolve pre-registered clients and public clients identified by HTTPS metadata.
use serde::Deserialize;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use url::Url;

const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
const MAX_CACHE_ENTRIES: usize = 256;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationType {
    #[default]
    Web,
    Native,
}

#[derive(Clone, Debug)]
pub struct Client {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub cimd: bool,
    pub application_type: ApplicationType,
}

/// The application's explicitly registered clients, consulted before CIMD.
/// Lookup failures must be returned rather than treated as an unknown client.
pub trait ClientRegistry {
    type Error;

    fn find_client(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<Option<Client>, Self::Error>> + Send;
}

/// A registry for deployments accepting only metadata-document clients.
pub struct NoRegisteredClients;

impl ClientRegistry for NoRegisteredClients {
    type Error = std::convert::Infallible;

    async fn find_client(&self, _id: &str) -> Result<Option<Client>, Self::Error> {
        Ok(None)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("OAuth error: {code}: {detail}")]
pub struct MetadataError {
    pub code: &'static str,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError<E> {
    #[error("Client registry lookup failed: {0}")]
    Registry(E),
    #[error(transparent)]
    Metadata(#[from] MetadataError),
}

impl Client {
    pub fn allows_redirect(&self, requested: &str) -> bool {
        self.redirect_uris.iter().any(|registered| {
            if registered == requested {
                return true;
            }
            if self.application_type != ApplicationType::Native {
                return false;
            }
            match (
                loopback_without_port(registered),
                loopback_without_port(requested),
            ) {
                (Some(registered), Some(requested)) => registered == requested,
                _ => false,
            }
        })
    }
}

// RFC 8252 permits an ephemeral port on native HTTP loopback callbacks.
// Remove only that port from the original text: URL normalization must not
// loosen matching of hosts, paths, query strings, or their encodings.
fn loopback_without_port(uri: &str) -> Option<String> {
    if !valid_redirect(uri) {
        return None;
    }
    let url = Url::parse(uri).ok()?;
    let loopback = match url.host()? {
        url::Host::Domain("localhost") => true,
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
        _ => false,
    };
    if !loopback {
        return None;
    }
    let remainder = uri.strip_prefix("http://")?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let host_end = if authority.starts_with('[') {
        authority.find(']')? + 1
    } else {
        authority.find(':').unwrap_or(authority.len())
    };
    let port = &authority[host_end..];
    if !port.is_empty() {
        let number = port.strip_prefix(':')?;
        if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    Some(format!(
        "http://{}{}",
        &authority[..host_end],
        &remainder[authority_end..]
    ))
}

#[derive(Deserialize)]
struct Document {
    #[serde(default)]
    application_type: ApplicationType,
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: Option<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
}

#[derive(Clone, Default)]
pub struct ClientMetadataService {
    cache: Arc<Mutex<HashMap<String, (Instant, Client)>>>,
}

fn log_client_id(id: &str) -> String {
    // Invalid URLs can contain credentials or query parameters. Never log those.
    Url::parse(id)
        .ok()
        .filter(|url| {
            id.len() <= 2048
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
        .map(|url| url.to_string())
        .unwrap_or_else(|| "<invalid client URL>".into())
}

fn invalid(id: &str, reason: &str) -> MetadataError {
    tracing::warn!(client_id = %log_client_id(id), reason, "CIMD client rejected");
    let detail = match reason {
        "invalid_metadata_url" | "missing_metadata_host" => {
            "The application's client ID must be a valid HTTPS client metadata URL, including a path and without credentials, query parameters, or a fragment."
        }
        "dns_lookup_timeout" => "Looking up the application's client metadata host timed out.",
        "dns_lookup_failed" | "dns_lookup_returned_no_addresses" => {
            "The application's client metadata host could not be found in DNS."
        }
        "metadata_address_is_not_public" => {
            "The application's client metadata URL resolves to a private or reserved network address. Client metadata must be hosted on a public HTTPS address."
        }
        "metadata_http_client_configuration_failed" => {
            "The identity provider could not prepare a secure connection to the application's client metadata endpoint."
        }
        "metadata_request_timeout" => "Fetching the application's client metadata timed out.",
        "metadata_connection_failed" => {
            "The identity provider could not establish a secure connection to the application's client metadata endpoint."
        }
        "metadata_request_failed" | "metadata_body_read_failed" => {
            "The identity provider could not download the application's client metadata."
        }
        "metadata_response_too_large" => {
            "The application's client metadata document exceeds the maximum size of 64 KiB."
        }
        "invalid_metadata_json_or_field_type" => {
            "The application's client metadata is not valid JSON, is missing required fields, or contains unsupported field types or values."
        }
        "metadata_client_id_mismatch" => {
            "The client_id in the application's metadata document does not exactly match the URL used to fetch that document."
        }
        "invalid_client_name" => {
            "The application's client metadata must include a non-empty client_name of at most 256 bytes."
        }
        "invalid_redirect_uri_count" => {
            "The application's client metadata must include between 1 and 32 callback URLs in redirect_uris."
        }
        "invalid_redirect_uri" => {
            "The application's client metadata contains an invalid callback URL. Callbacks must use HTTPS or HTTP on a loopback host, without credentials, fragments, or wildcards."
        }
        "public_client_authentication_not_supported" => {
            "The application's client metadata does not support token authentication method 'none', which is required by this identity provider's CIMD implementation."
        }
        "authorization_code_grant_not_supported" => {
            "The application's client metadata does not list the required 'authorization_code' grant type."
        }
        "unsupported_response_types" => {
            "The application's client metadata declares unsupported response types. This identity provider requires response_types to contain only 'code'."
        }
        _ => "The application's client metadata could not be validated.",
    };
    let detail = if let Some(status) = reason.strip_prefix("metadata_http_status_") {
        format!(
            "The application's client metadata endpoint returned HTTP {status} instead of a successful response. Metadata must be served directly without redirects."
        )
    } else {
        detail.to_string()
    };
    MetadataError {
        code: "invalid_client",
        detail,
    }
}

impl ClientMetadataService {
    /// Seed validated metadata for offline tests.
    #[cfg(test)]
    async fn cache_document(&self, id: &str, bytes: &[u8]) -> Result<(), MetadataError> {
        metadata_url(id)?;
        let client = parse_document(id, bytes)?;
        self.cache.lock().await.insert(
            id.into(),
            (Instant::now() + Duration::from_secs(300), client),
        );
        Ok(())
    }

    pub async fn resolve<R: ClientRegistry>(
        &self,
        registry: &R,
        id: &str,
    ) -> Result<Client, ResolveError<R::Error>> {
        if let Some(client) = registry
            .find_client(id)
            .await
            .map_err(ResolveError::Registry)?
        {
            return Ok(client);
        }
        Ok(self.resolve_metadata(id).await?)
    }

    async fn resolve_metadata(&self, id: &str) -> Result<Client, MetadataError> {
        let url = metadata_url(id)?;
        if let Some((expiry, client)) = self.cache.lock().await.get(id)
            && *expiry > Instant::now()
        {
            return Ok(client.clone());
        }
        // Resolve once, reject every non-public address, and pin these addresses to
        // the HTTP request. Disable proxies and redirects to avoid bypasses.
        let host = url
            .host_str()
            .ok_or_else(|| invalid(id, "missing_metadata_host"))?;
        let addresses: Vec<SocketAddr> = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((
                host.trim_matches(['[', ']']),
                url.port_or_known_default().unwrap_or(443),
            )),
        )
        .await
        .map_err(|_| invalid(id, "dns_lookup_timeout"))?
        .map_err(|_| invalid(id, "dns_lookup_failed"))?
        .collect();
        if addresses.is_empty() {
            return Err(invalid(id, "dns_lookup_returned_no_addresses"));
        }
        if addresses.iter().any(|a| !public_ip(a.ip())) {
            return Err(invalid(id, "metadata_address_is_not_public"));
        }
        let http = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| invalid(id, "metadata_http_client_configuration_failed"))?;
        let mut response = http
            .get(url.clone())
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|error| {
                invalid(
                    id,
                    if error.is_timeout() {
                        "metadata_request_timeout"
                    } else if error.is_connect() {
                        "metadata_connection_failed"
                    } else {
                        "metadata_request_failed"
                    },
                )
            })?;
        if !response.status().is_success() {
            return Err(invalid(
                id,
                &format!("metadata_http_status_{}", response.status().as_u16()),
            ));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_DOCUMENT_BYTES as u64)
        {
            return Err(invalid(id, "metadata_response_too_large"));
        }
        let cache_control = response
            .headers()
            .get("cache-control")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        let age = response
            .headers()
            .get("age")
            .and_then(|h| h.to_str().ok())
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| invalid(id, "metadata_body_read_failed"))?
        {
            if bytes.len() + chunk.len() > MAX_DOCUMENT_BYTES {
                return Err(invalid(id, "metadata_response_too_large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let client = parse_document(id, &bytes)?;
        let ttl = cache_ttl(&cache_control).saturating_sub(Duration::from_secs(age));
        if !ttl.is_zero() {
            let mut cache = self.cache.lock().await;
            cache.retain(|_, (expiry, _)| *expiry > Instant::now());
            if cache.len() >= MAX_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(id.to_string(), (Instant::now() + ttl, client.clone()));
        }
        Ok(client)
    }
}

fn cache_ttl(header: &str) -> Duration {
    let directives: Vec<_> = header.split(',').map(str::trim).collect();
    if directives
        .iter()
        .any(|d| d.eq_ignore_ascii_case("no-store") || d.eq_ignore_ascii_case("no-cache"))
    {
        return Duration::ZERO;
    }
    let seconds = directives
        .iter()
        .find_map(|d| {
            d.to_ascii_lowercase()
                .strip_prefix("max-age=")
                .and_then(|n| n.trim_matches('"').parse::<u64>().ok())
        })
        .unwrap_or(300);
    Duration::from_secs(seconds.min(300))
}

fn metadata_url(id: &str) -> Result<Url, MetadataError> {
    let url = Url::parse(id).map_err(|_| invalid(id, "invalid_metadata_url"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.path() == "/"
        || url.fragment().is_some()
        || url.query().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid(id, "invalid_metadata_url"));
    }
    Ok(url)
}

pub fn valid_redirect(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    let loopback = match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    !uri.contains('*')
        && url.host_str().is_some()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && (url.scheme() == "https" || (url.scheme() == "http" && loopback))
}

fn parse_document(id: &str, bytes: &[u8]) -> Result<Client, MetadataError> {
    let doc: Document = serde_json::from_slice(bytes)
        .map_err(|_| invalid(id, "invalid_metadata_json_or_field_type"))?;
    if doc.client_id != id {
        return Err(invalid(id, "metadata_client_id_mismatch"));
    }
    if doc.client_name.trim().is_empty() || doc.client_name.len() > 256 {
        return Err(invalid(id, "invalid_client_name"));
    }
    if doc.redirect_uris.is_empty() || doc.redirect_uris.len() > 32 {
        return Err(invalid(id, "invalid_redirect_uri_count"));
    }
    if doc.redirect_uris.iter().any(|uri| !valid_redirect(uri)) {
        return Err(invalid(id, "invalid_redirect_uri"));
    }
    let supports_none = match doc.token_endpoint_auth_methods_supported {
        Some(methods) => methods.iter().any(|m| m == "none"),
        None => doc.token_endpoint_auth_method.as_deref().unwrap_or("none") == "none",
    };
    if !supports_none {
        return Err(invalid(id, "public_client_authentication_not_supported"));
    }
    // CIMD describes capabilities shared across authorization servers.
    // Require the grant used here, rather than rejecting extra capabilities.
    if let Some(grants) = doc.grant_types {
        if !grants.iter().any(|grant| grant == "authorization_code") {
            return Err(invalid(id, "authorization_code_grant_not_supported"));
        }
        let additional_grant_count = grants
            .iter()
            .filter(|grant| {
                grant.as_str() != "authorization_code" && grant.as_str() != "refresh_token"
            })
            .count();
        if additional_grant_count > 0 {
            tracing::debug!(client_id = %log_client_id(id), additional_grant_count,
                "CIMD client advertises additional grants; accepting authorization-code flow");
        }
    }
    if doc.response_types.is_some_and(|types| types != ["code"]) {
        return Err(invalid(id, "unsupported_response_types"));
    }
    Ok(Client {
        client_id: doc.client_id,
        name: doc.client_name,
        redirect_uris: doc.redirect_uris,
        cimd: true,
        application_type: doc.application_type,
    })
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 198 && (b == 18 || b == 19))
                && !(a == 192 && b == 0)
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Only global unicast; exclude documentation, transition mechanisms,
            // and special allocations in 2001::/23.
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone, Default)]
    struct LogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn test_logs() -> LogBuffer {
        // Keep one subscriber alive for concurrent tests, so tracing's global
        // callsite/level cache cannot disable events between scoped collectors.
        static LOGS: std::sync::OnceLock<LogBuffer> = std::sync::OnceLock::new();
        LOGS.get_or_init(|| {
            let buffer = LogBuffer::default();
            let writer = buffer.clone();
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_env_filter("idp_oauth::client_metadata=debug")
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber).unwrap();
            buffer
        })
        .clone()
    }

    #[test]
    fn logs_explain_metadata_validation_without_exposing_sensitive_values() {
        let buffer = test_logs();
        {
            let id = "https://claude.ai/oauth/mcp-oauth-client-metadata";
            let mut document = serde_json::json!({
                "client_id": "https://wrong.example/never-log-document-secret",
                "client_name": "Claude", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
            });
            assert!(matches!(
                parse_document(id, &serde_json::to_vec(&document).unwrap()),
                Err(MetadataError {
                    code: "invalid_client",
                    ..
                })
            ));
            document["client_id"] = id.into();
            assert!(parse_document(id, &serde_json::to_vec(&document).unwrap()).is_ok());
            document["grant_types"] = serde_json::json!(["refresh_token"]);
            assert!(parse_document(id, &serde_json::to_vec(&document).unwrap()).is_err());
            document["grant_types"] = serde_json::json!(["authorization_code"]);
            document["token_endpoint_auth_method"] = "private_key_jwt".into();
            assert!(parse_document(id, &serde_json::to_vec(&document).unwrap()).is_err());
            assert!(parse_document(id, b"never-log-invalid-json-secret").is_err());
            assert!(metadata_url(
                "https://user:never-log-password@client.example/client.json?state=never-log-state"
            )
            .is_err());
        }
        let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        for expected in [
            "https://claude.ai/oauth/mcp-oauth-client-metadata",
            "metadata_client_id_mismatch",
            "additional_grant_count=1",
            "authorization_code_grant_not_supported",
            "public_client_authentication_not_supported",
            "invalid_metadata_json_or_field_type",
            "invalid_metadata_url",
        ] {
            assert!(logs.contains(expected), "missing {expected}: {logs}");
        }
        assert!(
            !logs.contains("never-log-"),
            "sensitive input leaked: {logs}"
        );
    }

    #[tokio::test]
    async fn logs_distinguish_blocked_metadata_fetches() {
        let buffer = test_logs();
        let result = ClientMetadataService::default()
            .resolve(&NoRegisteredClients, "https://127.0.0.1/client.json")
            .await;
        assert!(matches!(
            result,
            Err(ResolveError::Metadata(MetadataError {
                code: "invalid_client",
                ..
            }))
        ));
        let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("metadata_address_is_not_public"), "{logs}");
        assert!(logs.contains("https://127.0.0.1/client.json"), "{logs}");
    }

    struct ConfiguredClient(Client);

    impl ClientRegistry for ConfiguredClient {
        type Error = &'static str;

        async fn find_client(&self, id: &str) -> Result<Option<Client>, Self::Error> {
            Ok((self.0.client_id == id).then(|| self.0.clone()))
        }
    }

    #[tokio::test]
    async fn registered_clients_take_precedence_over_cached_metadata() {
        let id = "https://client.example/client.json";
        let resolver = ClientMetadataService::default();
        resolver
            .cache_document(
                id,
                &serde_json::to_vec(&serde_json::json!({
                    "client_id": id, "client_name": "Metadata client",
                    "redirect_uris": ["https://client.example/metadata-callback"]
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let registry = ConfiguredClient(Client {
            client_id: id.into(),
            name: "Configured client".into(),
            redirect_uris: vec!["https://client.example/configured-callback".into()],
            cimd: false,
            application_type: ApplicationType::Web,
        });
        let client = resolver.resolve(&registry, id).await.unwrap();
        assert!(!client.cimd);
        assert!(client.allows_redirect("https://client.example/configured-callback"));
        assert!(!client.allows_redirect("https://client.example/metadata-callback"));
        let client = resolver.resolve(&NoRegisteredClients, id).await.unwrap();
        assert!(client.cimd);
        assert!(client.allows_redirect("https://client.example/metadata-callback"));
    }

    #[tokio::test]
    async fn registry_failures_do_not_fall_back_to_metadata() {
        struct UnavailableRegistry;
        impl ClientRegistry for UnavailableRegistry {
            type Error = &'static str;

            async fn find_client(&self, _id: &str) -> Result<Option<Client>, Self::Error> {
                Err("registry unavailable")
            }
        }
        let resolver = ClientMetadataService::default();
        assert!(matches!(
            resolver
                .resolve(&UnavailableRegistry, "not-a-metadata-url")
                .await,
            Err(ResolveError::Registry("registry unavailable"))
        ));
    }

    #[test]
    fn native_loopback_redirects_allow_only_port_variation() {
        let id = "https://chatgpt.com/oauth/codex/client.json";
        let document = serde_json::json!({
            "client_id": id, "client_name": "Codex", "application_type": "native",
            "redirect_uris": ["http://127.0.0.1/callback", "http://[::1]:1234/callback", "http://localhost/callback"],
            "token_endpoint_auth_method": "none"
        });
        let client = parse_document(id, &serde_json::to_vec(&document).unwrap()).unwrap();
        for uri in [
            "http://127.0.0.1:52889/callback",
            "http://127.0.0.1:80/callback",
            "http://[::1]:52889/callback",
            "http://localhost:52889/callback",
        ] {
            assert!(client.allows_redirect(uri), "{uri}");
        }
        for uri in [
            "http://127.0.0.2:52889/callback",
            "http://127.1:52889/callback",
            "http://127.0.0.1:52889/other",
            "http://127.0.0.1:52889/%63allback",
            "http://127.0.0.1:52889/a/../callback",
            "http://127.0.0.1:52889/callback?extra=true",
            "http://127.0.0.1:52889/callback#fragment",
            "http://user@127.0.0.1:52889/callback",
            "https://127.0.0.1:52889/callback",
            "http://localhost.evil.example:52889/callback",
            "http://[::ffff:127.0.0.1]:52889/callback",
        ] {
            assert!(!client.allows_redirect(uri), "{uri}");
        }
        let mut web_document = document.clone();
        web_document
            .as_object_mut()
            .unwrap()
            .remove("application_type");
        let web = parse_document(id, &serde_json::to_vec(&web_document).unwrap()).unwrap();
        assert!(web.allows_redirect("http://127.0.0.1/callback"));
        assert!(!web.allows_redirect("http://127.0.0.1:52889/callback"));
        web_document["application_type"] = "web".into();
        let web = parse_document(id, &serde_json::to_vec(&web_document).unwrap()).unwrap();
        assert!(!web.allows_redirect("http://127.0.0.1:52889/callback"));
        web_document["application_type"] = "unknown".into();
        assert!(parse_document(id, &serde_json::to_vec(&web_document).unwrap()).is_err());
    }

    #[test]
    fn native_non_loopback_callbacks_still_require_exact_matching() {
        let client = Client {
            client_id: "native".into(),
            name: "Native".into(),
            cimd: true,
            application_type: ApplicationType::Native,
            redirect_uris: vec![
                "https://client.example/callback".into(),
                "http://127.0.0.1/callback?fixed=1".into(),
            ],
        };
        assert!(client.allows_redirect("https://client.example/callback"));
        assert!(!client.allows_redirect("https://client.example:52889/callback"));
        assert!(!client.allows_redirect("http://client.example:52889/callback"));
        assert!(client.allows_redirect("http://127.0.0.1:52889/callback?fixed=1"));
        assert!(!client.allows_redirect("http://127.0.0.1:52889/callback?fixed=2"));
    }

    #[test]
    fn claude_metadata_can_advertise_additional_grants() {
        let id = "https://claude.ai/oauth/mcp-oauth-client-metadata";
        let mut document = serde_json::json!({
            "client_id": id,
            "client_name": "Claude",
            "client_uri": "https://claude.ai",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        });
        let client = parse_document(id, &serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(client.allows_redirect("https://claude.ai/api/mcp/auth_callback"));
        // Extra capabilities are fine; the required authorization-code grant
        // still must be present when the document declares grant types.
        document["grant_types"] =
            serde_json::json!(["urn:ietf:params:oauth:grant-type:jwt-bearer"]);
        assert!(parse_document(id, &serde_json::to_vec(&document).unwrap()).is_err());
    }

    #[test]
    fn document_identity_redirects_and_authentication_are_checked() {
        let id = "https://client.example/client.json";
        let mut doc = serde_json::json!({"client_id":id,"client_name":"Client","redirect_uris":["https://client.example/callback"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_methods_supported":["none","private_key_jwt"]});
        assert!(parse_document(id, &serde_json::to_vec(&doc).unwrap()).is_ok());
        doc["client_id"] = "https://other.example/client.json".into();
        assert!(parse_document(id, &serde_json::to_vec(&doc).unwrap()).is_err());
        doc["client_id"] = id.into();
        doc["redirect_uris"] = serde_json::json!(["http://external.example/callback"]);
        assert!(parse_document(id, &serde_json::to_vec(&doc).unwrap()).is_err());
        doc["redirect_uris"] = serde_json::json!(["http://127.0.0.1:1234/callback"]);
        doc["token_endpoint_auth_methods_supported"] = serde_json::json!(["private_key_jwt"]);
        assert!(parse_document(id, &serde_json::to_vec(&doc).unwrap()).is_err());
    }
    #[test]
    fn unsafe_destinations_and_metadata_urls_are_rejected() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "2002:7f00:1::",
            "2001:db8::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public_ip(ip.parse().unwrap()));
        }
        for id in [
            "http://client.example/client.json",
            "https://client.example",
            "https://user@client.example/client.json",
            "https://client.example/client.json#fragment",
        ] {
            assert!(metadata_url(id).is_err());
        }
        assert_eq!(cache_ttl("max-age=10"), Duration::from_secs(10));
        assert_eq!(cache_ttl("no-store"), Duration::ZERO);
    }
}
