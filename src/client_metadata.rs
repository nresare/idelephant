//! Resolve pre-registered clients and public clients identified by HTTPS metadata.
use crate::error::IdentityError;
use crate::persistence::{OAuthClient, PersistenceService};
use serde::Deserialize;
use std::collections::HashMap;
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

impl From<OAuthClient> for Client {
    fn from(client: OAuthClient) -> Self {
        Self {
            client_id: client.client_id,
            name: client.name,
            redirect_uris: client.redirect_uris,
            cimd: false,
            application_type: ApplicationType::Web,
        }
    }
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

fn invalid() -> IdentityError {
    IdentityError::OAuth("invalid_client")
}

impl ClientMetadataService {
    #[cfg(test)]
    pub(crate) async fn cache_document(&self, id: &str, bytes: &[u8]) -> Result<(), IdentityError> {
        metadata_url(id)?;
        let client = parse_document(id, bytes)?;
        self.cache.lock().await.insert(
            id.into(),
            (Instant::now() + Duration::from_secs(300), client),
        );
        Ok(())
    }

    pub async fn resolve(
        &self,
        persistence: &PersistenceService,
        id: &str,
    ) -> Result<Client, IdentityError> {
        if let Some(client) = persistence.fetch_oauth_client(id).await? {
            return Ok(client.into());
        }
        let url = metadata_url(id)?;
        if let Some((expiry, client)) = self.cache.lock().await.get(id) {
            if *expiry > Instant::now() {
                return Ok(client.clone());
            }
        }
        // Resolve once, reject every non-public address, and pin these addresses to
        // the HTTP request. Disable proxies and redirects to avoid bypasses.
        let host = url.host_str().ok_or_else(invalid)?;
        let addresses: Vec<SocketAddr> = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((
                host.trim_matches(['[', ']']),
                url.port_or_known_default().unwrap_or(443),
            )),
        )
        .await
        .map_err(|_| invalid())?
        .map_err(|_| invalid())?
        .collect();
        if addresses.is_empty() || addresses.iter().any(|a| !public_ip(a.ip())) {
            return Err(invalid());
        }
        let http = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| invalid())?;
        let mut response = http
            .get(url.clone())
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|_| invalid())?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|n| n > MAX_DOCUMENT_BYTES as u64)
        {
            return Err(invalid());
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
        while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
            if bytes.len() + chunk.len() > MAX_DOCUMENT_BYTES {
                return Err(invalid());
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

fn metadata_url(id: &str) -> Result<Url, IdentityError> {
    let url = Url::parse(id).map_err(|_| invalid())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.path() == "/"
        || url.fragment().is_some()
        || url.query().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid());
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

fn parse_document(id: &str, bytes: &[u8]) -> Result<Client, IdentityError> {
    let doc: Document = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let supports_none = match doc.token_endpoint_auth_methods_supported {
        Some(methods) => methods.iter().any(|m| m == "none"),
        None => doc.token_endpoint_auth_method.as_deref().unwrap_or("none") == "none",
    };
    if doc.client_id != id
        || doc.client_name.trim().is_empty()
        || doc.client_name.len() > 256
        || doc.redirect_uris.is_empty()
        || doc.redirect_uris.len() > 32
        || doc.redirect_uris.iter().any(|u| !valid_redirect(u))
        || !supports_none
        || doc.grant_types.is_some_and(|g| {
            !g.iter().any(|s| s == "authorization_code")
                || g.iter()
                    .any(|s| s != "authorization_code" && s != "refresh_token")
        })
        || doc.response_types.is_some_and(|r| r != ["code"])
    {
        return Err(invalid());
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
