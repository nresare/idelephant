use anyhow::{Context, bail};
use idp_oauth::client_metadata::{ApplicationType, Client, ClientRegistry, valid_redirect};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
use url::Url;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub origin: String,
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub signing_key_file: PathBuf,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub upstream: UpstreamConfig,
    #[serde(rename = "resource")]
    pub resources: Vec<Resource>,
    #[serde(default, deserialize_with = "deserialize_traces")]
    pub traces: Option<TracesConfig>,
    #[serde(default)]
    pub clients: Vec<RegisteredClient>,
    #[serde(default)]
    pub state: StateConfig,
}

/// Where grant state lives. DynamoDB requires the `dynamodb` build feature.
#[derive(Clone, Deserialize)]
#[serde(
    tag = "backend",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    deny_unknown_fields
)]
pub enum StateConfig {
    // A struct variant, so that deny_unknown_fields applies to it.
    Memory {},
    Dynamodb {
        table: String,
        region: Option<String>,
        endpoint_url: Option<String>,
    },
}

impl Default for StateConfig {
    fn default() -> Self {
        Self::Memory {}
    }
}

pub use idp_server::telemetry::TracesConfig;

fn deserialize_traces<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<TracesConfig>, D::Error> {
    TracesConfig::deserialize_optional(deserializer, "idfrog")
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct UpstreamConfig {
    pub issuer: String,
    pub client_id: String,
    pub authentication: AuthenticationConfig,
}

/// An MCP resource backed by an Entra API application registration.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Resource {
    pub uri: String,
    pub application_id: String,
}

impl Resource {
    pub fn scope_prefix(&self) -> String {
        format!("api://{}/", self.application_id)
    }
    pub fn default_scope(&self) -> String {
        format!("{}.default", self.scope_prefix())
    }
}

/// Authentication of idFrog to its upstream OIDC provider.
#[derive(Clone, Deserialize)]
#[serde(
    tag = "method",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    deny_unknown_fields
)]
pub enum AuthenticationConfig {
    ClientSecretPost {
        client_secret_file: PathBuf,
    },
    PrivateKeyJwt {
        certificate_file: PathBuf,
        private_key_file: PathBuf,
    },
}

impl AuthenticationConfig {
    fn resolve_paths(&mut self, directory: &Path) {
        match self {
            Self::ClientSecretPost { client_secret_file } => {
                *client_secret_file = directory.join(&*client_secret_file)
            }
            Self::PrivateKeyJwt {
                certificate_file,
                private_key_file,
            } => {
                *certificate_file = directory.join(&*certificate_file);
                *private_key_file = directory.join(&*private_key_file);
            }
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RegisteredClient {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub native: bool,
}

fn default_listen() -> SocketAddr {
    ([0, 0, 0, 0], 8080).into()
}

/// HTTPS in deployments; HTTP is permitted only for loopback development.
pub fn validate_endpoint(value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value).context("Expected an absolute HTTP(S) URL")?;
    let loopback = match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
    {
        bail!(
            "Use an HTTPS URL without credentials, query, or fragment (HTTP is allowed on loopback only)"
        );
    }
    Ok(url)
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let mut config: Self = toml::from_str(&std::fs::read_to_string(path)?)
            .context("Invalid idFrog configuration")?;
        let directory = path.parent().unwrap_or(Path::new("."));
        config.signing_key_file = directory.join(&config.signing_key_file);
        config.upstream.authentication.resolve_paths(directory);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&mut self) -> anyhow::Result<()> {
        let origin = validate_endpoint(&self.origin)?;
        if origin.path() != "/" {
            bail!("origin must not contain a path");
        }
        self.origin = self.origin.trim_end_matches('/').into();
        let issuer = validate_endpoint(&self.upstream.issuer)?;
        if issuer.host_str() == Some("login.microsoftonline.com")
            && issuer.path_segments().is_some_and(|mut parts| {
                matches!(parts.next(), Some("common" | "organizations" | "consumers"))
            })
        {
            bail!("Use a tenant-specific Entra issuer, not common, organizations, or consumers");
        }
        if self.upstream.client_id.trim().is_empty() {
            bail!("upstream.client-id must not be empty");
        }
        if self.resources.is_empty() {
            bail!("Configure at least one MCP resource");
        }
        let mut resource_uris = std::collections::HashSet::new();
        for resource in &mut self.resources {
            let url = validate_endpoint(&resource.uri)?;
            if url.scheme() != "https" || !resource_uris.insert(resource.uri.clone()) {
                bail!("Each resource.uri must be a unique HTTPS URL");
            }
            let id = resource.application_id.as_bytes();
            if id.len() != 36
                || !id.iter().enumerate().all(|(index, byte)| {
                    if [8, 13, 18, 23].contains(&index) {
                        *byte == b'-'
                    } else {
                        byte.is_ascii_hexdigit()
                    }
                })
            {
                bail!("resource.application-id must be an application UUID");
            }
            resource.application_id.make_ascii_lowercase();
        }
        let mut ids = std::collections::HashSet::new();
        for client in &self.clients {
            if client.client_id.is_empty()
                || client.name.trim().is_empty()
                || client.redirect_uris.is_empty()
                || !ids.insert(&client.client_id)
                || client.redirect_uris.iter().any(|uri| !valid_redirect(uri))
            {
                bail!(
                    "Registered clients need a unique non-empty client_id, name, and valid redirect_uris"
                );
            }
        }
        if let StateConfig::Dynamodb { table, .. } = &self.state
            && table.trim().is_empty()
        {
            bail!("state.table must not be empty");
        }
        if self.tls_cert_path.is_some() != self.tls_key_path.is_some() {
            bail!("Configure both tls-cert-path and tls-key-path");
        }
        Ok(())
    }
}

impl ClientRegistry for Config {
    type Error = std::convert::Infallible;
    async fn find_client(&self, id: &str) -> Result<Option<Client>, Self::Error> {
        Ok(self
            .clients
            .iter()
            .find(|c| c.client_id == id)
            .map(|c| Client {
                client_id: c.client_id.clone(),
                name: c.name.clone(),
                redirect_uris: c.redirect_uris.clone(),
                cimd: false,
                application_type: if c.native {
                    ApplicationType::Native
                } else {
                    ApplicationType::Web
                },
            }))
    }
}
