use anyhow::{Context, bail};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Resolve optional application settings; TLS is disabled only when both are absent.
pub fn file_paths(
    certificate: Option<&str>,
    private_key: Option<&str>,
    config_path: &Path,
) -> anyhow::Result<Option<(PathBuf, PathBuf)>> {
    let (cert, key) = match (certificate, private_key) {
        (None, None) => return Ok(None),
        (Some(cert), Some(key)) if !cert.trim().is_empty() && !key.trim().is_empty() => (cert, key),
        _ => bail!("TLS requires both non-empty certificate and private-key paths"),
    };
    let directory = config_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(Some((directory.join(cert), directory.join(key))))
}

/// Load a certificate chain and matching key with an explicit crypto provider and HTTP ALPN.
pub async fn load(certificate: &Path, private_key: &Path) -> anyhow::Result<RustlsConfig> {
    let cert_path = certificate.to_owned();
    let key_path = private_key.to_owned();
    let server_config = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let certs = CertificateDer::pem_file_iter(&cert_path)
            .with_context(|| format!("Could not open TLS certificate {}", cert_path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .context("Could not parse TLS certificate chain")?;
        let key = PrivateKeyDer::from_pem_file(&key_path)
            .with_context(|| format!("Could not read TLS private key {}", key_path.display()))?;
        // Select the provider explicitly: other dependencies also enable aws-lc-rs.
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Invalid TLS certificate or mismatched private key")?;
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(server_config)
    })
    .await??;
    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}
