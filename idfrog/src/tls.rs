//! Application configuration adapter for the shared TLS loader.
use crate::config::Config;
use axum_server::tls_rustls::RustlsConfig;
use std::path::{Path, PathBuf};

fn file_paths(config: &Config, config_path: &Path) -> anyhow::Result<Option<(PathBuf, PathBuf)>> {
    idp_server::tls::file_paths(
        config.tls_cert_path.as_deref(),
        config.tls_key_path.as_deref(),
        config_path,
    )
}

pub async fn load(config: &Config, config_path: &Path) -> anyhow::Result<Option<RustlsConfig>> {
    match file_paths(config, config_path)? {
        Some((cert, key)) => Ok(Some(idp_server::tls::load(&cert, &key).await?)),
        None => Ok(None),
    }
}
