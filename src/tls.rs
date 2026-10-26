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

#[cfg(test)]
mod tests {
    use super::*;

    fn config(settings: &str) -> Config {
        toml::from_str(&format!(
            "{settings}\norigin = 'https://localhost:8443'\nroot_key = 'test'\n\
             [email]\nrelay_host = 'localhost'\nsender_email = 'test@example.com'\n\
             [persistence]\nuri = 'ws://localhost:8000'\n"
        ))
        .unwrap()
    }

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/server/tests/tls/config.toml")
    }

    #[tokio::test]
    async fn no_tls_settings_preserves_http() {
        assert!(load(&config(""), &fixtures()).await.unwrap().is_none());
        assert_eq!(crate::listen_address(false, false).port(), 8080);
        assert_eq!(crate::listen_address(true, false).port(), 8443);
        for (enabled, port) in [(false, 8080), (true, 8443)] {
            let address = crate::listen_address(enabled, true);
            assert!(address.ip().is_loopback());
            assert_eq!(address.port(), port);
        }
    }
}
