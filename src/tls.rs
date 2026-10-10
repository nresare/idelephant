use crate::config::Config;
use anyhow::{bail, Context};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn file_paths(config: &Config, config_path: &Path) -> anyhow::Result<Option<(PathBuf, PathBuf)>> {
    let (cert, key) = match (&config.tls_cert_path, &config.tls_key_path) {
        (None, None) => return Ok(None),
        (Some(cert), Some(key)) if !cert.trim().is_empty() && !key.trim().is_empty() => (cert, key),
        _ => bail!("TLS requires both non-empty tls_cert_path and tls_key_path"),
    };
    let directory = config_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(Some((directory.join(cert), directory.join(key))))
}

pub async fn load(config: &Config, config_path: &Path) -> anyhow::Result<Option<RustlsConfig>> {
    let Some((cert_path, key_path)) = file_paths(config, config_path)? else {
        return Ok(None);
    };
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
    Ok(Some(RustlsConfig::from_config(Arc::new(server_config))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};

    fn config(settings: &str) -> Config {
        toml::from_str(&format!(
            "{settings}\norigin = 'https://localhost:8443'\nroot_key = 'test'\n\
             [email]\nrelay_host = 'localhost'\nsender_email = 'test@example.com'\n\
             [persistence]\nuri = 'ws://localhost:8000'\n"
        ))
        .unwrap()
    }

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tls/config.toml")
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

    #[test]
    fn validates_paired_paths() {
        for settings in [
            "tls_cert_path = 'cert.pem'",
            "tls_key_path = 'key.pem'",
            "tls_cert_path = ''\ntls_key_path = 'key.pem'",
            "tls_cert_path = 'cert.pem'\ntls_key_path = '  '",
        ] {
            let error = file_paths(&config(settings), &fixtures()).unwrap_err();
            assert!(error.to_string().contains("TLS requires both"));
        }
    }

    #[test]
    fn resolves_relative_and_absolute_paths() {
        let config = config("tls_cert_path = 'cert.pem'\ntls_key_path = '/tls/key.pem'");
        let (cert, key) = file_paths(&config, Path::new("/config/app.toml"))
            .unwrap()
            .unwrap();
        assert_eq!(cert, Path::new("/config/cert.pem"));
        assert_eq!(key, Path::new("/tls/key.pem"));
    }

    #[tokio::test]
    async fn rejects_missing_invalid_and_mismatched_files() {
        for settings in [
            "tls_cert_path = 'missing.pem'\ntls_key_path = 'test-only-key.pem'",
            "tls_cert_path = 'test-only-key.pem'\ntls_key_path = 'test-only-key.pem'",
            "tls_cert_path = 'cert.pem'\ntls_key_path = 'cert.pem'",
            "tls_cert_path = 'cert.pem'\ntls_key_path = 'other-test-only-key.pem'",
        ] {
            assert!(load(&config(settings), &fixtures()).await.is_err());
        }
    }

    #[tokio::test]
    async fn https_negotiates_http2_and_supports_http1() {
        let settings = config("tls_cert_path = 'cert.pem'\ntls_key_path = 'test-only-key.pem'");
        let tls = load(&settings, &fixtures()).await.unwrap().unwrap();
        assert_eq!(
            tls.get_inner().alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = axum_server::Handle::new();
        let server = axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .handle(handle.clone());
        let app = Router::new().route("/healthz", get(|| async { "ok" }));
        let task = tokio::spawn(server.serve(app.into_make_service()));
        handle.listening().await.unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(include_bytes!("../tests/tls/cert.pem")).unwrap())
            .unwrap();
        for http2 in [true, false] {
            let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
            client_tls.alpn_protocols = if http2 {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            } else {
                vec![b"http/1.1".to_vec()]
            };
            let client = reqwest::Client::builder()
                .use_preconfigured_tls(client_tls)
                .no_proxy()
                .timeout(std::time::Duration::from_secs(5));
            let client = if http2 {
                client.http2_prior_knowledge()
            } else {
                client.http1_only()
            }
            .build()
            .unwrap();
            let response = client
                .get(format!("https://localhost:{port}/healthz"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert_eq!(
                response.version(),
                if http2 {
                    reqwest::Version::HTTP_2
                } else {
                    reqwest::Version::HTTP_11
                }
            );
            assert_eq!(response.text().await.unwrap(), "ok");
        }
        handle.shutdown();
        task.await.unwrap().unwrap();
    }
}
