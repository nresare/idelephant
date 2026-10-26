use axum::{Router, routing::get};
use idp_server::tls::{file_paths, load};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tls")
}
#[test]
fn tls_settings_must_be_paired_and_resolve_relative_to_the_application_config() {
    let config = Path::new("/config/app.toml");
    assert!(file_paths(None, None, config).unwrap().is_none());
    assert!(file_paths(Some("cert.pem"), None, config).is_err());
    assert!(file_paths(Some(""), Some("key.pem"), config).is_err());
    assert_eq!(
        file_paths(Some("cert.pem"), Some("/keys/key.pem"), config)
            .unwrap()
            .unwrap(),
        (
            PathBuf::from("/config/cert.pem"),
            PathBuf::from("/keys/key.pem")
        )
    );
}
#[tokio::test]
async fn rejects_invalid_and_mismatched_credentials() {
    for (cert, key) in [
        ("missing.pem", "test-only-key.pem"),
        ("test-only-key.pem", "test-only-key.pem"),
        ("cert.pem", "cert.pem"),
        ("cert.pem", "other-test-only-key.pem"),
    ] {
        assert!(
            load(&fixtures().join(cert), &fixtures().join(key))
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn https_negotiates_http2_and_supports_http1() {
    let tls = load(
        &fixtures().join("cert.pem"),
        &fixtures().join("test-only-key.pem"),
    )
    .await
    .unwrap();
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
