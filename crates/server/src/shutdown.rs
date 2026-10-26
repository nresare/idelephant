use std::{future::Future, io, time::Duration};
use tracing::{info, warn};

// Leave time for process teardown within Kubernetes' 30-second grace period.
pub const GRACE_PERIOD: Duration = Duration::from_secs(25);

pub struct Signals {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
}

impl Signals {
    // Register before startup work so PID 1 can receive signals during startup too.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            #[cfg(unix)]
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
        })
    }

    pub async fn wait(mut self) {
        #[cfg(unix)]
        let signal = tokio::select! {
            _ = self.terminate.recv() => "SIGTERM",
            _ = self.interrupt.recv() => "SIGINT",
        };
        #[cfg(not(unix))]
        let signal = {
            tokio::signal::ctrl_c()
                .await
                .expect("could not listen for Ctrl-C");
            "Ctrl-C"
        };
        info!(signal, "received shutdown signal");
    }
}

pub async fn drain(
    server: impl Future<Output = io::Result<()>>,
    signal: impl Future<Output = ()>,
    begin_shutdown: impl FnOnce(),
    grace_period: Duration,
) -> io::Result<()> {
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => return result,
        () = signal => {}
    }
    info!(?grace_period, "starting graceful shutdown");
    begin_shutdown();
    match tokio::time::timeout(grace_period, server).await {
        Ok(result) => {
            result?;
            info!("graceful shutdown complete");
        }
        Err(_) => warn!("shutdown grace period expired; forcing shutdown"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use std::sync::Arc;
    use tokio::sync::{Notify, oneshot};

    async fn exercise_shutdown(tls: bool, finish_request: bool) {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let app = Router::new().route(
            "/",
            get({
                let entered = entered.clone();
                let release = release.clone();
                move || {
                    let entered = entered.clone();
                    let release = release.clone();
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        "finished"
                    }
                }
            }),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (signal_tx, signal_rx) = oneshot::channel();
        let (draining_tx, draining_rx) = oneshot::channel();
        let grace = Duration::from_millis(200);
        let server = tokio::spawn(async move {
            let signal = async {
                signal_rx.await.unwrap();
            };
            if tls {
                let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tls");
                let config = crate::tls::load(
                    &fixtures.join("cert.pem"),
                    &fixtures.join("test-only-key.pem"),
                )
                .await
                .unwrap();
                let handle = axum_server::Handle::new();
                let server = axum_server::from_tcp_rustls(listener, config)
                    .unwrap()
                    .handle(handle.clone())
                    .serve(app.into_make_service());
                drain(
                    server,
                    signal,
                    || {
                        handle.graceful_shutdown(None);
                        draining_tx.send(()).unwrap();
                    },
                    grace,
                )
                .await
            } else {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (tx, rx) = oneshot::channel();
                let server = axum::serve(listener, app).with_graceful_shutdown(async {
                    let _ = rx.await;
                });
                drain(
                    std::future::IntoFuture::into_future(server),
                    signal,
                    || {
                        tx.send(()).unwrap();
                        draining_tx.send(()).unwrap();
                    },
                    grace,
                )
                .await
            }
        });
        let mut request = tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .no_proxy()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();
            client
                .get(format!(
                    "{}://localhost:{}/",
                    if tls { "https" } else { "http" },
                    addr.port()
                ))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        });
        entered.notified().await;
        let started = std::time::Instant::now();
        signal_tx.send(()).unwrap();
        draining_rx.await.unwrap();
        assert!(
            !server.is_finished(),
            "server must wait for the active request"
        );
        if finish_request {
            release.notify_one();
            assert_eq!((&mut request).await.unwrap(), "finished");
        }
        server.await.unwrap().unwrap();
        if !finish_request {
            assert!(started.elapsed() >= grace);
            assert!(
                !request.is_finished(),
                "stuck request must not prevent shutdown"
            );
            request.abort();
        }
    }

    #[tokio::test]
    async fn http_and_https_drain_active_requests() {
        for tls in [false, true] {
            tokio::time::timeout(Duration::from_secs(5), exercise_shutdown(tls, true))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn http_and_https_bound_shutdown_for_stuck_requests() {
        for tls in [false, true] {
            tokio::time::timeout(Duration::from_secs(5), exercise_shutdown(tls, false))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn server_failure_is_preserved_without_waiting_for_signal() {
        let result = drain(
            async { Err(io::Error::other("bind failed")) },
            std::future::pending(),
            || panic!("shutdown must not start"),
            GRACE_PERIOD,
        )
        .await;
        assert_eq!(result.unwrap_err().to_string(), "bind failed");
    }
}
