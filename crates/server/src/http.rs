//! HTTP diagnostics without OAuth query parameters, headers, or bodies.
use axum::{extract::Request, middleware::Next, response::Response};
use std::time::Instant;
use tracing::Instrument;

pub async fn request(request: Request, next: Next) -> Response {
    let span = tracing::info_span!(
        "request",
        method = %request.method(),
        path = %request.uri().path(),
    );
    async move {
        let started = Instant::now();
        let response = next.run(request).await;
        tracing::info!(
            status = response.status().as_u16(),
            latency_ms = started.elapsed().as_millis(),
        );
        response
    }
    .instrument(span)
    .await
}
