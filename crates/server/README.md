# idp-server

HTTP infrastructure shared by idElephant and idFrog. This crate has no dependency
on an identity provider, user directory, database, or application configuration.

- `http::request` emits one completion event with method, path, status and latency.
  It omits request IDs, query strings, headers, and bodies. Handler diagnostics
  share the method/path span. Enable `idp_server=info` in the tracing filter and use
  a compact formatter with targets disabled.
- The optional `telemetry` feature provides shared OTLP/gRPC export, validated
  configuration, W3C context propagation, safe HTTP spans and shutdown flushing.
  Applications select their default service name and when to enable exporting.
- `tls::file_paths` validates optional certificate settings and resolves paths
  relative to a configuration file. `tls::load` accepts required certificate and
  key paths, validates their match, selects the ring crypto provider explicitly,
  and enables HTTP/2 and HTTP/1.1 through ALPN.
- `shutdown::Signals` registers process signals before startup, while
  `shutdown::drain` bounds graceful shutdown of an application-supplied server.
  Applications decide when to start draining and how to retain configuration.

The crate does not install routes, choose a listening address, initialize tracing,
reload certificates, or own application state.

```rust,no_run
use axum::{routing::get, Router};
let app: Router = Router::new()
    .route("/healthz", get(|| async { "ok" }))
    .layer(axum::middleware::from_fn(idp_server::http::request));
```

Run `cargo test -p idp-server` from the repository root. TLS and graceful-shutdown
tests use public localhost certificate fixtures and require loopback sockets.
