mod auth;
mod embed;
mod error;
mod persistence;
mod register;
mod util;

use crate::auth::auth_routes;
use crate::persistence::{make_db, PersistenceService};
use crate::register::register_routes;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, Router};
use embed::StaticFile;
use std::net::{Ipv6Addr, SocketAddr};
use surrealdb::engine::local::Db;
use surrealdb::Surreal;
use time::Duration;
use tower_http::trace;
use tower_http::trace::TraceLayer;
use tower_sessions::{Expiry, SessionManagerLayer};
use tower_sessions_surrealdb_store::SurrealSessionStore;
use tracing::info;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing_subscriber::fmt()
    //     .with_target(false)
    //     .compact()
    //     .init();
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            "idelephant=info,tower_http=info,axum::rejection=trace",
        ))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();

    let db = make_db(std::path::Path::new("/tmp/db")).await?;
    let ps = PersistenceService::new(db.clone());
    let state = AppState { ps: ps.clone() };

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/static/{*path}", get(static_handler))
        .merge(register_routes())
        .merge(auth_routes())
        .fallback_service(get(not_found))
        .layer(make_session_layer(db))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);

    // Start listening on the given address.
    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 3000));
    info!(?addr, "listening");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

fn make_session_layer(db: Surreal<Db>) -> SessionManagerLayer<SurrealSessionStore<Db>> {
    let session_store = SurrealSessionStore::new(db, "session".to_string());
    SessionManagerLayer::new(session_store)
        .with_expiry(Expiry::OnInactivity(Duration::hours(1)))
        .with_secure(false)
}

#[derive(Clone)]
struct AppState {
    ps: PersistenceService,
}

// We use static route matchers ("/" and "/index.html") to serve our home
// page.
async fn index_handler() -> impl IntoResponse {
    StaticFile("index.html")
}

async fn static_handler(Path(path): Path<String>) -> impl IntoResponse {
    StaticFile(path)
}

async fn not_found() -> (StatusCode, Html<&'static str>) {
    (StatusCode::NOT_FOUND, Html("<h1>404</h1><p>Not Found</p>"))
}
