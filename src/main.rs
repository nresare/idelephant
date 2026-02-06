mod auth;
mod bytes;
mod config;
mod embed;
mod error;
mod invite;
mod persistence;
mod register;
mod root_setup;
mod util;
mod web;

use crate::auth::{auth_routes, IDENTITY};
use crate::config::Config;
use crate::error::IdentityError;
use crate::invite::{invite_routes, InviteService};
use crate::persistence::{make_db, Identity, PersistenceService};
use crate::register::register_routes;
use crate::web::Templates;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, Router};
use clap::Parser;
use embed::StaticFile;
use idelephant_common::{convert_key, ToBoxedSlice};
use serde_json::json;
use ssh_key::{HashAlg, PublicKey};
use std::borrow::Cow;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use surrealdb::engine::any::Any;
use surrealdb::Surreal;
use thiserror::Error;
use time::Duration;
use tower_http::trace;
use tower_http::trace::TraceLayer;
use tower_sessions::{Expiry, Session, SessionManagerLayer};
use tower_sessions_surrealdb_store::SurrealSessionStore;
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Cli {
    #[arg(
        name = "config-file",
        short = 'c',
        long = "config-file",
        default_value = "/etc/idelephant.toml"
    )]
    config_path: String,
}

#[derive(Error, Debug)]
enum Fatal {
    #[error("Could not read '{0}': {1}")]
    ReadConfigFile(String, anyhow::Error),
    #[error("unknown fatal error: {0}")]
    Other(#[from] anyhow::Error),
    #[error("Could not configure database: {0}")]
    DbSetup(anyhow::Error),
    #[error("Could not parser admin key: {0}")]
    AdminKey(anyhow::Error),
    #[error("Could not begin to listen to {0}: {1}")]
    Listen(SocketAddr, io::Error),
    #[error("Failed to set up email transport: {0}")]
    EmailTransport(anyhow::Error),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            "idelephant=info,tower_http=info,axum::rejection=trace",
        ))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();
    match run().await {
        Ok(()) => Ok(()),
        Err(e) => {
            error!("{}", e);
            error!("This is a fatal error. Exiting");
            std::process::exit(-1);
        }
    }
}

const ADDR: SocketAddr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3000, 0, 0));

async fn run() -> Result<(), Fatal> {
    let cli = Cli::parse();

    // tracing_subscriber::fmt()
    //     .with_target(false)
    //     .compact()
    //     .init();

    let config = std::fs::read_to_string(&cli.config_path)
        .map_err(|e| Fatal::ReadConfigFile(cli.config_path.clone(), e.into()))?;

    let config: Config =
        toml::from_str(&config).map_err(|e| Fatal::ReadConfigFile(cli.config_path, e.into()))?;

    let db = make_db(&config.persistence)
        .await
        .map_err(|e| Fatal::DbSetup(e.into()))?;
    let ps = Arc::new(PersistenceService::new(db.clone()));
    let is = Arc::new(InviteService::new(
        ps.clone(),
        &config.email_config,
        Cow::from(config.origin),
    )?);

    let key = PublicKey::from_openssh(&config.root_key).map_err(|e| Fatal::AdminKey(e.into()))?;
    let spki_bytes = convert_key(&key)?.to_boxed_slice();
    ps.configure_root_key(key.fingerprint(HashAlg::Sha256).as_bytes(), &spki_bytes)
        .await
        .map_err(|e| Fatal::AdminKey(e.into()))?;

    let templates = Arc::new(Templates::new()?);

    let state = AppState { ps, is, templates };

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/static/{*path}", get(static_handler))
        .route("/logout", get(logout_handler))
        .merge(register_routes())
        .merge(auth_routes())
        .merge(invite_routes())
        .fallback_service(get(not_found))
        .layer(make_session_layer(db))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);

    // Start listening on the given address.
    info!(?ADDR, "listening");
    let listener = tokio::net::TcpListener::bind(ADDR)
        .await
        .map_err(|e| Fatal::Listen(ADDR, e))?;
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| Fatal::Other(e.into()))?;
    Ok(())
}

fn make_session_layer(db: Surreal<Any>) -> SessionManagerLayer<SurrealSessionStore<Any>> {
    let session_store = SurrealSessionStore::new(db, "session".to_string());
    SessionManagerLayer::new(session_store)
        .with_expiry(Expiry::OnInactivity(Duration::hours(1)))
        .with_secure(false)
}

#[derive(Clone)]
struct AppState {
    ps: Arc<PersistenceService>,
    is: Arc<InviteService>,
    templates: Arc<Templates>,
}

// We use static route matchers ("/" and "/index.html") to serve our home
// page.
async fn index_handler(
    State(templates): State<Templates>,
    session: Session,
) -> Result<Html<String>, IdentityError> {
    let id: Option<Identity> = session.get(IDENTITY).await?;
    Ok(Html(templates.render("index", &json!({"identity": id}))?))
}

async fn logout_handler(session: Session) -> Result<StatusCode, IdentityError> {
    let _: Option<Identity> = session.remove(IDENTITY).await?;
    Ok(StatusCode::OK)
}

async fn static_handler(Path(path): Path<String>) -> impl IntoResponse {
    StaticFile(path)
}

async fn not_found() -> (StatusCode, Html<&'static str>) {
    (StatusCode::NOT_FOUND, Html("<h1>404</h1><p>Not Found</p>"))
}

#[cfg(test)]
mod tests {
    use crate::bytes::Bytes;

    #[test]
    fn test_serde() -> anyhow::Result<()> {
        let identity = Bytes::from(b"foo".to_vec());

        let serialized = serde_json::to_value(&identity)?;
        let deserialized: Bytes = serde_json::from_value(serialized)?;
        assert_eq!(identity, deserialized);
        Ok(())
    }
}
