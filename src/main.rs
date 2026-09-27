mod auth;
mod config;
mod embed;
mod error;
mod groups;
mod idmouse;
mod invite;
mod later;
mod oauth;
mod oidc;
mod persistence;
mod register;
mod root_setup;
mod util;
mod web;

use crate::auth::{auth_routes, IDENTITY};
use crate::config::Config;
use crate::error::IdentityError;
use crate::invite::{invite_routes, InviteService};
use crate::later::LaterService;
use crate::oauth::{oauth_routes, PENDING_AUTHORIZATION};
use crate::oidc::OidcService;
use crate::persistence::{make_db, Identity, PersistenceService};
use crate::register::{register_routes, RegistrationService};
use crate::web::Templates;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, Router};
use clap::Parser;
use embed::StaticFile;
use idelephant_common::{convert_key, ToBoxedSlice};
use serde::Deserialize;
use serde_json::json;
use ssh_key::HashAlg;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use surrealdb::engine::any::Any;
use surrealdb::Surreal;
use thiserror::Error;
use time::Duration;
use tower_http::trace;
use tower_http::trace::TraceLayer;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, Session, SessionManagerLayer};
use tower_sessions_surrealdb_store::SurrealSessionStore;
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use url::{Host, Url};

#[derive(Parser)]
struct Cli {
    #[arg(
        name = "config-file",
        short = 'c',
        long = "config-file",
        default_value = "/etc/idelephant.toml"
    )]
    config_path: String,
    #[arg(
        long,
        help = "Enable local-only login with /?user=<identity ID or email>"
    )]
    bypass_authentication: bool,
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
    #[error("--bypass-authentication requires a loopback origin in the config file")]
    BypassRequiresLoopbackOrigin,
    #[error("--bypass-authentication requires a loopback database URI in the config file")]
    BypassRequiresLoopbackDatabase,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("idelephant=debug,tower_http=info,axum::rejection=debug")
    });

    tracing_subscriber::registry()
        .with(env_filter)
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

const ADDR: SocketAddr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 8080, 0, 0));

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
    if cli.bypass_authentication && !is_loopback_url(&config.origin) {
        return Err(Fatal::BypassRequiresLoopbackOrigin);
    }
    if cli.bypass_authentication && !is_loopback_url(&config.persistence.uri) {
        return Err(Fatal::BypassRequiresLoopbackDatabase);
    }

    let later = LaterService::new();
    let db = make_db(&config.persistence, later)
        .await
        .map_err(|e| Fatal::DbSetup(e.into()))?;

    let session_layer = make_session_layer(db.clone());
    let state = build_app_state(&config, db, cli.bypass_authentication).await?;

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/admin/apps", get(admin_apps_handler))
        .route("/admin/groups", get(admin_groups_handler))
        .route("/healthz", get(healthz_handler))
        .route("/static/{*path}", get(static_handler))
        .route("/logout", get(logout_handler))
        .merge(register_routes())
        .merge(auth_routes())
        .merge(invite_routes())
        .merge(oauth_routes())
        .merge(groups::group_routes())
        .fallback_service(get(not_found))
        .layer(session_layer)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);

    let addr = if cli.bypass_authentication {
        SocketAddr::from(([127, 0, 0, 1], 8080))
    } else {
        ADDR
    };
    info!(
        ?addr,
        bypass_authentication = cli.bypass_authentication,
        "listening"
    );
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Fatal::Listen(addr, e))?;
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| Fatal::Other(e.into()))?;
    Ok(())
}

fn is_loopback_url(origin: &str) -> bool {
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    match url.host() {
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

async fn build_app_state(
    config: &Config,
    db: Arc<Surreal<Any>>,
    bypass_authentication: bool,
) -> Result<AppState, Fatal> {
    let ps = Arc::new(PersistenceService::new(db));
    let rs = Arc::new(
        RegistrationService::new(&config.origin)
            .map_err(|e| Fatal::ReadConfigFile("Failed to parse origin".to_string(), e.into()))?,
    );
    let is = Arc::new(InviteService::new(
        ps.clone(),
        &config.email_config,
        &config.origin,
    )?);

    let key = zqlu::parse(&config.root_key).map_err(|e| Fatal::AdminKey(e.into()))?;
    let spki_bytes = convert_key(&key)?.to_boxed_slice();
    ps.configure_root_key(key.fingerprint(HashAlg::Sha256).as_bytes(), &spki_bytes)
        .await
        .map_err(|e| Fatal::AdminKey(e.into()))?;

    let templates = Arc::new(Templates::new()?);
    let oidc = Arc::new(OidcService::new(&config.origin, ps.as_ref().clone()));

    let state = AppState {
        ps,
        is,
        templates,
        oidc,
        rs,
        bypass_authentication,
    };
    Ok(state)
}

fn make_session_layer(db: Arc<Surreal<Any>>) -> SessionManagerLayer<SurrealSessionStore<Any>> {
    let session_store = SurrealSessionStore::new(db, "sessions".to_string());
    SessionManagerLayer::new(session_store)
        .with_expiry(Expiry::OnInactivity(Duration::hours(1)))
        .with_same_site(SameSite::Lax)
        .with_secure(false)
}

#[derive(Clone)]
struct AppState {
    ps: Arc<PersistenceService>,
    is: Arc<InviteService>,
    templates: Arc<Templates>,
    oidc: Arc<OidcService>,
    rs: Arc<RegistrationService>,
    bypass_authentication: bool,
}

// We use static route matchers ("/" and "/index.html") to serve our home
// page.
#[derive(Deserialize)]
struct IndexQuery {
    user: Option<String>,
}

async fn index_handler(
    State(state): State<AppState>,
    Query(query): Query<IndexQuery>,
    session: Session,
) -> Result<Response, IdentityError> {
    if let Some(user) = query.user {
        if !state.bypass_authentication {
            return Err(IdentityError::Unauthorized(
                "URL login is disabled".to_string(),
            ));
        }
        let user = user.trim();
        if user.is_empty() {
            return Err(IdentityError::BadRequest(
                "user must not be empty".to_string(),
            ));
        }
        let id = user.strip_prefix("identity:").unwrap_or(user);
        let identity = match state.ps.fetch_identity(id).await? {
            Some(identity) => Some(identity),
            None => state.ps.fetch_identity_by_email(user).await?,
        };
        let identity = match identity {
            Some(identity) => identity,
            None if user.contains('@')
                && !user.chars().any(char::is_whitespace)
                && user.len() <= 254 =>
            {
                state.ps.create_development_identity(user).await?
            }
            None => return Err(IdentityError::Unauthorized("Unknown user".to_string())),
        };
        if !matches!(identity.state, persistence::IdentityState::Active { .. }) {
            return Err(IdentityError::Unauthorized(
                "User is not active".to_string(),
            ));
        }
        session.insert(IDENTITY, &identity).await?;
        let pending_authorization = session
            .get::<serde_json::Value>(PENDING_AUTHORIZATION)
            .await?
            .is_some();
        return Ok(Redirect::to(if pending_authorization {
            "/authorize/resume"
        } else {
            "/"
        })
        .into_response());
    }
    let id: Option<Identity> = session.get(IDENTITY).await?;
    let pending_authorization: bool = session
        .get::<serde_json::Value>(PENDING_AUTHORIZATION)
        .await?
        .is_some();
    Ok(Html(state.templates.render(
        "index",
        &json!({"identity": id, "admin": oauth::current_admin(&session, &state.ps).await?, "pending_authorization": pending_authorization, "bypass_authentication": state.bypass_authentication}),
    )?).into_response())
}

async fn admin_page(
    page: &str,
    session: Session,
    ps: PersistenceService,
    templates: Templates,
) -> Result<Html<String>, IdentityError> {
    if !oauth::current_admin(&session, &ps).await? {
        return Err(IdentityError::Unauthorized(
            "An active admin login is required".to_string(),
        ));
    }
    let identity: Option<Identity> = session.get(IDENTITY).await?;
    Ok(Html(
        templates.render(page, &json!({ "identity": identity }))?,
    ))
}

async fn admin_apps_handler(
    State(ps): State<PersistenceService>,
    State(templates): State<Templates>,
    session: Session,
) -> Result<Html<String>, IdentityError> {
    admin_page("apps", session, ps, templates).await
}

async fn admin_groups_handler(
    State(ps): State<PersistenceService>,
    State(templates): State<Templates>,
    session: Session,
) -> Result<Html<String>, IdentityError> {
    admin_page("groups", session, ps, templates).await
}

async fn logout_handler(session: Session) -> Result<StatusCode, IdentityError> {
    let _: Option<Identity> = session.remove(IDENTITY).await?;
    Ok(StatusCode::OK)
}

async fn healthz_handler(
    State(persistence_service): State<PersistenceService>,
) -> Result<StatusCode, IdentityError> {
    persistence_service.check_health().await?;
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
    use super::{healthz_handler, index_handler, is_loopback_url, AppState};
    use crate::config::EmailConfig;
    use crate::invite::InviteService;
    use crate::oidc::OidcService;
    use crate::persistence::{mem_db, Credential, Identity, IdentityState, PersistenceService};
    use crate::register::RegistrationService;
    use crate::web::Templates;
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use chrono::Utc;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_reads_from_database() -> anyhow::Result<()> {
        let db = mem_db().await?;
        let persistence = Arc::new(PersistenceService::new(db));
        let state = AppState {
            ps: persistence.clone(),
            is: Arc::new(InviteService::new(
                persistence.clone(),
                &EmailConfig {
                    relay_host: "localhost".to_string(),
                    username: None,
                    password_file: None,
                    sender_email: "test@example.com".to_string(),
                },
                "http://localhost:8080",
            )?),
            templates: Arc::new(Templates::new()?),
            oidc: Arc::new(OidcService::new(
                "http://localhost:8080",
                persistence.as_ref().clone(),
            )),
            rs: Arc::new(RegistrationService::new("http://localhost:8080")?),
            bypass_authentication: false,
        };
        let app = Router::new()
            .route("/healthz", get(healthz_handler))
            .with_state(state);

        let response = app
            .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[test]
    fn bypass_authentication_only_accepts_loopback_urls() {
        assert!(is_loopback_url("http://localhost:8080"));
        assert!(is_loopback_url("http://127.0.0.1:8080"));
        assert!(is_loopback_url("http://[::1]:8080"));
        assert!(!is_loopback_url("https://example.com"));
        assert!(!is_loopback_url("http://192.168.1.2:8080"));
    }

    #[tokio::test]
    async fn url_login_requires_flag_and_can_create_local_user() -> anyhow::Result<()> {
        let db = mem_db().await?;
        let ps = Arc::new(PersistenceService::new(db.clone()));
        ps.persist_identity_with_id(
            "root",
            Identity {
                email: "root_user".to_string(),
                created: Utc::now(),
                admin: true,
                id: None,
                state: IdentityState::Active {
                    credentials: vec![Credential::new(b"id", b"key", -7, 0)],
                },
            },
        )
        .await?;
        let state = AppState {
            ps: ps.clone(),
            is: Arc::new(InviteService::new(
                ps.clone(),
                &EmailConfig {
                    relay_host: "localhost".to_string(),
                    username: None,
                    password_file: None,
                    sender_email: "test@example.com".to_string(),
                },
                "http://localhost:8080",
            )?),
            templates: Arc::new(Templates::new()?),
            oidc: Arc::new(OidcService::new(
                "http://localhost:8080",
                ps.as_ref().clone(),
            )),
            rs: Arc::new(RegistrationService::new("http://localhost:8080")?),
            bypass_authentication: false,
        };
        let make_app = |state: AppState| {
            Router::new()
                .route("/", get(index_handler))
                .layer(super::make_session_layer(db.clone()))
                .with_state(state)
        };
        let disabled = make_app(state.clone());
        let response = disabled
            .oneshot(Request::builder().uri("/?user=root").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let enabled = make_app(AppState {
            bypass_authentication: true,
            ..state
        });
        let root_login = enabled
            .clone()
            .oneshot(Request::builder().uri("/?user=root").body(Body::empty())?)
            .await?;
        assert_eq!(root_login.status(), StatusCode::SEE_OTHER);
        assert_eq!(root_login.headers()[header::LOCATION], "/");
        let cookie = root_login.headers()[header::SET_COOKIE]
            .to_str()?
            .split(';')
            .next()
            .unwrap();
        let admin_page = enabled
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(admin_page.status(), StatusCode::OK);
        let admin_html =
            String::from_utf8(to_bytes(admin_page.into_body(), usize::MAX).await?.to_vec())?;
        assert!(admin_html.contains("id=\"app-form\""));

        let user_login = enabled
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/?user=alice%40example.test")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(user_login.status(), StatusCode::SEE_OTHER);
        let alice = ps
            .fetch_identity_by_email("alice@example.test")
            .await?
            .unwrap();
        assert!(!alice.admin);
        assert!(matches!(alice.state, IdentityState::Active { .. }));
        let cookie = user_login.headers()[header::SET_COOKIE]
            .to_str()?
            .split(';')
            .next()
            .unwrap();
        let denied = enabled
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(denied.status(), StatusCode::OK);
        let user_html =
            String::from_utf8(to_bytes(denied.into_body(), usize::MAX).await?.to_vec())?;
        assert!(!user_html.contains("id=\"app-form\""));
        Ok(())
    }
}
