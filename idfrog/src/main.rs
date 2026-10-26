use clap::{Parser, Subcommand};
use idfrog::{
    config::Config,
    shutdown, signing, tls,
    upstream::Upstream,
    web::{AppState, router},
};
use idp_server::telemetry;
use std::{future::IntoFuture, path::PathBuf};
use tracing::info;

#[derive(Parser)]
#[command(
    name = "idfrog",
    version,
    about = "OAuth for MCP backed by upstream OIDC single sign-on"
)]
struct Cli {
    #[arg(short, long, default_value = "idfrog.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a P-256 signing key; refuses to overwrite an existing file.
    GenerateSigningKey {
        #[arg(long)]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(Command::GenerateSigningKey { output }) = cli.command {
        signing::generate(&output)?;
        println!("Created signing key at {}", output.display());
        return Ok(());
    }
    tracing_subscriber::fmt()
        .compact()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "idfrog=info,idp_server=info,idp_oauth=warn".into()),
        )
        .init();
    let signals = shutdown::Signals::new()?;
    let config = Config::load(&cli.config)?;
    let provider = match &config.traces {
        Some(traces) => telemetry::provider(traces)?,
        None => telemetry::SdkTracerProvider::builder().build(),
    };
    let result = run_server(cli, config, signals, &provider).await;
    telemetry::shutdown(provider).await;
    result
}

async fn run_server(
    cli: Cli,
    config: Config,
    signals: shutdown::Signals,
    provider: &telemetry::SdkTracerProvider,
) -> anyhow::Result<()> {
    let signal = signals.wait();
    tokio::pin!(signal);
    let startup = async {
        let tls = tls::load(&config, &cli.config).await?;
        let key = signing::load(&config.signing_key_file)?;
        let upstream = Upstream::discover(&config).await?;
        let addr = config.listen;
        let origin = config.origin.clone();
        let traces = config.traces.clone();
        let app = router(AppState::new(config, upstream, key));
        let app = match &traces {
            Some(traces) => telemetry::instrument(app, provider, traces),
            None => app,
        };
        Ok::<_, anyhow::Error>((app, addr, origin, tls))
    };
    let (app, addr, origin, tls) = tokio::select! {
        result = startup => result?,
        () = &mut signal => { info!("shutdown complete during startup"); return Ok(()); }
    };
    info!(%addr, %origin, "idFrog is ready");
    if let Some(tls) = tls {
        let handle = axum_server::Handle::new();
        let server = axum_server::bind_rustls(addr, tls)
            .handle(handle.clone())
            .serve(app.into_make_service());
        shutdown::drain(
            server,
            &mut signal,
            || handle.graceful_shutdown(None),
            shutdown::GRACE_PERIOD,
        )
        .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = axum::serve(listener, app.into_make_service()).with_graceful_shutdown(async {
            let _ = rx.await;
        });
        shutdown::drain(
            server.into_future(),
            &mut signal,
            || {
                let _ = tx.send(());
            },
            shutdown::GRACE_PERIOD,
        )
        .await?;
    }
    Ok(())
}
