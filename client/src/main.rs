mod auth;
mod credential;
mod register;

use crate::credential::{Credential, P256Random, SshAgentBackedCredential};
use auth::authenticate;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use clap::Parser;
use log::info;
use rand::random;
use reqwest::blocking::ClientBuilder;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

pub(crate) const BASE: &str = "http://localhost:3000";

#[derive(Parser)]
struct Cli {
    #[arg(short = 'a', long = "agent")]
    agent: bool,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new("idelephant=info"))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();
    info!("Connecting to {BASE}");
    let args = Cli::parse();

    let client = ClientBuilder::new().cookie_store(true).build()?;

    let credential: &mut dyn Credential = match args.agent {
        true => &mut SshAgentBackedCredential::new()?,
        false => &mut P256Random::new(),
    };
    let email = make_random_email();

    let user_id = register::register_public_key(&client, credential, &email)?;

    authenticate(&client, credential, user_id)?;
    info!("Successfully authenticated using the newly registered key");
    Ok(())
}

fn make_random_email() -> String {
    let bytes: [u8; 8] = random();
    format!("{}@example.com", STANDARD_NO_PAD.encode(bytes))
}
