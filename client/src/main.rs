mod auth;
mod credential;
mod register;

use crate::credential::{P256Random, SshAgentBackedCredential};
use crate::register::register_public_key;
use anyhow::anyhow;
use auth::authenticate;
use clap::{Parser, Subcommand};
use log::info;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

pub(crate) const BASE: &str = "http://localhost:8080";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command()]
    /// Invite the user with the given email to this idElephant instance
    Invite {
        #[arg()]
        email: String,
        #[arg(long = "admin", short = 'e', default_value_t = false)]
        admin: bool,
    },
    /// This functionality was used for initial testing and is now waiting for
    /// use when building the performance testing suite
    Register {
        #[arg()]
        email: String,
    },
    #[command()]
    /// Configure an OAuth/OIDC client on this idElephant instance
    RegisterClient {
        #[arg()]
        client_id: String,
        #[arg()]
        name: String,
        #[arg(long = "redirect-uri", required = true)]
        redirect_uris: Vec<String>,
        #[arg(long = "pkce-required", default_value_t = true)]
        pkce_required: bool,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new("idelephant=info"))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();
    info!("Connecting to {BASE}");
    let args = Cli::parse();

    let client = ClientBuilder::new().cookie_store(true).build()?;

    let mut credential = SshAgentBackedCredential::new()?;

    authenticate(&client, &mut credential, b"root".to_vec())?;
    info!("Successfully authenticated using the newly registered key");

    match args.command {
        Command::Invite { email, admin } => {
            info!("Inviting user with email '{}' and admin = {}", email, admin);
            invite(&client, email, admin)?;
        }
        Command::Register { email } => {
            info!("Registering user with email '{}'", email);
            let mut key = P256Random::new();
            register_public_key(&client, &mut key, &email)?;
        }
        Command::RegisterClient {
            client_id,
            name,
            redirect_uris,
            pkce_required,
        } => {
            info!("Creating OAuth client '{}'", client_id);
            create_client(
                &client,
                CreateClientRequest {
                    client_id,
                    name,
                    redirect_uris,
                    pkce_required,
                },
            )?;
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct InviteRequest {
    email: String,
    admin: bool,
}

#[derive(Serialize, Deserialize)]
struct CreateClientRequest {
    client_id: String,
    name: String,
    redirect_uris: Vec<String>,
    pkce_required: bool,
}

fn invite(client: &Client, email: String, admin: bool) -> Result<(), anyhow::Error> {
    let response = client
        .post(format!("{BASE}/invite"))
        .json(&InviteRequest { email, admin })
        .send()?;
    match response.status() {
        StatusCode::OK => Ok(()),
        code => Err(anyhow!("Failed to invite user, status: {code}")),
    }
}

fn create_client(client: &Client, request: CreateClientRequest) -> Result<(), anyhow::Error> {
    let response = client
        .post(format!("{BASE}/oauth-client"))
        .json(&request)
        .send()?;
    match response.status() {
        StatusCode::CREATED => Ok(()),
        code => Err(anyhow!("Failed to create OAuth client, status: {code}")),
    }
}
