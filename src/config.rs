use anyhow::Error;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
pub struct Config {
    pub origin: String,
    pub root_key: String,
    #[serde(rename = "email")]
    pub email_config: EmailConfig,
    pub persistence: PersistenceConfig,
}

#[derive(Deserialize)]
pub struct PersistenceConfig {
    pub uri: String,
    pub username: Option<String>,
    password_file: Option<Box<Path>>,
    pub idmouse: Option<IdmouseConfig>,
}

#[derive(Clone, Deserialize)]
pub struct IdmouseConfig {
    pub url: String,
    pub(crate) bearer_token_file: Box<Path>,
}

#[derive(Deserialize)]
pub struct EmailConfig {
    pub relay_host: String,
    pub username: Option<String>,
    pub password_file: Option<String>,
    pub sender_email: String,
}

impl EmailConfig {
    pub fn password(&self) -> Result<Option<String>, Error> {
        let Some(password_file) = &self.password_file else {
            return Ok(None);
        };

        Ok(Some(read_secret_file(Path::new(password_file))?))
    }
}

impl PersistenceConfig {
    pub fn password(&self) -> Result<String, Error> {
        let Some(password_file) = self.password_file.as_deref() else {
            return Err(anyhow::anyhow!(
                "Missing persistence.password_file and no idmouse config was provided"
            ));
        };

        read_secret_file(password_file)
    }

    pub fn username(&self) -> Result<String, Error> {
        self.username.clone().ok_or_else(|| {
            anyhow::anyhow!("Missing persistence.username and no idmouse config was provided")
        })
    }
}

impl IdmouseConfig {
    pub fn bearer_token(&self) -> Result<String, Error> {
        read_secret_file(&self.bearer_token_file)
    }
}

fn read_secret_file(path: &Path) -> Result<String, Error> {
    let mut secret = std::fs::read_to_string(path)?;
    let len = secret.trim_end_matches(['\r', '\n']).len();
    secret.truncate(len);
    Ok(secret)
}
