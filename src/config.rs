use std::path::Path;
use anyhow::Error;
use serde::Deserialize;

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
    pub username: String,
    password_file: Box<Path>,
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

        let mut password = std::fs::read_to_string(password_file)?;
        let len = password.trim_end_matches(['\r', '\n']).len();
        password.truncate(len);
        Ok(Some(password))
    }
}

impl PersistenceConfig {
    pub fn password(&self) -> Result<String, Error> {
        let mut password = std::fs::read_to_string(&self.password_file)?;
        let len = password.trim_end_matches(['\r', '\n']).len();
        password.truncate(len);
        Ok(password)
    }
}
