use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub origin: String,
    pub db_path: String,
    pub root_key: String,
    #[serde(rename = "email")]
    pub email_config: EmailConfig,
}

#[derive(Deserialize)]
pub struct EmailConfig {
    pub relay_host: String,
    pub username: Option<String>,
    pub password_file: Option<String>,
    pub sender_email: String,
}

impl EmailConfig {
    pub fn password(&self) -> Result<Option<String>, anyhow::Error> {
        let Some(password_file) = &self.password_file else {
            return Ok(None);
        };

        let mut password = std::fs::read_to_string(password_file)?;
        let len = password.trim_end_matches(['\r', '\n']).len();
        password.truncate(len);
        Ok(Some(password))
    }
}
