use anyhow::Error;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
pub struct Config {
    pub origin: String,
    #[serde(
        default = "default_session_timeout",
        deserialize_with = "deserialize_session_timeout"
    )]
    pub session_timeout: time::Duration,
    pub root_key: String,
    #[serde(default)]
    pub bypass_authentication: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
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
    pub token_path: Box<Path>,
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
        read_secret_file(&self.token_path)
    }
}

fn read_secret_file(path: &Path) -> Result<String, Error> {
    let mut secret = std::fs::read_to_string(path)?;
    let len = secret.trim_end_matches(['\r', '\n']).len();
    secret.truncate(len);
    Ok(secret)
}

fn default_session_timeout() -> time::Duration {
    time::Duration::hours(1)
}

fn deserialize_session_timeout<'de, D>(deserializer: D) -> Result<time::Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let duration = humantime::parse_duration(&value).map_err(serde::de::Error::custom)?;
    if duration.is_zero() || duration > std::time::Duration::from_secs(u32::MAX.into()) {
        return Err(serde::de::Error::custom(
            "session_timeout must be positive and at most 4294967295 seconds",
        ));
    }
    time::Duration::try_from(duration).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn bypass_authentication_defaults_to_disabled_and_can_be_enabled() {
        let config = r#"
origin = "http://localhost:8080"
root_key = "test-key"

[email]
relay_host = "localhost"
sender_email = "admin@example.test"

[persistence]
uri = "ws://localhost:8001"
"#;
        let disabled: Config = toml::from_str(config).unwrap();
        assert!(!disabled.bypass_authentication);

        let enabled: Config =
            toml::from_str(&format!("bypass_authentication = true\n{config}")).unwrap();
        assert!(enabled.bypass_authentication);
    }

    fn parse(timeout: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(&format!(
            r#"origin = "http://localhost:8080"
root_key = "test"
{timeout}
[email]
relay_host = "localhost"
sender_email = "test@example.com"
[persistence]
uri = "ws://localhost:8000"
"#
        ))
    }

    #[test]
    fn session_timeout_defaults_to_one_hour() {
        assert_eq!(parse("").unwrap().session_timeout, time::Duration::hours(1));
    }

    #[test]
    fn session_timeout_can_be_configured() {
        for (value, expected) in [
            ("30s", time::Duration::seconds(30)),
            ("15 minutes", time::Duration::minutes(15)),
            ("12h", time::Duration::hours(12)),
            ("7d", time::Duration::days(7)),
            ("1h 30m", time::Duration::minutes(90)),
        ] {
            assert_eq!(
                parse(&format!("session_timeout = {value:?}"))
                    .unwrap()
                    .session_timeout,
                expected
            );
        }
    }

    #[test]
    fn session_timeout_rejects_invalid_values() {
        for value in ["0s", "-1h", "4294967296s", "", "forever", "10"] {
            assert!(parse(&format!("session_timeout = {value:?}")).is_err());
        }
        assert!(parse("session_timeout = 3600").is_err());
    }
}
