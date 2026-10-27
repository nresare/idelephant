use anyhow::Error;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
pub struct Config {
    pub origin: String,
    #[serde(
        default = "default_session_timeout",
        deserialize_with = "deserialize_login_duration"
    )]
    pub session_timeout: time::Duration,
    #[serde(
        default = "default_max_login_time",
        deserialize_with = "deserialize_login_duration"
    )]
    pub max_login_time: time::Duration,
    pub root_key: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    #[serde(rename = "email")]
    pub email_config: EmailConfig,
    pub persistence: PersistenceConfig,
    #[serde(default, deserialize_with = "deserialize_traces")]
    pub traces: Option<TracesConfig>,
}

pub use authzoo_server::telemetry::TracesConfig;

fn deserialize_traces<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<TracesConfig>, D::Error> {
    TracesConfig::deserialize_optional(deserializer, "idelephant")
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

fn default_max_login_time() -> time::Duration {
    time::Duration::days(30)
}

fn deserialize_login_duration<'de, D>(deserializer: D) -> Result<time::Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let duration = humantime::parse_duration(&value).map_err(serde::de::Error::custom)?;
    if duration.is_zero() || duration > std::time::Duration::from_secs(u32::MAX.into()) {
        return Err(serde::de::Error::custom(
            "login duration must be positive and at most 4294967295 seconds",
        ));
    }
    time::Duration::try_from(duration).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::Config;

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

    #[test]
    fn max_login_time_defaults_to_thirty_days() {
        assert_eq!(parse("").unwrap().max_login_time, time::Duration::days(30));
    }

    #[test]
    fn max_login_time_can_be_configured_independently() {
        let config = parse("session_timeout = '5d'\nmax_login_time = '30d'").unwrap();
        assert_eq!(config.session_timeout, time::Duration::days(5));
        assert_eq!(config.max_login_time, time::Duration::days(30));
        assert_eq!(
            parse("max_login_time = '1h 30m'").unwrap().max_login_time,
            time::Duration::minutes(90)
        );
    }

    #[test]
    fn max_login_time_rejects_invalid_values() {
        for value in ["0s", "-1h", "4294967296s", "", "forever", "10"] {
            assert!(parse(&format!("max_login_time = {value:?}")).is_err());
        }
        assert!(parse("max_login_time = 3600").is_err());
    }

    fn parse_traces(settings: &str) -> Result<Config, toml::de::Error> {
        let config = format!(
            "origin = 'http://localhost:8080'\nroot_key = 'test'\n\
             [email]\nrelay_host = 'localhost'\nsender_email = 'test@example.com'\n\
             [persistence]\nuri = 'ws://localhost:8000'\n{settings}"
        );
        toml::from_str(&config)
    }

    #[test]
    fn traces_are_optional_with_service_and_exclusion_defaults() {
        assert!(parse_traces("").unwrap().traces.is_none());
        let traces = parse_traces("[traces]\nendpoint = 'http://tempo:4317'")
            .unwrap()
            .traces
            .unwrap();
        assert_eq!(traces.service_name, "idelephant");
        assert!(traces.excluded_paths.is_empty());
        let traces = parse_traces("[traces]\nendpoint = 'https://tempo:4317'\nservice-name = 'identity'\nexcluded-paths = ['/healthz']")
            .unwrap().traces.unwrap();
        assert_eq!(traces.service_name, "identity");
        assert_eq!(traces.excluded_paths, ["/healthz"]);
    }

    #[test]
    fn traces_reject_invalid_configuration() {
        for settings in [
            "",
            "endpoint = ''",
            "endpoint = 'tempo:4317'",
            "endpoint = 'ftp://tempo:4317'",
            "endpoint = 'http://tempo:4317/v1/traces'",
            "endpoint = 'http://user:secret@tempo:4317'",
            "endpoint = 'http://tempo:4317?secret=yes'",
            "endpoint = 'http://tempo:4317#fragment'",
            "endpoint = 'http://tempo:4317'\nservice-name = '  '",
            "endpoint = 'http://tempo:4317'\nservice_name = 'typo'",
            "endpoint = 'http://tempo:4317'\nexcluded-paths = ['healthz']",
            "endpoint = 'http://tempo:4317'\nexcluded-paths = ['/healthz?query']",
            "endpoint = 'http://tempo:4317'\nexcluded-paths = ['/healthz#fragment']",
            "endpoint = 'http://tempo:4317'\nexcluded-paths = '/healthz'",
            "endpoint = 'http://tempo:4317'\nexcluded-paths = [42]",
        ] {
            assert!(
                parse_traces(&format!("[traces]\n{settings}")).is_err(),
                "{settings}"
            );
        }
    }
}
