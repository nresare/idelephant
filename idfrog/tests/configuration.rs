use idfrog::{
    config::{AuthenticationConfig, Config, StateConfig, validate_endpoint},
    signing,
    state::random_token,
};
use std::{path::PathBuf, process::Command};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("idfrog-config-{}", random_token()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn example_loads_with_paths_relative_to_configuration_and_secrets_stay_out_of_config() {
    let directory = Directory::new();
    let config_path = directory.0.join("idfrog.toml");
    std::fs::write(&config_path, include_str!("../idfrog.example.toml")).unwrap();
    let config = Config::load(&config_path).unwrap();
    assert_eq!(config.origin, "https://idfrog.noa.re");
    assert_eq!(config.signing_key_file, directory.0.join("signing-key.pem"));
    let AuthenticationConfig::PrivateKeyJwt {
        certificate_file,
        private_key_file,
    } = config.upstream.authentication
    else {
        panic!("Example should use certificate authentication");
    };
    assert_eq!(
        certificate_file,
        PathBuf::from("/var/run/idfrog/entra/tls.crt")
    );
    assert_eq!(
        private_key_file,
        PathBuf::from("/var/run/idfrog/entra/tls.key")
    );
    assert!(config.clients.is_empty());
    assert_eq!(config.resources.len(), 1);
    assert_eq!(config.resources[0].uri, "https://tools.example.com/mcp");
    assert_eq!(
        config.resources[0].default_scope(),
        "api://0816f759-d89d-4319-a8d7-d88b5d751dc9/.default"
    );
}

#[test]
fn unsafe_endpoints_ambiguous_tenants_and_incomplete_configuration_are_rejected() {
    for bad in [
        "http://idfrog.example",
        "https://user:secret@example.com",
        "https://example.com?token=secret",
        "https://example.com/#fragment",
        "ftp://example.com",
    ] {
        assert!(validate_endpoint(bad).is_err());
    }
    for valid in [
        "https://idfrog.noa.re",
        "http://localhost:8081",
        "http://127.0.0.1:8081",
        "http://[::1]:8081",
    ] {
        assert!(validate_endpoint(valid).is_ok());
    }
    let original = include_str!("../idfrog.example.toml");
    for variant in [
        original.replace("YOUR-TENANT-ID", "common"),
        original.replace("YOUR-TENANT-ID", "organizations"),
        original.replace("https://idfrog.noa.re", "https://idfrog.noa.re/subpath"),
        original.replace(
            "https://tools.example.com/mcp",
            "http://tools.example.com/mcp",
        ),
        format!("tls-cert-path = 'cert.pem'\n{original}"),
    ] {
        let mut config: Config = toml::from_str(&variant).unwrap();
        assert!(config.validate().is_err());
    }
    assert!(toml::from_str::<Config>(&format!("unknown_setting = true\n{original}")).is_err());
}

#[test]
fn key_cli_creates_a_persistent_private_key_and_refuses_overwrite() {
    let directory = Directory::new();
    let path = directory.0.join("key.pem");
    let status = Command::new(env!("CARGO_BIN_EXE_idfrog"))
        .args(["generate-signing-key", "--output"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(status.status.success());
    let first = std::fs::read(&path).unwrap();
    let key = signing::load(&path).unwrap().public_jwk();
    assert_eq!(key.kid, signing::load(&path).unwrap().public_jwk().kid);
    assert_eq!(key.alg, "ES256");
    let status = Command::new(env!("CARGO_BIN_EXE_idfrog"))
        .args(["generate-signing-key", "--output"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!status.status.success());
    assert_eq!(first, std::fs::read(&path).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn authentication_configuration_is_explicit_and_resolves_each_credential_path() {
    let directory = Directory::new();
    let path = directory.0.join("idfrog.toml");
    let original = include_str!("../idfrog.example.toml");
    let certificate = original
        .replace("/var/run/idfrog/entra/tls.crt", "entra/tls.crt")
        .replace("/var/run/idfrog/entra/tls.key", "entra/tls.key");
    std::fs::write(&path, &certificate).unwrap();
    let config = Config::load(&path).unwrap();
    let AuthenticationConfig::PrivateKeyJwt {
        certificate_file,
        private_key_file,
    } = config.upstream.authentication
    else {
        panic!("Expected certificate authentication");
    };
    assert_eq!(certificate_file, directory.0.join("entra/tls.crt"));
    assert_eq!(private_key_file, directory.0.join("entra/tls.key"));
    let secret = original.replace("method = \"private-key-jwt\"\ncertificate-file = \"/var/run/idfrog/entra/tls.crt\"\nprivate-key-file = \"/var/run/idfrog/entra/tls.key\"",
        "method = \"client-secret-post\"\nclient-secret-file = \"secret\"");
    std::fs::write(&path, &secret).unwrap();
    let config = Config::load(&path).unwrap();
    let AuthenticationConfig::ClientSecretPost { client_secret_file } =
        config.upstream.authentication
    else {
        panic!("Expected secret authentication");
    };
    assert_eq!(client_secret_file, directory.0.join("secret"));
    let ambiguous = original.replace(
        "method = \"private-key-jwt\"",
        "method = \"private-key-jwt\"\nclient-secret-file = \"secret\"",
    );
    assert!(toml::from_str::<Config>(&ambiguous).is_err());
}

#[test]
fn resource_blocks_define_unique_https_uris_and_application_ids() {
    let original = include_str!("../idfrog.example.toml");
    for variant in [
        original.replace(
            "https://tools.example.com/mcp",
            "http://tools.example.com/mcp",
        ),
        original.replace(
            "0816f759-d89d-4319-a8d7-d88b5d751dc9",
            "not-an-application-id",
        ),
        original.replace("0816f759-d89d-4319-a8d7-d88b5d751dc9", ""),
    ] {
        let mut config: Config = toml::from_str(&variant).unwrap();
        assert!(config.validate().is_err());
    }
    let mut config: Config = toml::from_str(original).unwrap();
    config.resources.clear();
    assert!(config.validate().is_err());
    let mut config: Config = toml::from_str(original).unwrap();
    config.resources.push(config.resources[0].clone());
    assert!(config.validate().is_err());
    for legacy in [
        "required-groups = []",
        "required_groups = []",
        "resources = []",
        "signing_key_file = 'key.pem'",
    ] {
        assert!(
            toml::from_str::<Config>(&format!("{legacy}\n{original}")).is_err(),
            "{legacy}"
        );
    }
}

#[test]
fn traces_are_optional_and_validate_the_otlp_endpoint_and_service_name() {
    let original = include_str!("../idfrog.example.toml");
    let config: Config = toml::from_str(original).unwrap();
    assert!(config.traces.is_none());
    let config: Config = toml::from_str(&format!("{original}\n[traces]\nendpoint = 'http://tempo.tempo.svc:4317'\nexcluded-paths = ['/healthz']\n")).unwrap();
    let traces = config.traces.unwrap();
    assert_eq!(traces.service_name, "idfrog");
    assert_eq!(traces.excluded_paths, ["/healthz"]);
    for settings in [
        "endpoint = 'http://tempo:4317/v1/traces'",
        "endpoint = 'http://user:secret@tempo:4317'",
        "endpoint = 'ftp://tempo:4317'",
        "endpoint = 'http://tempo:4317'\nservice-name = ''",
        "endpoint = 'http://tempo:4317'\nexcluded-paths = ['/callback?code=secret']",
    ] {
        assert!(toml::from_str::<Config>(&format!("{original}\n[traces]\n{settings}")).is_err());
    }
}

#[test]
fn state_defaults_to_memory_and_dynamodb_needs_a_table() {
    let original = include_str!("../idfrog.example.toml");
    let config: Config = toml::from_str(original).unwrap();
    assert!(matches!(config.state, StateConfig::Memory {}));
    let mut config: Config = toml::from_str(&format!(
        "{original}\n[state]\nbackend = 'dynamodb'\ntable = 'idfrog'\nendpoint-url = 'http://localhost:8000'\n"
    ))
    .unwrap();
    config.validate().unwrap();
    assert!(matches!(
        config.state,
        StateConfig::Dynamodb { ref table, region: None, endpoint_url: Some(_) } if table == "idfrog"
    ));
    let mut config: Config = toml::from_str(&format!(
        "{original}\n[state]\nbackend = 'dynamodb'\ntable = ' '\n"
    ))
    .unwrap();
    assert!(config.validate().is_err());
    for settings in [
        "backend = 'dynamodb'",
        "backend = 'redis'",
        "backend = 'memory'\ntable = 'x'",
    ] {
        assert!(
            toml::from_str::<Config>(&format!("{original}\n[state]\n{settings}")).is_err(),
            "{settings}"
        );
    }
}
