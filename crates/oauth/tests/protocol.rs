use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use idp_oauth::protocol::ScopePolicy;
use idp_oauth::{
    client_metadata::{ApplicationType, Client},
    protocol::{
        AuthorizationPolicy, AuthorizationRequest, ProtocolError, ResourceRequirement,
        build_redirect, valid_verifier, validate_authorization_request, validate_pending_client,
        verify_pkce,
    },
};
use sha2::{Digest, Sha256};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
fn client() -> Client {
    Client {
        client_id: "client".into(),
        name: "Client".into(),
        redirect_uris: vec!["https://client.example/callback".into()],
        cimd: false,
        application_type: ApplicationType::Web,
    }
}
fn request() -> AuthorizationRequest {
    AuthorizationRequest {
        resource: None,
        response_type: "code".into(),
        client_id: "client".into(),
        redirect_uri: "https://client.example/callback".into(),
        scope: "openid profile".into(),
        state: Some("state".into()),
        nonce: Some("nonce".into()),
        code_challenge: Some(CHALLENGE.into()),
        code_challenge_method: Some("S256".into()),
    }
}
fn policy(resource_requirement: ResourceRequirement) -> AuthorizationPolicy<'static> {
    AuthorizationPolicy {
        scopes: ScopePolicy::Supported(&["openid", "profile", "email"]),
        resource_requirement,
    }
}
#[test]
fn oidc_and_mcp_resource_requirements_are_explicit_and_metadata_clients_always_need_a_resource() {
    let pending = validate_authorization_request(
        request(),
        &client(),
        policy(ResourceRequirement::MetadataClients),
    )
    .unwrap();
    assert_eq!(pending.scopes, ["openid", "profile"]);
    assert_eq!(pending.state.as_deref(), Some("state"));
    assert!(matches!(
        validate_authorization_request(request(), &client(), policy(ResourceRequirement::Always)),
        Err(ProtocolError::OAuth("invalid_target"))
    ));
    let mut metadata_client = client();
    metadata_client.cimd = true;
    assert!(
        validate_authorization_request(
            request(),
            &metadata_client,
            policy(ResourceRequirement::MetadataClients)
        )
        .is_err()
    );
    let mut mcp = request();
    mcp.resource = Some("https://mcp.example".into());
    mcp.scope.clear();
    let pending =
        validate_authorization_request(mcp, &client(), policy(ResourceRequirement::Always))
            .unwrap();
    assert_eq!(pending.scopes, ["email"]);
    assert_eq!(pending.resource.as_deref(), Some("https://mcp.example"));
}
#[test]
fn resource_redirect_client_scope_and_pkce_validation_fail_closed() {
    for resource in [
        "http://mcp.example",
        "https://user:pass@mcp.example",
        "https://mcp.example?token=secret",
        "https://mcp.example/#fragment",
    ] {
        let mut invalid = request();
        invalid.resource = Some(resource.into());
        assert!(
            validate_authorization_request(invalid, &client(), policy(ResourceRequirement::Always))
                .is_err()
        );
    }
    for (field, value) in [
        ("client_id", "other"),
        ("redirect_uri", "https://attacker.example/callback"),
        ("scope", "admin"),
        ("response_type", "token"),
        ("code_challenge", "short"),
        ("code_challenge_method", "plain"),
    ] {
        let mut invalid = request();
        match field {
            "client_id" => invalid.client_id = value.into(),
            "redirect_uri" => invalid.redirect_uri = value.into(),
            "scope" => invalid.scope = value.into(),
            "response_type" => invalid.response_type = value.into(),
            "code_challenge" => invalid.code_challenge = Some(value.into()),
            _ => invalid.code_challenge_method = Some(value.into()),
        }
        assert!(
            validate_authorization_request(
                invalid,
                &client(),
                policy(ResourceRequirement::MetadataClients)
            )
            .is_err(),
            "{field}"
        );
    }
    let pending = validate_authorization_request(
        request(),
        &client(),
        policy(ResourceRequirement::MetadataClients),
    )
    .unwrap();
    let mut changed = client();
    changed.client_id = "other".into();
    assert!(validate_pending_client(&pending, &changed).is_err());
    changed = client();
    changed.redirect_uris.clear();
    assert!(validate_pending_client(&pending, &changed).is_err());
}
#[test]
fn s256_matches_rfc7636_and_redirect_parameters_stay_encoded() {
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
        CHALLENGE
    );
    assert!(valid_verifier(VERIFIER));
    assert!(!valid_verifier("short"));
    assert!(!valid_verifier(&"!".repeat(43)));
    assert!(!valid_verifier(&"a".repeat(129)));
    assert!(verify_pkce(VERIFIER, CHALLENGE));
    assert!(!verify_pkce("wrong", CHALLENGE));
    let redirect = build_redirect(
        "https://client.example/callback?existing=1",
        &[
            ("code", Some("a&b")),
            ("state", Some("#value")),
            ("nonce", None),
        ],
    )
    .unwrap();
    let url = url::Url::parse(&redirect).unwrap();
    assert_eq!(url.fragment(), None);
    assert_eq!(
        url.query_pairs()
            .collect::<std::collections::HashMap<_, _>>()
            .get("code")
            .unwrap(),
        "a&b"
    );
}

#[test]
fn resource_defined_scopes_allow_new_names_but_still_enforce_oauth_syntax() {
    let mut dynamic = request();
    dynamic.scope = "Custom.Read NewPermission".into();
    assert!(
        validate_authorization_request(
            dynamic,
            &client(),
            AuthorizationPolicy {
                scopes: ScopePolicy::ResourceDefined,
                resource_requirement: ResourceRequirement::MetadataClients,
            }
        )
        .is_ok()
    );
    for scope in ["bad\\scope", "quoted\"scope", "non-ascii-å"] {
        let mut invalid = request();
        invalid.scope = scope.into();
        assert!(
            validate_authorization_request(
                invalid,
                &client(),
                AuthorizationPolicy {
                    scopes: ScopePolicy::ResourceDefined,
                    resource_requirement: ResourceRequirement::MetadataClients,
                }
            )
            .is_err()
        );
    }
}
