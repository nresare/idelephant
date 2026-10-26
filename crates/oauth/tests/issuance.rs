//! Exercise the public platform API without idElephant, a database, or HTTP routes.
use chrono::{Duration, Utc};
use idp_oauth::token::{AccessTokenRequest, IdTokenRequest, Principal, SigningKey, TokenIssuer};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use p256::{ecdsa::SigningKey as EcSigningKey, elliptic_curve::Generate, pkcs8::EncodePrivateKey};
use serde_json::Value;

fn key() -> SigningKey {
    let key = EcSigningKey::generate();
    SigningKey::from_pkcs8("configured-key", key.to_pkcs8_der().unwrap().as_bytes()).unwrap()
}

fn verify(token: &str, key: &SigningKey, audience: &str) -> Value {
    let jwk = serde_json::from_value(serde_json::to_value(key.public_jwk()).unwrap()).unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&["https://idfrog.example"]);
    validation.set_audience(&[audience]);
    decode::<Value>(token, &DecodingKey::from_jwk(&jwk).unwrap(), &validation)
        .unwrap()
        .claims
}

#[test]
fn externally_authenticated_principal_gets_resource_bound_scoped_access_tokens() {
    let key = key();
    let issuer = TokenIssuer::new("https://idfrog.example");
    let groups = vec!["engineering-object-id".into()];
    let principal = Principal {
        subject: "entra:tenant-id:object-id",
        email: Some("alice@example.com"),
        groups: &groups,
    };
    let now = Utc::now();
    let mint = |scopes: &[String]| {
        issuer
            .mint_access_token(
                &key,
                &principal,
                AccessTokenRequest {
                    client_id: "https://client.example/client.json",
                    resource: Some("https://tools.example/mcp"),
                    scopes,
                },
                now,
            )
            .unwrap()
    };
    let token = mint(&["email".into(), "groups".into()]);
    let header = decode_header(&token).unwrap();
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    assert_eq!(header.kid.as_deref(), Some("configured-key"));
    let claims = verify(&token, &key, "https://tools.example/mcp");
    assert_eq!(claims["sub"], principal.subject);
    assert_eq!(claims["client_id"], "https://client.example/client.json");
    assert_eq!(claims["email"], "alice@example.com");
    assert_eq!(claims["groups"], serde_json::json!(groups));
    assert_eq!(claims["scope"], "email groups");
    assert_eq!(claims["iat"], now.timestamp());
    assert_eq!(claims["exp"], (now + Duration::hours(1)).timestamp());
    let second = mint(&[]);
    let restricted = verify(&second, &key, "https://tools.example/mcp");
    assert!(restricted.get("email").is_none());
    assert!(restricted.get("groups").is_none());
    assert_ne!(claims["jti"], restricted["jti"]);
    // A valid signature must not make this token usable by another MCP resource.
    let jwk = serde_json::from_value(serde_json::to_value(key.public_jwk()).unwrap()).unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["https://other.example/mcp"]);
    assert!(decode::<Value>(&token, &DecodingKey::from_jwk(&jwk).unwrap(), &validation).is_err());
}

#[test]
fn id_tokens_preserve_upstream_authentication_time_and_allow_missing_email() {
    let key = key();
    let issuer = TokenIssuer::new("https://idfrog.example");
    let now = Utc::now();
    let authenticated_at = now - Duration::minutes(20);
    let token = issuer
        .mint_id_token(
            &key,
            &Principal {
                subject: "upstream-subject",
                email: None,
                groups: &[],
            },
            IdTokenRequest {
                audience: "client-1",
                nonce: Some("downstream-nonce"),
                authenticated_at,
                include_groups: true,
            },
            now,
        )
        .unwrap();
    assert_eq!(decode_header(&token).unwrap().typ.as_deref(), Some("JWT"));
    let claims = verify(&token, &key, "client-1");
    assert_eq!(claims["auth_time"], authenticated_at.timestamp());
    assert_eq!(claims["iat"], now.timestamp());
    assert_eq!(claims["nonce"], "downstream-nonce");
    assert_eq!(claims["groups"], serde_json::json!([]));
    assert!(claims.get("email").is_none());
}

#[test]
fn oidc_access_tokens_keep_userinfo_audience_and_invalid_keys_are_rejected() {
    let key = key();
    let issuer = TokenIssuer::new("https://idfrog.example");
    let token = issuer
        .mint_access_token(
            &key,
            &Principal {
                subject: "user-1",
                email: None,
                groups: &[],
            },
            AccessTokenRequest {
                client_id: "client-1",
                resource: None,
                scopes: &["groups".into()],
            },
            Utc::now(),
        )
        .unwrap();
    let claims = verify(&token, &key, "https://idfrog.example/userinfo");
    assert_eq!(claims["groups"], serde_json::json!([]));
    assert!(claims.get("email").is_none());
    assert!(SigningKey::from_pkcs8("invalid", b"not-a-private-key").is_err());
}
