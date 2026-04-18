use crate::config::PersistenceConfig;
use crate::error::IdentityError;
use crate::error::IdentityError::Logic;
use crate::idmouse::IdmouseClient;
use crate::util::Token;
use crate::AppState;
use axum::extract::FromRef;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use surrealdb::engine::any;
use surrealdb::engine::any::Any;
use surrealdb::types::{RecordId, RecordIdKey, SurrealValue};
use surrealdb::Surreal;

const NAMESPACE: &str = "default";
const DATABASE: &str = "idelephant";

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone, SurrealValue)]
pub struct Identity {
    pub email: String,
    pub created: DateTime<Utc>,
    pub admin: bool,
    pub id: Option<RecordId>,
    pub state: IdentityState,
}

impl Identity {
    pub fn id(&self) -> Result<String, IdentityError> {
        let Some(id) = self.id.as_ref() else {
            return Err(Logic(
                "Attempted to read id from Identity not read from the db".to_string(),
            ));
        };
        record_id_key_to_string(&id.key)
    }
}

#[derive(Deserialize, SurrealValue)]
struct Record {
    id: RecordId,
}

#[derive(Serialize, SurrealValue)]
struct NewOAuthClient {
    client_id: String,
    name: String,
    redirect_uris: Vec<String>,
}

#[derive(Serialize, SurrealValue)]
struct NewAuthorizationCode {
    code: String,
    client_id: String,
    subject_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    nonce: Option<String>,
    code_challenge: String,
    expires_at: DateTime<Utc>,
}

pub struct CreateAuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub subject_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, SurrealValue)]
struct NewAccessToken {
    token_hash: String,
    client_id: String,
    subject_id: String,
    scopes: Vec<String>,
    expires_at: DateTime<Utc>,
}

#[derive(Serialize, SurrealValue)]
struct NewConsentGrant {
    subject_id: String,
    client_id: String,
    scopes: Vec<String>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone, SurrealValue)]
pub enum IdentityState {
    Allocated { challenge: Vec<u8> },
    Active { credentials: Vec<Credential> },
    Invited { token: Token },
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone, SurrealValue)]
pub struct Credential {
    pub id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub public_key_algorithm: i32,
    pub sign_count: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone, SurrealValue)]
pub struct OAuthClient {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub id: RecordId,
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone, SurrealValue)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub subject_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub expires_at: DateTime<Utc>,
    pub id: RecordId,
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone, SurrealValue)]
pub struct AccessToken {
    pub token_hash: String,
    pub client_id: String,
    pub subject_id: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub id: RecordId,
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone, SurrealValue)]
pub struct ConsentGrant {
    pub subject_id: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub id: RecordId,
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone, SurrealValue)]
pub struct JwkKey {
    pub kid: String,
    pub private_key_der: Vec<u8>,
    pub active_from: DateTime<Utc>,
    pub retire_after: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub id: RecordId,
}

#[derive(Serialize, SurrealValue)]
struct NewJwkKey {
    kid: String,
    private_key_der: Vec<u8>,
    active_from: DateTime<Utc>,
    retire_after: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct PersistenceService {
    db: Surreal<Any>,
}

fn record_id_key_to_string(key: &RecordIdKey) -> Result<String, IdentityError> {
    match key {
        RecordIdKey::String(value) => Ok(value.clone()),
        RecordIdKey::Number(value) => Ok(value.to_string()),
        RecordIdKey::Uuid(value) => Ok(value.to_string()),
        other => Err(Logic(format!(
            "Unsupported record id key type for string conversion: {other:?}"
        ))),
    }
}

fn is_duplicate_email_error(err: &surrealdb::Error) -> bool {
    err.message()
        .contains("Database index `identityEmail` already contains")
}

fn is_duplicate_jwk_slot_error(err: &surrealdb::Error) -> bool {
    err.message()
        .contains("Database index `jwkKeyActiveFrom` already contains")
}

pub async fn make_db(config: &PersistenceConfig) -> Result<Surreal<Any>, IdentityError> {
    let db: Surreal<Any> = any::connect(&config.uri).await?;
    if let Some(idmouse_config) = config.idmouse.clone() {
        let access_token = IdmouseClient::new(idmouse_config)
            .fetch_access_token()
            .await?;
        db.authenticate(access_token).await?;
    } else {
        db.signin(surrealdb::opt::auth::Database {
            namespace: NAMESPACE.to_string(),
            database: DATABASE.to_string(),
            username: config.username()?,
            password: config.password()?,
        })
        .await?;
    }
    setup_db(&db).await?;
    Ok(db)
}

#[cfg(test)]
pub async fn mem_db() -> Result<Surreal<Any>, IdentityError> {
    let db = any::connect("mem://").await?;
    setup_db(&db).await?;
    Ok(db)
}

async fn setup_db(db: &Surreal<Any>) -> anyhow::Result<()> {
    db.use_ns(NAMESPACE).use_db(DATABASE).await?;
    db.query(
        "DEFINE INDEX IF NOT EXISTS identityEmail ON identity FIELDS email UNIQUE;
         DEFINE INDEX IF NOT EXISTS inviteToken ON identity FIELDS state.Invited.token UNIQUE;
         DEFINE INDEX IF NOT EXISTS oauthClientId ON oauth_client FIELDS client_id UNIQUE;
         DEFINE INDEX IF NOT EXISTS authorizationCode ON authorization_code FIELDS code UNIQUE;
         DEFINE INDEX IF NOT EXISTS accessTokenHash ON access_token FIELDS token_hash UNIQUE;
         DEFINE INDEX IF NOT EXISTS consentGrantBySubjectClient ON consent_grant FIELDS subject_id, client_id UNIQUE;
         DEFINE INDEX IF NOT EXISTS jwkKeyKid ON jwk_key FIELDS kid UNIQUE;
         DEFINE INDEX IF NOT EXISTS jwkKeyActiveFrom ON jwk_key FIELDS active_from UNIQUE;
         DEFINE TABLE IF NOT EXISTS sessions;"

    )
    .await?;
    Ok(())
}

impl PersistenceService {
    pub fn new(db: Surreal<Any>) -> Self {
        PersistenceService { db }
    }

    #[cfg(test)]
    pub async fn persist_identity(&self, identity: Identity) -> Result<String, IdentityError> {
        let result: Record = self
            .db
            .create("identity")
            .content(identity)
            .await?
            .ok_or_else(|| Logic("Create didn't fail but returned None".to_string()))?;
        record_id_key_to_string(&result.id.key)
    }

    pub async fn persist_identity_with_id(
        &self,
        id: &str,
        identity: Identity,
    ) -> Result<(), IdentityError> {
        let Some(_): Option<Record> = self.db.create(("identity", id)).content(identity).await?
        else {
            return Err(Logic("db.create succeeded but returned None".to_string()));
        };
        Ok(())
    }

    pub async fn fetch_identity(&self, id: &str) -> Result<Option<Identity>, IdentityError> {
        Ok(self.db.select(("identity", id)).await?)
    }

    pub async fn create_oauth_client(
        &self,
        client_id: &str,
        name: &str,
        redirect_uris: Vec<String>,
    ) -> Result<String, IdentityError> {
        let result: Record = self
            .db
            .create("oauth_client")
            .content(NewOAuthClient {
                client_id: client_id.to_string(),
                name: name.to_string(),
                redirect_uris,
            })
            .await?
            .ok_or_else(|| Logic("Create didn't fail but returned None".to_string()))?;
        record_id_key_to_string(&result.id.key)
    }

    pub async fn fetch_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, IdentityError> {
        let mut result = self
            .db
            .query("SELECT * FROM oauth_client WHERE client_id = $client_id LIMIT 1")
            .bind(("client_id", client_id.to_string()))
            .await?;
        Ok(result.take(0)?)
    }

    pub async fn create_jwk_key(
        &self,
        kid: &str,
        private_key_der: &[u8],
        active_from: DateTime<Utc>,
        retire_after: DateTime<Utc>,
        created_at: DateTime<Utc>,
    ) -> Result<JwkKey, IdentityError> {
        let result: Option<JwkKey> = self
            .db
            .create("jwk_key")
            .content(NewJwkKey {
                kid: kid.to_string(),
                private_key_der: private_key_der.to_vec(),
                active_from,
                retire_after,
                created_at,
            })
            .await?;
        result.ok_or_else(|| Logic("Create didn't fail but returned None".to_string()))
    }

    pub async fn fetch_jwk_key_by_slot(
        &self,
        active_from: DateTime<Utc>,
    ) -> Result<Option<JwkKey>, IdentityError> {
        let mut result = self
            .db
            .query("SELECT * FROM jwk_key WHERE active_from = $active_from LIMIT 1")
            .bind(("active_from", active_from))
            .await?;
        Ok(result.take(0)?)
    }

    pub async fn fetch_signing_key_for_time(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Option<JwkKey>, IdentityError> {
        let mut result = self
            .db
            .query(
                "SELECT * FROM jwk_key
                 WHERE active_from <= $now AND retire_after > $now
                 ORDER BY active_from DESC
                 LIMIT 1",
            )
            .bind(("now", now))
            .await?;
        Ok(result.take(0)?)
    }

    pub async fn list_jwks_keys(&self, now: DateTime<Utc>) -> Result<Vec<JwkKey>, IdentityError> {
        let mut result = self
            .db
            .query(
                "SELECT * FROM jwk_key
                 WHERE retire_after > $now
                 ORDER BY active_from ASC",
            )
            .bind(("now", now))
            .await?;
        Ok(result.take(0)?)
    }

    pub async fn delete_expired_jwk_keys(&self, now: DateTime<Utc>) -> Result<(), IdentityError> {
        self.db
            .query("DELETE jwk_key WHERE retire_after <= $now")
            .bind(("now", now))
            .await?;
        Ok(())
    }

    pub fn is_duplicate_jwk_key_error(&self, err: &IdentityError) -> bool {
        match err {
            IdentityError::PersistentStorage(inner) => is_duplicate_jwk_slot_error(inner),
            _ => false,
        }
    }

    pub async fn create_authorization_code(
        &self,
        code: CreateAuthorizationCode,
    ) -> Result<String, IdentityError> {
        let result: Record = self
            .db
            .create("authorization_code")
            .content(NewAuthorizationCode {
                code: code.code,
                client_id: code.client_id,
                subject_id: code.subject_id,
                redirect_uri: code.redirect_uri,
                scopes: code.scopes,
                nonce: code.nonce,
                code_challenge: code.code_challenge,
                expires_at: code.expires_at,
            })
            .await?
            .ok_or_else(|| Logic("Create didn't fail but returned None".to_string()))?;
        record_id_key_to_string(&result.id.key)
    }

    pub async fn fetch_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, IdentityError> {
        let mut result = self
            .db
            .query("SELECT * FROM authorization_code WHERE code = $code LIMIT 1")
            .bind(("code", code.to_string()))
            .await?;
        Ok(result.take(0)?)
    }

    pub async fn delete_authorization_code(&self, code: &str) -> Result<bool, IdentityError> {
        let Some(authorization_code) = self.fetch_authorization_code(code).await? else {
            return Ok(false);
        };
        let result: Option<AuthorizationCode> = self.db.delete(authorization_code.id).await?;
        Ok(result.is_some())
    }

    pub async fn create_access_token(
        &self,
        token_hash: &str,
        client_id: &str,
        subject_id: &str,
        scopes: Vec<String>,
        expires_at: DateTime<Utc>,
    ) -> Result<String, IdentityError> {
        let result: Record = self
            .db
            .create("access_token")
            .content(NewAccessToken {
                token_hash: token_hash.to_string(),
                client_id: client_id.to_string(),
                subject_id: subject_id.to_string(),
                scopes,
                expires_at,
            })
            .await?
            .ok_or_else(|| Logic("Create didn't fail but returned None".to_string()))?;
        record_id_key_to_string(&result.id.key)
    }

    pub async fn fetch_access_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<AccessToken>, IdentityError> {
        let mut result = self
            .db
            .query("SELECT * FROM access_token WHERE token_hash = $token_hash LIMIT 1")
            .bind(("token_hash", token_hash.to_string()))
            .await?;
        Ok(result.take(0)?)
    }

    pub async fn grant_consent(
        &self,
        subject_id: &str,
        client_id: &str,
        scopes: Vec<String>,
        created_at: DateTime<Utc>,
    ) -> Result<String, IdentityError> {
        let existing = self.fetch_consent_grant(subject_id, client_id).await?;
        if let Some(existing) = existing {
            let updated: Option<ConsentGrant> = self
                .db
                .update(existing.id)
                .content(NewConsentGrant {
                    subject_id: subject_id.to_string(),
                    client_id: client_id.to_string(),
                    scopes,
                    created_at,
                })
                .await?;
            let updated = updated.ok_or_else(|| {
                Logic("db.update succeeded but returned None for consent grant".to_string())
            })?;
            return record_id_key_to_string(&updated.id.key);
        }

        let result: Record = self
            .db
            .create("consent_grant")
            .content(NewConsentGrant {
                subject_id: subject_id.to_string(),
                client_id: client_id.to_string(),
                scopes,
                created_at,
            })
            .await?
            .ok_or_else(|| Logic("Create didn't fail but returned None".to_string()))?;
        record_id_key_to_string(&result.id.key)
    }

    pub async fn fetch_consent_grant(
        &self,
        subject_id: &str,
        client_id: &str,
    ) -> Result<Option<ConsentGrant>, IdentityError> {
        let mut result = self
            .db
            .query(
                "SELECT * FROM consent_grant WHERE subject_id = $subject_id AND client_id = $client_id LIMIT 1",
            )
            .bind(("subject_id", subject_id.to_string()))
            .bind(("client_id", client_id.to_string()))
            .await?;
        Ok(result.take(0)?)
    }

    pub async fn update_identity(&self, identity: &Identity) -> Result<bool, IdentityError> {
        let id = identity.id()?;
        let result: Option<Identity> = self
            .db
            .update(("identity", id))
            .content(identity.clone())
            .await?;
        Ok(result.is_some())
    }

    pub async fn create_invite(&self, email: &str, admin: bool) -> Result<Token, IdentityError> {
        let token = Token::random();
        let identity = Identity {
            email: email.to_string(),
            created: Utc::now(),
            admin,
            state: IdentityState::Invited {
                token: token.clone(),
            },
            id: None,
        };
        let result: Result<Option<Record>, surrealdb::Error> =
            self.db.create("identity").content(identity).await;
        match result {
            Ok(_) => Ok(token),
            Err(err) if is_duplicate_email_error(&err) => Err(IdentityError::EmailAlreadyInUse),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn id_email_from_token(
        &self,
        token: &Token,
    ) -> Result<Option<Identity>, anyhow::Error> {
        let identities: Vec<Identity> = self.db.select("identity").await?;
        Ok(identities.into_iter().find(|identity| {
            matches!(
                &identity.state,
                IdentityState::Invited {
                    token: invited_token
                } if invited_token == token
            )
        }))
    }

    pub async fn configure_root_key(
        &self,
        credential_id: &[u8],
        key_bytes: &[u8],
    ) -> Result<(), IdentityError> {
        let identity: Option<Identity> = self.db.select(("identity", "root")).await?;
        if let Some(mut identity) = identity {
            match identity.state {
                IdentityState::Active { mut credentials } => {
                    if !identity.admin {
                        return Err(Logic("root identity is not admin".to_string()));
                    }
                    let mut found = false;
                    for credential in credentials.iter() {
                        if credential.public_key == key_bytes {
                            found = true;
                        }
                    }
                    if !found {
                        credentials.push(Credential {
                            id: credential_id.to_vec(),
                            public_key: key_bytes.to_vec(),
                            public_key_algorithm: -7,
                            sign_count: 0,
                        });
                        identity.state = IdentityState::Active { credentials };
                        let _: Option<Identity> = self
                            .db
                            .update(("identity", "root"))
                            .content(identity)
                            .await?;
                    }
                }
                _ => {
                    return Err(Logic(
                        "root identity needs to be in state Active".to_string(),
                    ));
                }
            }
        } else {
            self.persist_identity_with_id(
                "root",
                Identity {
                    email: "root_user".to_string(),
                    created: Utc::now(),
                    admin: true,
                    state: IdentityState::Active {
                        credentials: vec![Credential {
                            id: credential_id.to_vec(),
                            public_key: key_bytes.to_vec(),
                            public_key_algorithm: -7,
                            sign_count: 0,
                        }],
                    },
                    id: None,
                },
            )
            .await?;
        }
        Ok(())
    }
}

impl FromRef<AppState> for PersistenceService {
    fn from_ref(input: &AppState) -> Self {
        input.ps.deref().clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::error::IdentityError;
    use crate::persistence::{
        mem_db, CreateAuthorizationCode, Credential, Identity, IdentityState, PersistenceService,
    };
    use anyhow::Result;
    use chrono::{Duration, TimeZone, Utc};

    #[tokio::test]
    async fn test_persist() -> Result<()> {
        let email = "some-email@example.com";

        let db = mem_db().await?;
        let rs = PersistenceService::new(db);
        let created = Utc::now();
        let challenge = Vec::from(b"some_challenge");

        let mut identity = Identity {
            admin: false,
            state: IdentityState::Allocated {
                challenge: challenge.clone(),
            },
            email: email.to_string(),
            created,
            id: None,
        };

        let id = rs.persist_identity(identity.clone()).await?;

        let result = rs.fetch_identity(&id).await?;
        let id_from_db = result.clone().unwrap().id.unwrap();
        identity.id = Some(id_from_db);
        assert_eq!(result.unwrap(), identity);

        identity.state = IdentityState::Active {
            credentials: vec![Credential {
                id: b"some_id".into(),
                public_key: b"public_key".into(),
                public_key_algorithm: -7,
                sign_count: 0,
            }],
        };

        assert!(rs.update_identity(&identity).await?);

        let result = rs.fetch_identity(&id).await?;
        let IdentityState::Active { credentials } = result.unwrap().state else {
            panic!("did not update IdentityState::Active");
        };
        assert_eq!(
            credentials,
            vec![Credential {
                id: b"some_id".into(),
                public_key: b"public_key".into(),
                public_key_algorithm: -7,
                sign_count: 0,
            }]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_create_invite() -> Result<()> {
        let db = mem_db().await?;
        let ps = PersistenceService::new(db);
        let token = ps.create_invite("some-email", false).await?;
        let id = ps.id_email_from_token(&token).await?.unwrap();
        assert_eq!(&id.email, "some-email");
        let identity = ps.fetch_identity(&id.id()?).await?.unwrap();
        assert_eq!(identity.email, "some-email");

        let result = ps.create_invite("some-email", false).await;
        assert!(matches!(result, Err(IdentityError::EmailAlreadyInUse)));

        Ok(())
    }

    #[tokio::test]
    async fn test_persist_oauth_client() -> Result<()> {
        let db = mem_db().await?;
        let ps = PersistenceService::new(db);
        let redirect_uris = vec!["http://localhost:4000/callback".to_string()];

        ps.create_oauth_client("client-1", "Example client", redirect_uris.clone())
            .await?;
        let fetched = ps.fetch_oauth_client("client-1").await?.unwrap();
        assert_eq!(fetched.client_id, "client-1");
        assert_eq!(fetched.name, "Example client");
        assert_eq!(fetched.redirect_uris, redirect_uris);
        Ok(())
    }

    #[tokio::test]
    async fn test_persist_authorization_code_and_mark_used() -> Result<()> {
        let db = mem_db().await?;
        let ps = PersistenceService::new(db);
        let expires_at = Utc::now() + Duration::minutes(5);
        let scopes = vec!["openid".to_string(), "email".to_string()];
        let nonce = Some("nonce-123".to_string());
        ps.create_authorization_code(CreateAuthorizationCode {
            code: "code-hash".to_string(),
            client_id: "client-1".to_string(),
            subject_id: "identity:alice".to_string(),
            redirect_uri: "http://localhost:4000/callback".to_string(),
            scopes: scopes.clone(),
            nonce: nonce.clone(),
            code_challenge: "challenge".to_string(),
            expires_at,
        })
        .await?;
        let fetched = ps.fetch_authorization_code("code-hash").await?.unwrap();
        assert_eq!(fetched.code, "code-hash");
        assert_eq!(fetched.client_id, "client-1");
        assert_eq!(fetched.subject_id, "identity:alice");
        assert_eq!(fetched.redirect_uri, "http://localhost:4000/callback");
        assert_eq!(fetched.scopes, scopes);
        assert_eq!(fetched.nonce, nonce);
        assert_eq!(fetched.code_challenge, "challenge");
        assert_eq!(fetched.expires_at, expires_at);

        assert!(ps.delete_authorization_code("code-hash").await?);
        assert!(ps.fetch_authorization_code("code-hash").await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_persist_access_token() -> Result<()> {
        let db = mem_db().await?;
        let ps = PersistenceService::new(db);
        let scopes = vec!["openid".to_string()];
        let expires_at = Utc::now() + Duration::minutes(10);
        ps.create_access_token(
            "token-hash",
            "client-1",
            "identity:alice",
            scopes.clone(),
            expires_at,
        )
        .await?;
        let fetched = ps.fetch_access_token("token-hash").await?.unwrap();
        assert_eq!(fetched.token_hash, "token-hash");
        assert_eq!(fetched.client_id, "client-1");
        assert_eq!(fetched.subject_id, "identity:alice");
        assert_eq!(fetched.scopes, scopes);
        assert_eq!(fetched.expires_at, expires_at);
        Ok(())
    }

    #[tokio::test]
    async fn test_persist_and_fetch_jwk_key_by_slot() -> Result<()> {
        let db = mem_db().await?;
        let ps = PersistenceService::new(db);
        let active_from = Utc.with_ymd_and_hms(2026, 4, 12, 8, 0, 0).unwrap();
        let retire_after = active_from + Duration::hours(9);
        let created_at = active_from - Duration::minutes(5);

        let created = ps
            .create_jwk_key(
                "kid-1",
                b"private-key",
                active_from,
                retire_after,
                created_at,
            )
            .await?;
        let fetched = ps.fetch_jwk_key_by_slot(active_from).await?.unwrap();
        assert_eq!(created.kid, "kid-1");
        assert_eq!(fetched.kid, "kid-1");
        assert_eq!(fetched.private_key_der, b"private-key");
        assert_eq!(fetched.active_from, active_from);
        assert_eq!(fetched.retire_after, retire_after);
        Ok(())
    }

    #[tokio::test]
    async fn test_duplicate_jwk_slot_is_rejected() -> Result<()> {
        let db = mem_db().await?;
        let ps = PersistenceService::new(db);
        let active_from = Utc.with_ymd_and_hms(2026, 4, 12, 8, 0, 0).unwrap();
        let retire_after = active_from + Duration::hours(9);

        ps.create_jwk_key("kid-1", b"key-1", active_from, retire_after, active_from)
            .await?;
        let err = ps
            .create_jwk_key("kid-2", b"key-2", active_from, retire_after, active_from)
            .await
            .unwrap_err();
        assert!(ps.is_duplicate_jwk_key_error(&err));
        Ok(())
    }

    #[tokio::test]
    async fn test_list_and_cleanup_jwk_keys() -> Result<()> {
        let db = mem_db().await?;
        let ps = PersistenceService::new(db);
        let retired = Utc.with_ymd_and_hms(2026, 4, 12, 0, 0, 0).unwrap();
        let current = Utc.with_ymd_and_hms(2026, 4, 12, 8, 0, 0).unwrap();
        let next = Utc.with_ymd_and_hms(2026, 4, 12, 16, 0, 0).unwrap();
        ps.create_jwk_key(
            "kid-retired",
            b"retired",
            retired,
            retired + Duration::hours(8),
            retired,
        )
        .await?;
        ps.create_jwk_key(
            "kid-current",
            b"current",
            current,
            current + Duration::hours(9),
            current,
        )
        .await?;
        ps.create_jwk_key("kid-next", b"next", next, next + Duration::hours(9), next)
            .await?;

        let now = Utc.with_ymd_and_hms(2026, 4, 12, 8, 30, 0).unwrap();
        let visible = ps.list_jwks_keys(now).await?;
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].kid, "kid-current");
        assert_eq!(visible[1].kid, "kid-next");

        ps.delete_expired_jwk_keys(now).await?;
        assert!(ps.fetch_jwk_key_by_slot(retired).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_upsert_consent_grant() -> Result<()> {
        let db = mem_db().await?;
        let ps = PersistenceService::new(db);
        let created_at = Utc::now();
        let first_id = ps
            .grant_consent(
                "identity:alice",
                "client-1",
                vec!["openid".to_string()],
                created_at,
            )
            .await?;
        let fetched = ps
            .fetch_consent_grant("identity:alice", "client-1")
            .await?
            .unwrap();
        assert_eq!(fetched.scopes, vec!["openid".to_string()]);

        let updated_at = created_at + Duration::seconds(1);
        let second_id = ps
            .grant_consent(
                "identity:alice",
                "client-1",
                vec!["openid".to_string(), "email".to_string()],
                updated_at,
            )
            .await?;
        assert_eq!(first_id, second_id);

        let fetched = ps
            .fetch_consent_grant("identity:alice", "client-1")
            .await?
            .unwrap();
        assert_eq!(
            fetched.scopes,
            vec!["openid".to_string(), "email".to_string()]
        );
        assert_eq!(fetched.created_at, updated_at);
        Ok(())
    }
}
