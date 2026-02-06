use crate::error::IdentityError;
use crate::error::IdentityError::Logic;
use crate::util::Token;
use crate::AppState;
use anyhow::anyhow;
use axum::extract::FromRef;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use surrealdb::engine::any;
use surrealdb::engine::any::Any;
use surrealdb::{RecordId, Surreal};
use crate::config::PersistenceConfig;

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone)]
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
        Ok(id.key().into_inner_ref().to_raw())
    }
}

#[derive(Deserialize)]
struct Record {
    id: RecordId,
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone)]
pub enum IdentityState {
    Allocated { challenge: Vec<u8> },
    Active { credentials: Vec<Credential> },
    Invited { token: Token },
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone)]
pub struct Credential {
    pub id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub public_key_algorithm: i32,
    pub sign_count: u32,
}

#[derive(Clone)]
pub struct PersistenceService {
    db: Surreal<Any>,
}

pub async fn make_db(config: &PersistenceConfig) -> Result<Surreal<Any>, IdentityError> {
    let db = any::connect(&config.uri).await?;
    db.signin(surrealdb::opt::auth::Database {
        namespace: "default",
        database: "idelephant",
        username: &config.username,
        password: &config.password()?,
    }).await?;
    setup_db(&db).await?;
    Ok(db)
}

async fn setup_db(db: &Surreal<Any>) -> anyhow::Result<()> {
    db.use_ns("default").use_db("idelephant").await?;
    db.query("DEFINE INDEX IF NOT EXISTS identityEmail ON identity FIELDS email UNIQUE")
        .query(
            "DEFINE INDEX IF NOT EXISTS inviteToken ON identity FIELDS state.Invited.token UNIQUE",
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
        Ok(result.id.key().to_string())
    }

    pub async fn persist_identity_with_id(
        &self,
        id: &str,
        identity: Identity,
    ) -> Result<String, IdentityError> {
        let Some(result): Option<Record> =
            self.db.create(("identity", id)).content(identity).await?
        else {
            return Err(Logic("db.create succeeded but returned None".to_string()));
        };
        Ok(result.id.key().to_string())
    }

    pub async fn fetch_identity(&self, id: &str) -> Result<Option<Identity>, IdentityError> {
        Ok(self.db.select(("identity", id)).await?)
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
        let result: Result<Option<Record>, _> = self.db.create("identity").content(identity).await;
        match result {
            Ok(_) => Ok(token),
            Err(surrealdb::Error::Db(surrealdb::error::Db::IndexExists { .. })) => {
                Err(IdentityError::EmailAlreadyInUse)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn id_email_from_token(
        &self,
        token: &Token,
    ) -> Result<Option<Identity>, anyhow::Error> {
        let mut result = self
            .db
            .query("SELECT * FROM identity where state.Invited.token = $t")
            .bind(("t", token.clone()))
            .await?;
        result.take(0).map_err(|e| anyhow!(e))
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
                        return Err(Logic(
                            "root identity is not admin".to_string(),
                        ));
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
    use crate::persistence::{setup_db, Credential, Identity, IdentityState, PersistenceService};
    use anyhow::Result;
    use chrono::Utc;
    use surrealdb::engine::any;
    use surrealdb::engine::any::Any;
    use surrealdb::Surreal;

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

    async fn mem_db() -> std::result::Result<Surreal<Any>, IdentityError> {
        let db = any::connect("mem://").await?;
        setup_db(&db).await?;
        Ok(db)
    }
}
