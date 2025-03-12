use crate::error::IdentityError;
use crate::AppState;
use axum::extract::FromRef;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use surrealdb::engine::any;
use surrealdb::engine::any::Any;
use surrealdb::{RecordId, Surreal};

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone)]
pub struct Identity {
    pub email: String,
    pub created: DateTime<Utc>,
    pub state: IdentityState,
}

#[derive(Deserialize)]
struct Record {
    id: RecordId,
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Clone)]
pub enum IdentityState {
    Allocated { challenge: Vec<u8> },
    Active { credentials: Vec<Credential> },
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
    db: Arc<Surreal<Any>>,
}

pub async fn make_db(path: &Path) -> Result<Surreal<Any>, IdentityError> {
    let path = format!("surrealkv:{}", path.to_string_lossy());
    let db = any::connect(path).await?;
    db.use_ns("dev").use_db("identityprovider").await?;
    let _ = db
        .query("DEFINE INDEX IF NOT EXISTS identityEmail ON identity FIELDS email UNIQUE")
        .await?;
    Ok(db)
}

impl PersistenceService {
    pub fn new(db: Surreal<Any>) -> Self {
        PersistenceService { db: Arc::new(db) }
    }

    pub async fn persist(&self, identity: Identity) -> Result<String, IdentityError> {
        let Some(result): Option<Record> = self.db.create("identity").content(identity).await?
        else {
            return Err(IdentityError::Logic(
                "db.create succeeded but returned None".to_string(),
            ));
        };
        Ok(result.id.key().to_string())
    }

    pub async fn fetch(&self, id: &str) -> Result<Option<Identity>, IdentityError> {
        Ok(self.db.select(("identity", id)).await?)
    }

    pub async fn update(&self, id: &str, identity: Identity) -> Result<bool, IdentityError> {
        let result: Option<Identity> = self.db.update(("identity", id)).content(identity).await?;
        Ok(result.is_some())
    }
}

impl FromRef<AppState> for PersistenceService {
    fn from_ref(input: &AppState) -> Self {
        input.ps.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::persistence::{make_db, Credential, Identity, IdentityState, PersistenceService};
    use anyhow::Result;
    use chrono::Utc;

    #[tokio::test]
    async fn test_persist() -> Result<()> {
        let email = "some-email@example.com";

        let dir = tempfile::tempdir()?;
        let db = make_db(dir.path()).await?;
        let rs = PersistenceService::new(db);
        let created = Utc::now();
        let challenge = Vec::from(b"some_challenge");

        let mut identity = Identity {
            state: IdentityState::Allocated {
                challenge: challenge.clone(),
            },
            email: email.to_string(),
            created,
        };

        let id = rs.persist(identity.clone()).await?;

        let result = rs.fetch(&id).await?;
        assert_eq!(
            result,
            Some(Identity {
                email: email.to_string(),
                state: IdentityState::Allocated { challenge },
                created,
            })
        );

        identity.state = IdentityState::Active {
            credentials: vec![Credential {
                id: b"some_id".into(),
                public_key: b"public_key".into(),
                public_key_algorithm: -7,
                sign_count: 0,
            }],
        };

        assert!(rs.update(&id, identity).await?);

        let result = rs.fetch(&id).await?;
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
}
