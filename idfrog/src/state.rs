//! Browser transactions, authorization codes, and refresh-token families.
#[cfg(feature = "dynamodb")]
use crate::dynamodb::DynamoStore;
use crate::{
    config::StateConfig,
    error::BrokerError,
    protocol::PendingAuthorizationRequest,
    upstream::{LoginChallenge, UpstreamIdentity},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

pub const TRANSACTION_LIMIT: usize = 1024;
pub const CODE_LIMIT: usize = 1024;
pub const REFRESH_LIMIT: usize = 4096;
pub const ROTATION_LIMIT: usize = 1024;

pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}
pub fn token_hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}
pub fn secrets_equal(a: &str, b: &str) -> bool {
    bool::from(Sha256::digest(a.as_bytes()).ct_eq(&Sha256::digest(b.as_bytes())))
}

#[derive(Serialize, Deserialize)]
pub struct Transaction {
    pub binding: String,
    pub request: PendingAuthorizationRequest,
    pub expires_at: DateTime<Utc>,
    pub challenge: LoginChallenge,
}

#[derive(Serialize, Deserialize)]
pub struct CodeGrant {
    pub request: PendingAuthorizationRequest,
    pub identity: UpstreamIdentity,
    pub expires_at: DateTime<Utc>,
}

/// A refresh-token family's grant; rotation bookkeeping belongs to the store.
#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshGrant {
    pub client_id: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub claims_scopes: Vec<String>,
    pub identity: UpstreamIdentity,
    pub expires_at: DateTime<Utc>,
}

pub fn transaction_deadline() -> DateTime<Utc> {
    Utc::now() + Duration::minutes(10)
}

pub(crate) fn unknown_transaction() -> BrokerError {
    BrokerError::rejected("invalid_request", "unknown_or_expired_login_state")
}
pub(crate) fn binding_mismatch() -> BrokerError {
    BrokerError::rejected("invalid_request", "browser_binding_mismatch")
}
pub(crate) fn unknown_code() -> BrokerError {
    BrokerError::rejected(
        "invalid_grant",
        "unknown_expired_or_used_authorization_code",
    )
}
pub(crate) fn unknown_refresh() -> BrokerError {
    BrokerError::rejected("invalid_grant", "unknown_or_expired_refresh_token")
}
pub(crate) fn refresh_mismatch() -> BrokerError {
    BrokerError::rejected("invalid_grant", "refresh_client_or_resource_mismatch")
}
pub(crate) fn refresh_replay() -> BrokerError {
    BrokerError::rejected("invalid_grant", "refresh_replay_or_rotation_limit")
}
pub(crate) fn refresh_revoked() -> BrokerError {
    BrokerError::rejected("invalid_grant", "refresh_family_revoked_during_exchange")
}
pub(crate) fn refresh_matches(
    grant: &RefreshGrant,
    client_id: &str,
    resource: Option<&str>,
) -> bool {
    grant.client_id == client_id && resource.is_none_or(|r| r == grant.resource)
}

/// Grant state, either in process memory or shared between replicas in DynamoDB.
#[derive(Clone)]
pub enum Store {
    Memory(Arc<Mutex<MemoryState>>),
    #[cfg(feature = "dynamodb")]
    DynamoDb(DynamoStore),
}

impl Store {
    pub fn memory() -> Self {
        Self::Memory(Default::default())
    }

    pub async fn from_config(config: &StateConfig) -> anyhow::Result<Self> {
        Ok(match config {
            StateConfig::Memory {} => Self::memory(),
            #[cfg(feature = "dynamodb")]
            StateConfig::Dynamodb {
                table,
                region,
                endpoint_url,
            } => Self::DynamoDb(
                DynamoStore::connect(table, region.as_deref(), endpoint_url.as_deref()).await?,
            ),
            #[cfg(not(feature = "dynamodb"))]
            StateConfig::Dynamodb { .. } => {
                anyhow::bail!("This idFrog build lacks DynamoDB state; enable the dynamodb feature")
            }
        })
    }

    pub async fn insert_transaction(
        &self,
        state: &str,
        transaction: Transaction,
    ) -> Result<(), BrokerError> {
        match self {
            Self::Memory(memory) => {
                let mut memory = memory.lock().await;
                memory.cleanup(Utc::now());
                if memory.transactions.len() >= TRANSACTION_LIMIT {
                    return Err(BrokerError::Capacity);
                }
                memory.transactions.insert(state.into(), transaction);
                Ok(())
            }
            #[cfg(feature = "dynamodb")]
            Self::DynamoDb(dynamo) => dynamo.insert_transaction(state, &transaction).await,
        }
    }

    /// Removes a login transaction, unless it belongs to a different browser.
    pub async fn take_transaction(
        &self,
        state: &str,
        binding: &str,
    ) -> Result<Transaction, BrokerError> {
        match self {
            Self::Memory(memory) => {
                let mut memory = memory.lock().await;
                memory.cleanup(Utc::now());
                let transaction = memory
                    .transactions
                    .get(state)
                    .ok_or_else(unknown_transaction)?;
                if !secrets_equal(binding, &transaction.binding) {
                    return Err(binding_mismatch());
                }
                memory
                    .transactions
                    .remove(state)
                    .ok_or(BrokerError::OAuth("invalid_request"))
            }
            #[cfg(feature = "dynamodb")]
            Self::DynamoDb(dynamo) => dynamo.take_transaction(state, binding).await,
        }
    }

    pub async fn insert_code(&self, hash: &str, grant: CodeGrant) -> Result<(), BrokerError> {
        match self {
            Self::Memory(memory) => {
                let mut memory = memory.lock().await;
                memory.cleanup(Utc::now());
                if memory.codes.len() >= CODE_LIMIT {
                    return Err(BrokerError::Capacity);
                }
                memory.codes.insert(hash.into(), grant);
                Ok(())
            }
            #[cfg(feature = "dynamodb")]
            Self::DynamoDb(dynamo) => dynamo.insert_code(hash, &grant).await,
        }
    }

    /// Removes a code only when `check` accepts it, so failed exchanges leave it usable.
    pub async fn take_code(
        &self,
        hash: &str,
        check: impl FnOnce(&CodeGrant) -> Result<(), BrokerError>,
    ) -> Result<CodeGrant, BrokerError> {
        match self {
            Self::Memory(memory) => {
                let mut memory = memory.lock().await;
                memory.cleanup(Utc::now());
                let grant = memory.codes.get(hash).ok_or_else(unknown_code)?;
                check(grant)?;
                if grant.request.scopes.iter().any(|s| s == "offline_access")
                    && memory.refresh.len() >= REFRESH_LIMIT
                {
                    return Err(BrokerError::Capacity);
                }
                // Validation and removal share one lock: concurrent exchanges cannot both succeed.
                memory
                    .codes
                    .remove(hash)
                    .ok_or(BrokerError::OAuth("invalid_grant"))
            }
            #[cfg(feature = "dynamodb")]
            Self::DynamoDb(dynamo) => dynamo.take_code(hash, check).await,
        }
    }

    /// Starts a refresh-token family whose current token has hash `token_hash`.
    pub async fn insert_refresh(
        &self,
        token_hash: &str,
        grant: RefreshGrant,
    ) -> Result<(), BrokerError> {
        let family_id = random_token();
        match self {
            Self::Memory(memory) => {
                let mut memory = memory.lock().await;
                if memory.refresh.len() >= REFRESH_LIMIT {
                    return Err(BrokerError::Capacity);
                }
                memory.refresh.insert(
                    family_id,
                    RefreshFamily {
                        grant,
                        current_hash: token_hash.into(),
                        used_hashes: HashSet::new(),
                        busy: false,
                    },
                );
                Ok(())
            }
            #[cfg(feature = "dynamodb")]
            Self::DynamoDb(dynamo) => dynamo.insert_refresh(&family_id, token_hash, &grant).await,
        }
    }

    /// Marks the presented token spent and its family busy until [`Self::finish_refresh`].
    ///
    /// A replayed token, a concurrent refresh, or an exhausted rotation limit revokes the
    /// family. Mismatches and `check` failures reject the request without changing state.
    /// Returns the family ID, its grant, and the value produced by `check`.
    pub async fn begin_refresh<T>(
        &self,
        hash: &str,
        client_id: &str,
        resource: Option<&str>,
        check: impl FnOnce(&RefreshGrant) -> Result<T, BrokerError>,
    ) -> Result<(String, RefreshGrant, T), BrokerError> {
        match self {
            Self::Memory(memory) => {
                let mut memory = memory.lock().await;
                memory.cleanup(Utc::now());
                let family_id = memory
                    .refresh
                    .iter()
                    .find(|(_, family)| {
                        family.current_hash == hash || family.used_hashes.contains(hash)
                    })
                    .map(|(id, _)| id.clone())
                    .ok_or_else(unknown_refresh)?;
                let family = memory
                    .refresh
                    .get_mut(&family_id)
                    .ok_or(BrokerError::OAuth("invalid_grant"))?;
                if !refresh_matches(&family.grant, client_id, resource) {
                    return Err(refresh_mismatch());
                }
                if family.busy
                    || family.used_hashes.contains(hash)
                    || family.used_hashes.len() >= ROTATION_LIMIT
                {
                    memory.refresh.remove(&family_id);
                    return Err(refresh_replay());
                }
                let value = check(&family.grant)?;
                family.busy = true;
                family.used_hashes.insert(hash.into());
                Ok((family_id, family.grant.clone(), value))
            }
            #[cfg(feature = "dynamodb")]
            Self::DynamoDb(dynamo) => dynamo.begin_refresh(hash, client_id, resource, check).await,
        }
    }

    /// Stores the refreshed grant and rotates to `token_hash`, unless the family was revoked.
    pub async fn finish_refresh(
        &self,
        family_id: &str,
        grant: RefreshGrant,
        token_hash: &str,
    ) -> Result<(), BrokerError> {
        match self {
            Self::Memory(memory) => {
                let mut memory = memory.lock().await;
                memory.cleanup(Utc::now());
                // A concurrent replay may have revoked the family while upstream was contacted.
                let family = memory
                    .refresh
                    .get_mut(family_id)
                    .ok_or_else(refresh_revoked)?;
                family.grant = grant;
                family.current_hash = token_hash.into();
                family.busy = false;
                Ok(())
            }
            #[cfg(feature = "dynamodb")]
            Self::DynamoDb(dynamo) => dynamo.finish_refresh(family_id, &grant, token_hash).await,
        }
    }

    pub async fn revoke_refresh(&self, family_id: &str) -> Result<(), BrokerError> {
        match self {
            Self::Memory(memory) => {
                memory.lock().await.refresh.remove(family_id);
                Ok(())
            }
            #[cfg(feature = "dynamodb")]
            Self::DynamoDb(dynamo) => dynamo.revoke_refresh(family_id).await,
        }
    }
}

struct RefreshFamily {
    grant: RefreshGrant,
    current_hash: String,
    used_hashes: HashSet<String>,
    busy: bool,
}

#[derive(Default)]
pub struct MemoryState {
    transactions: HashMap<String, Transaction>,
    codes: HashMap<String, CodeGrant>,
    refresh: HashMap<String, RefreshFamily>,
}

impl MemoryState {
    fn cleanup(&mut self, now: DateTime<Utc>) {
        self.transactions.retain(|_, item| item.expires_at > now);
        self.codes.retain(|_, item| item.expires_at > now);
        self.refresh.retain(|_, item| item.grant.expires_at > now);
    }
}
