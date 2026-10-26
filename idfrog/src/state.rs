use crate::{
    protocol::PendingAuthorizationRequest,
    upstream::{LoginChallenge, UpstreamIdentity},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use subtle::ConstantTimeEq;

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

pub struct Transaction {
    pub binding: String,
    pub request: PendingAuthorizationRequest,
    pub expires_at: DateTime<Utc>,
    pub challenge: LoginChallenge,
}

pub struct CodeGrant {
    pub request: PendingAuthorizationRequest,
    pub identity: UpstreamIdentity,
    pub expires_at: DateTime<Utc>,
}

pub struct RefreshGrant {
    pub client_id: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub claims_scopes: Vec<String>,
    pub identity: UpstreamIdentity,
    pub current_hash: String,
    pub used_hashes: HashSet<String>,
    pub busy: bool,
    pub expires_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct MemoryState {
    pub transactions: HashMap<String, Transaction>,
    pub codes: HashMap<String, CodeGrant>,
    pub refresh: HashMap<String, RefreshGrant>,
}

impl MemoryState {
    pub fn cleanup(&mut self, now: DateTime<Utc>) {
        self.transactions.retain(|_, item| item.expires_at > now);
        self.codes.retain(|_, item| item.expires_at > now);
        self.refresh.retain(|_, item| item.expires_at > now);
    }
    pub fn transaction_deadline() -> DateTime<Utc> {
        Utc::now() + Duration::minutes(10)
    }
}
