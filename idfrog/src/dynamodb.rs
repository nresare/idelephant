//! Grant state in a DynamoDB table, shared between replicas and kept across restarts.
//!
//! The table has a string partition key `pk`. Items expire at `expires_at` (epoch
//! seconds), which can be the table's TTL attribute; reads also ignore expired items
//! because TTL deletion is delayed. Conditional writes provide the single-use and
//! replay guarantees that the in-memory store gets from its lock.
use crate::{
    error::BrokerError,
    state::{
        CodeGrant, ROTATION_LIMIT, RefreshGrant, Transaction, binding_mismatch, refresh_matches,
        refresh_mismatch, refresh_replay, refresh_revoked, secrets_equal, unknown_code,
        unknown_refresh, unknown_transaction,
    },
};
use anyhow::Context;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_dynamodb::{
    Client,
    config::SharedHttpClient,
    error::DisplayErrorContext,
    types::{AttributeValue, Put, TransactWriteItem, Update},
};
use aws_smithy_http_client::tls::{self, rustls_provider::CryptoMode};
use chrono::{DateTime, Utc};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashMap;

type Item = HashMap<String, AttributeValue>;

#[derive(Clone)]
pub struct DynamoStore {
    client: Client,
    table: String,
}

fn failed(operation: &'static str, error: impl std::error::Error + 'static) -> BrokerError {
    tracing::error!(operation, error = %DisplayErrorContext(&error), "DynamoDB request failed");
    BrokerError::Internal
}

fn key(kind: &str, id: &str) -> AttributeValue {
    AttributeValue::S(format!("{kind}#{id}"))
}

fn string<'a>(item: &'a Item, name: &str) -> Result<&'a str, BrokerError> {
    match item.get(name) {
        Some(AttributeValue::S(value)) => Ok(value),
        _ => {
            tracing::error!(attribute = name, "Malformed DynamoDB item");
            Err(BrokerError::Internal)
        }
    }
}

fn number(item: &Item, name: &str) -> Result<i64, BrokerError> {
    match item.get(name) {
        Some(AttributeValue::N(value)) => value.parse().map_err(|_| BrokerError::Internal),
        _ => {
            tracing::error!(attribute = name, "Malformed DynamoDB item");
            Err(BrokerError::Internal)
        }
    }
}

fn data<T: DeserializeOwned>(item: &Item) -> Result<T, BrokerError> {
    serde_json::from_str(string(item, "data")?).map_err(|_| {
        tracing::error!("Undecodable DynamoDB item data");
        BrokerError::Internal
    })
}

fn new_item(
    key: AttributeValue,
    data: Option<&impl Serialize>,
    expires_at: DateTime<Utc>,
) -> Result<Item, BrokerError> {
    let mut item = HashMap::from([
        ("pk".into(), key),
        (
            "expires_at".into(),
            AttributeValue::N(expires_at.timestamp().to_string()),
        ),
    ]);
    if let Some(data) = data {
        let json = serde_json::to_string(data).map_err(|_| BrokerError::Internal)?;
        item.insert("data".into(), AttributeValue::S(json));
    }
    Ok(item)
}

/// An HTTPS client using ring, like the rest of idFrog, rather than the SDK default.
pub fn http_client() -> SharedHttpClient {
    aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(CryptoMode::Ring))
        .build_https()
}

impl DynamoStore {
    pub fn new(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }

    /// Connects with the default AWS credential and region chain, then checks the table.
    pub async fn connect(
        table: &str,
        region: Option<&str>,
        endpoint_url: Option<&str>,
    ) -> anyhow::Result<Self> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest()).http_client(http_client());
        if let Some(region) = region {
            loader = loader.region(Region::new(region.to_owned()));
        }
        if let Some(endpoint_url) = endpoint_url {
            loader = loader.endpoint_url(endpoint_url);
        }
        let client = Client::new(&loader.load().await);
        client
            .describe_table()
            .table_name(table)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{}", DisplayErrorContext(e)))
            .with_context(|| format!("Could not access DynamoDB table {table}"))?;
        Ok(Self::new(client, table))
    }

    /// Reads an unexpired item with strong consistency.
    async fn get(&self, key: AttributeValue) -> Result<Option<Item>, BrokerError> {
        let item = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("pk", key)
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| failed("get_item", e))?
            .item;
        match item {
            Some(item) if number(&item, "expires_at")? > Utc::now().timestamp() => Ok(Some(item)),
            _ => Ok(None),
        }
    }

    async fn put(&self, item: Item) -> Result<(), BrokerError> {
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await
            .map_err(|e| failed("put_item", e))?;
        Ok(())
    }

    /// Deletes an item, returning false if another request already deleted it.
    async fn delete(&self, key: AttributeValue) -> Result<bool, BrokerError> {
        match self
            .client
            .delete_item()
            .table_name(&self.table)
            .key("pk", key)
            .condition_expression("attribute_exists(pk)")
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(e) => Err(failed("delete_item", e)),
        }
    }

    pub async fn insert_transaction(
        &self,
        state: &str,
        transaction: &Transaction,
    ) -> Result<(), BrokerError> {
        self.put(new_item(
            key("transaction", state),
            Some(transaction),
            transaction.expires_at,
        )?)
        .await
    }

    pub async fn take_transaction(
        &self,
        state: &str,
        binding: &str,
    ) -> Result<Transaction, BrokerError> {
        let item = self
            .get(key("transaction", state))
            .await?
            .ok_or_else(unknown_transaction)?;
        let transaction: Transaction = data(&item)?;
        if !secrets_equal(binding, &transaction.binding) {
            return Err(binding_mismatch());
        }
        if !self.delete(key("transaction", state)).await? {
            return Err(unknown_transaction());
        }
        Ok(transaction)
    }

    pub async fn insert_code(&self, hash: &str, grant: &CodeGrant) -> Result<(), BrokerError> {
        self.put(new_item(key("code", hash), Some(grant), grant.expires_at)?)
            .await
    }

    pub async fn take_code(
        &self,
        hash: &str,
        check: impl FnOnce(&CodeGrant) -> Result<(), BrokerError>,
    ) -> Result<CodeGrant, BrokerError> {
        let item = self
            .get(key("code", hash))
            .await?
            .ok_or_else(unknown_code)?;
        let grant: CodeGrant = data(&item)?;
        check(&grant)?;
        // Only one concurrent exchange can delete the code.
        if !self.delete(key("code", hash)).await? {
            return Err(unknown_code());
        }
        Ok(grant)
    }

    /// Writes a family item and a token item pointing to it.
    ///
    /// Spent token items stay until the family expires, so their replay is detected.
    pub async fn insert_refresh(
        &self,
        family_id: &str,
        token_hash: &str,
        grant: &RefreshGrant,
    ) -> Result<(), BrokerError> {
        let mut family = new_item(key("family", family_id), Some(grant), grant.expires_at)?;
        family.insert("current_hash".into(), AttributeValue::S(token_hash.into()));
        family.insert("busy".into(), AttributeValue::Bool(false));
        family.insert("rotations".into(), AttributeValue::N("0".into()));
        let put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(family))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|e| failed("transact_write_items", e))?;
        self.client
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().put(put).build())
            .transact_items(self.token_item(family_id, token_hash, grant)?)
            .send()
            .await
            .map_err(|e| failed("transact_write_items", e))?;
        Ok(())
    }

    fn token_item(
        &self,
        family_id: &str,
        token_hash: &str,
        grant: &RefreshGrant,
    ) -> Result<TransactWriteItem, BrokerError> {
        let mut item = new_item(key("refresh", token_hash), None::<&()>, grant.expires_at)?;
        item.insert("family".into(), AttributeValue::S(family_id.into()));
        let put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|e| failed("transact_write_items", e))?;
        Ok(TransactWriteItem::builder().put(put).build())
    }

    pub async fn begin_refresh<T>(
        &self,
        hash: &str,
        client_id: &str,
        resource: Option<&str>,
        check: impl FnOnce(&RefreshGrant) -> Result<T, BrokerError>,
    ) -> Result<(String, RefreshGrant, T), BrokerError> {
        let token = self
            .get(key("refresh", hash))
            .await?
            .ok_or_else(unknown_refresh)?;
        let family_id = string(&token, "family")?.to_owned();
        let family = self
            .get(key("family", &family_id))
            .await?
            .ok_or_else(unknown_refresh)?;
        let grant: RefreshGrant = data(&family)?;
        if !refresh_matches(&grant, client_id, resource) {
            return Err(refresh_mismatch());
        }
        if matches!(family.get("busy"), Some(AttributeValue::Bool(true)))
            || string(&family, "current_hash")? != hash
            || number(&family, "rotations")? >= ROTATION_LIMIT as i64
        {
            self.delete(key("family", &family_id)).await?;
            return Err(refresh_replay());
        }
        let value = check(&grant)?;
        // Another request may have spent the same token since it was read.
        let claimed = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("pk", key("family", &family_id))
            .update_expression("SET busy = :true, rotations = rotations + :one")
            .condition_expression("current_hash = :hash AND busy = :false AND rotations < :limit")
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .expression_attribute_values(":one", AttributeValue::N("1".into()))
            .expression_attribute_values(":hash", AttributeValue::S(hash.into()))
            .expression_attribute_values(":limit", AttributeValue::N(ROTATION_LIMIT.to_string()))
            .send()
            .await;
        match claimed {
            Ok(_) => Ok((family_id, grant, value)),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                self.delete(key("family", &family_id)).await?;
                Err(refresh_replay())
            }
            Err(e) => Err(failed("update_item", e)),
        }
    }

    pub async fn finish_refresh(
        &self,
        family_id: &str,
        grant: &RefreshGrant,
        token_hash: &str,
    ) -> Result<(), BrokerError> {
        let json = serde_json::to_string(grant).map_err(|_| BrokerError::Internal)?;
        let update = Update::builder()
            .table_name(&self.table)
            .key("pk", key("family", family_id))
            .update_expression("SET #data = :data, current_hash = :hash, busy = :false")
            // A concurrent replay may have revoked the family while upstream was contacted.
            .condition_expression("attribute_exists(pk) AND busy = :true")
            .expression_attribute_names("#data", "data")
            .expression_attribute_values(":data", AttributeValue::S(json))
            .expression_attribute_values(":hash", AttributeValue::S(token_hash.into()))
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .build()
            .map_err(|e| failed("transact_write_items", e))?;
        match self
            .client
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().update(update).build())
            .transact_items(self.token_item(family_id, token_hash, grant)?)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_transaction_canceled_exception()) =>
            {
                Err(refresh_revoked())
            }
            Err(e) => Err(failed("transact_write_items", e)),
        }
    }

    pub async fn revoke_refresh(&self, family_id: &str) -> Result<(), BrokerError> {
        self.delete(key("family", family_id)).await.map(drop)
    }
}
