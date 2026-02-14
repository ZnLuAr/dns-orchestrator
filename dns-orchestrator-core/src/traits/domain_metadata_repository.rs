//! Domain name metadata persistence abstract Trait

use async_trait::async_trait;
use std::collections::HashMap;

use crate::error::CoreResult;
use crate::types::{DomainMetadata, DomainMetadataKey, DomainMetadataUpdate};

/// Domain name metadata warehouse Trait
///
/// Platform implementation:
/// - Tauri: `TauriDomainMetadataRepository` (tauri-plugin-store)
/// - Actix-Web: `DatabaseDomainMetadataRepository` (`SeaORM`)
#[async_trait]
pub trait DomainMetadataRepository: Send + Sync {
    /// Get metadata for a single domain name
    ///
    /// # Returns
    /// * `Some(metadata)` - found metadata
    /// * `None` - not found (use default value)
    async fn find_by_key(&self, key: &DomainMetadataKey) -> CoreResult<Option<DomainMetadata>>;

    /// Obtain metadata of multiple domain names in batches (performance optimization)
    ///
    /// # Arguments
    /// * `keys` - list of domain name metadata keys
    ///
    /// # Returns
    /// * Key-value pair mapping (contains only existing metadata)
    async fn find_by_keys(
        &self,
        keys: &[DomainMetadataKey],
    ) -> CoreResult<HashMap<DomainMetadataKey, DomainMetadata>>;

    /// Save or update metadata
    ///
    /// # Arguments
    /// * `key` - domain name metadata key
    /// * `metadata` - metadata
    ///
    /// # Note
    /// If `metadata.is_empty()` is true, the storage entry should be deleted
    async fn save(&self, key: &DomainMetadataKey, metadata: &DomainMetadata) -> CoreResult<()>;

    /// Save metadata of multiple domain names in batches (performance optimization, only write files once)
    ///
    /// # Arguments
    /// * `entries` - list of key-value pairs
    ///
    /// # Note
    /// - This method is used for batch operation performance optimization to avoid multiple file writes
    /// - If a `metadata.is_empty()` is true, the corresponding storage entry should be deleted
    async fn batch_save(&self, entries: &[(DomainMetadataKey, DomainMetadata)]) -> CoreResult<()>;

    /// Update metadata (partial update, used in Phase 2/3)
    async fn update(
        &self,
        key: &DomainMetadataKey,
        update: &DomainMetadataUpdate,
    ) -> CoreResult<()>;

    /// Delete metadata
    async fn delete(&self, key: &DomainMetadataKey) -> CoreResult<()>;

    /// Delete all metadata under the account (called when the account is deleted)
    async fn delete_by_account(&self, account_id: &str) -> CoreResult<()>;

    /// Get all favorite domain name keys under the account
    async fn find_favorites_by_account(
        &self,
        account_id: &str,
    ) -> CoreResult<Vec<DomainMetadataKey>>;

    /// Query domain name by label (return all domain name keys containing the label)
    async fn find_by_tag(&self, tag: &str) -> CoreResult<Vec<DomainMetadataKey>>;

    /// Get all used tags (remove duplicates, sort)
    async fn list_all_tags(&self) -> CoreResult<Vec<String>>;
}
