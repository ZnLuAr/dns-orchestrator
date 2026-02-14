//! Credential storage abstraction Trait

use async_trait::async_trait;
use dns_orchestrator_provider::ProviderCredentials;
use std::collections::HashMap;

use crate::error::CoreResult;

/// Credential mapping type: `account_id` -> `ProviderCredentials` (type safe)
pub type CredentialsMap = HashMap<String, ProviderCredentials>;

/// Old format credential mapping (used during migration)
pub type LegacyCredentialsMap = HashMap<String, HashMap<String, String>>;

/// Credential storage Trait
///
/// Platform implementation:
/// - Tauri Desktop: `TauriCredentialStore` (keyring crate)
/// - Tauri Android: `TauriCredentialStore` (tauri-plugin-store)
/// - Actix-Web: `DatabaseCredentialStore` (`SeaORM` + AES encryption)
///
/// # v1.7.0 changes
///
/// - Use type-safe `ProviderCredentials` instead of `HashMap<String, String>`
/// - Methods renamed to match Rust idioms: `load()` → `get()`, `save()` → `set()`, `delete()` → `remove()`
/// - Added `save_all()` for batch saving (migration scenario)
/// - Added `load_raw_json()` and `save_raw_json()` for migration detection
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Load all credentials (new format)
    ///
    /// Used at startup to reduce the number of storage accesses. Returns type-safe `CredentialsMap`.
    async fn load_all(&self) -> CoreResult<CredentialsMap>;

    /// Save vouchers in batches (new format)
    ///
    /// Used in migration scenarios to write all credentials at once.
    ///
    /// # Arguments
    /// * `credentials` - Credential mapping
    async fn save_all(&self, credentials: &CredentialsMap) -> CoreResult<()>;

    /// Get individual account credentials
    ///
    /// # Arguments
    /// * `account_id` - Account ID
    ///
    /// # Returns
    /// * `Ok(Some(credentials))` - token exists
    /// * `Ok(None)` - token does not exist
    async fn get(&self, account_id: &str) -> CoreResult<Option<ProviderCredentials>>;

    /// Set up individual account credentials
    ///
    /// # Arguments
    /// * `account_id` - Account ID
    /// * `credentials` - type-safe token
    async fn set(&self, account_id: &str, credentials: &ProviderCredentials) -> CoreResult<()>;

    /// Delete credentials
    ///
    /// # Arguments
    /// * `account_id` - Account ID
    async fn remove(&self, account_id: &str) -> CoreResult<()>;

    // === Migration helper methods ===

    /// Load raw JSON (for format detection and migration)
    ///
    /// Returns the raw JSON string from storage, without deserialization.
    async fn load_raw_json(&self) -> CoreResult<String>;

    /// Save raw JSON (for migration writes)
    ///
    /// Write JSON string directly to storage without serialization.
    ///
    /// # Arguments
    /// * `json` - JSON string
    async fn save_raw_json(&self, json: &str) -> CoreResult<()>;
}
