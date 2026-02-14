//! Account persistence abstract Trait

use async_trait::async_trait;

use crate::error::CoreResult;
use crate::types::{Account, AccountStatus};

/// Account Metadata Warehouse Trait
///
/// Platform implementation:
/// - Tauri: `TauriAccountRepository` (tauri-plugin-store)
/// - Actix-Web: `DatabaseAccountRepository` (`SeaORM`)
#[async_trait]
pub trait AccountRepository: Send + Sync {
    /// Get all accounts
    async fn find_all(&self) -> CoreResult<Vec<Account>>;

    /// Get account based on ID
    ///
    /// # Arguments
    /// * `id` - Account ID
    async fn find_by_id(&self, id: &str) -> CoreResult<Option<Account>>;

    /// Save account (new or update)
    ///
    /// # Arguments
    /// * `account` - Account data
    async fn save(&self, account: &Account) -> CoreResult<()>;

    /// Delete account
    ///
    /// # Arguments
    /// * `id` - Account ID
    async fn delete(&self, id: &str) -> CoreResult<()>;

    /// Save accounts in batches (for import)
    ///
    /// # Arguments
    /// * `accounts` - Account list
    async fn save_all(&self, accounts: &[Account]) -> CoreResult<()>;

    /// Update account status
    ///
    /// # Arguments
    /// * `id` - Account ID
    /// * `status` - new status
    /// * `error` - error message (if status is Error)
    async fn update_status(
        &self,
        id: &str,
        status: AccountStatus,
        error: Option<String>,
    ) -> CoreResult<()>;
}
