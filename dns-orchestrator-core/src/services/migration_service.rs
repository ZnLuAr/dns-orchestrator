//! Credential format migration service (v1.7.0)
//!
//! Responsible for migrating old format credentials (`HashMap`<String, `HashMap`<String, String>>) to new format (`ProviderCredentials`)

use dns_orchestrator_provider::{ProviderCredentials, ProviderType};
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{CoreError, CoreResult};
use crate::traits::{AccountRepository, CredentialStore};

/// Migration services
pub struct MigrationService {
    credential_store: Arc<dyn CredentialStore>,
    account_repository: Arc<dyn AccountRepository>,
}

impl MigrationService {
    pub fn new(
        credential_store: Arc<dyn CredentialStore>,
        account_repository: Arc<dyn AccountRepository>,
    ) -> Self {
        Self {
            credential_store,
            account_repository,
        }
    }

    /// Check and perform migration (if needed)
    ///
    /// Returns the migration result, or `NotNeeded` if it is in the new format.
    pub async fn migrate_if_needed(&self) -> CoreResult<MigrationResult> {
        // Try loading credentials
        match self.credential_store.load_all().await {
            Ok(_) => {
                log::info!("凭证已是新格式，无需迁移");
                Ok(MigrationResult::NotNeeded)
            }
            Err(CoreError::MigrationRequired) => {
                log::info!("检测到旧格式凭证，开始迁移...");
                self.perform_migration().await
            }
            Err(e) => Err(e),
        }
    }

    /// Execute migration
    ///
    /// Note: The backup logic has been implemented in the Tauri layer (src-tauri/src/lib.rs),
    /// Executed before calling `migrate_if_needed()`.
    async fn perform_migration(&self) -> CoreResult<MigrationResult> {
        // 1. Load the original JSON (the backup has been done by the Tauri layer before calling this method)
        let raw_json = self.credential_store.load_raw_json().await?;

        // 2. Parse the old format
        let old_creds: HashMap<String, HashMap<String, String>> =
            serde_json::from_str(&raw_json)
                .map_err(|e| CoreError::MigrationFailed(format!("解析旧格式失败: {e}")))?;

        if old_creds.is_empty() {
            log::info!("旧凭证为空，无需迁移");
            return Ok(MigrationResult::NotNeeded);
        }

        // 3. Get account provider information
        let accounts = self.account_repository.find_all().await?;
        let account_providers: HashMap<String, ProviderType> =
            accounts.into_iter().map(|a| (a.id, a.provider)).collect();

        // 4. Convert voucher
        let mut new_creds = HashMap::new();
        let mut failed_accounts = Vec::new();

        for (account_id, old_cred_map) in old_creds {
            if let Some(provider) = account_providers.get(&account_id) {
                match ProviderCredentials::from_map(provider, &old_cred_map) {
                    Ok(provider_creds) => {
                        new_creds.insert(account_id.clone(), provider_creds);
                    }
                    Err(e) => {
                        log::warn!("账户 {account_id} 凭证转换失败: {e}");
                        failed_accounts.push((account_id, format!("转换失败: {e}")));
                    }
                }
            } else {
                log::warn!("找不到账户 {account_id} 的元数据，跳过迁移");
                failed_accounts.push((account_id, "账户元数据缺失".to_string()));
            }
        }

        // 5. Save the new format
        if !new_creds.is_empty() {
            self.credential_store.save_all(&new_creds).await?;
            log::info!(
                "凭证迁移完成：成功 {} 个，失败 {} 个",
                new_creds.len(),
                failed_accounts.len()
            );
        }

        Ok(MigrationResult::Success {
            migrated_count: new_creds.len(),
            failed_accounts,
        })
    }

    // Note: backup_credentials method has been removed
    // The backup logic is now implemented in the Tauri layer (src-tauri/src/lib.rs),
    // Because the MigrationService is in the platform-independent Core layer, it should not access the file system.
}

/// Migration results
#[derive(Debug)]
pub enum MigrationResult {
    /// No migration required (already new format or empty data)
    NotNeeded,

    /// Migration successful
    Success {
        /// Number of accounts successfully migrated
        migrated_count: usize,
        /// List of failed accounts (`account_id`, `error_reason`)
        failed_accounts: Vec<(String, String)>,
    },
}
