//! 统一账户服务
//!
//! 合并原有的 AccountMetadataService、CredentialManagementService、
//! AccountLifecycleService、AccountBootstrapService 四个服务。

use std::sync::Arc;

use chrono::Utc;
use dns_orchestrator_provider::{create_provider, DnsProvider, ProviderCredentials, ProviderType};

use crate::error::{CoreError, CoreResult};
use crate::services::ServiceContext;
use crate::traits::CredentialsMap;
use crate::types::{
    Account, AccountStatus, BatchDeleteFailure, BatchDeleteResult, CreateAccountRequest,
    UpdateAccountRequest,
};

/// 账户恢复结果
#[derive(Debug, Clone)]
pub struct RestoreResult {
    /// 成功恢复的账户数
    pub success_count: usize,
    /// 恢复失败的账户数
    pub error_count: usize,
}

/// 统一账户服务
pub struct AccountService {
    ctx: Arc<ServiceContext>,
}

impl AccountService {
    /// 创建账户服务实例
    #[must_use]
    pub fn new(ctx: Arc<ServiceContext>) -> Self {
        Self { ctx }
    }

    // ===== CRUD 操作 =====

    /// 列出所有账户
    pub async fn list_accounts(&self) -> CoreResult<Vec<Account>> {
        self.ctx.account_repository().find_all().await
    }

    /// 根据 ID 获取账户
    pub async fn get_account(&self, account_id: &str) -> CoreResult<Option<Account>> {
        self.ctx.account_repository().find_by_id(account_id).await
    }

    /// 更新账户状态
    pub async fn update_status(
        &self,
        account_id: &str,
        status: AccountStatus,
        error: Option<String>,
    ) -> CoreResult<()> {
        self.ctx
            .account_repository()
            .update_status(account_id, status, error)
            .await
    }

    // ===== 生命周期操作 =====

    /// 创建账户
    ///
    /// 完整流程：验证凭证 -> 保存凭证 -> 注册 Provider -> 保存元数据
    /// 如果保存元数据失败，会自动清理已保存的凭证和已注册的 Provider
    pub async fn create_account(&self, request: CreateAccountRequest) -> CoreResult<Account> {
        // 1. 验证凭证
        let provider = self
            .validate_and_create_provider(&request.credentials)
            .await?;

        // 2. 生成账号 ID
        let account_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        // 3. 保存凭证
        log::info!("Saving credentials for account: {account_id}");
        self.save_credentials(&account_id, &request.credentials)
            .await?;
        log::info!("Credentials saved successfully");

        // 4. 注册 provider
        self.register_provider(account_id.clone(), provider).await;

        // 5. 创建账号元数据
        let account = Account {
            id: account_id.clone(),
            name: request.name,
            provider: request.provider,
            created_at: now,
            updated_at: now,
            status: Some(AccountStatus::Active),
            error: None,
        };

        // 6. 保存元数据，失败时 cleanup
        if let Err(e) = self.ctx.account_repository().save(&account).await {
            log::error!("Failed to save account metadata, cleaning up: {e}");
            if let Err(cleanup_err) = self.delete_credentials(&account_id).await {
                log::warn!("Cleanup: failed to delete credentials for {account_id}: {cleanup_err}");
            }
            self.unregister_provider(&account_id).await;
            return Err(e);
        }

        Ok(account)
    }

    /// 从导入数据创建账户（不验证凭证）
    pub async fn create_account_from_import(
        &self,
        name: String,
        provider_type: ProviderType,
        credentials: ProviderCredentials,
    ) -> CoreResult<Account> {
        let provider = create_provider(credentials.clone())?;
        let account_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        self.save_credentials(&account_id, &credentials).await?;
        self.register_provider(account_id.clone(), provider).await;

        let account = Account {
            id: account_id.clone(),
            name,
            provider: provider_type,
            created_at: now,
            updated_at: now,
            status: Some(AccountStatus::Active),
            error: None,
        };

        if let Err(e) = self.ctx.account_repository().save(&account).await {
            log::error!("Failed to save account metadata, cleaning up: {e}");
            if let Err(cleanup_err) = self.delete_credentials(&account_id).await {
                log::warn!("Cleanup: failed to delete credentials for {account_id}: {cleanup_err}");
            }
            self.unregister_provider(&account_id).await;
            return Err(e);
        }

        Ok(account)
    }

    /// 更新账户
    ///
    /// 支持更新账户名称和/或凭证。
    /// 如果更新凭证，会重新验证并重新注册 Provider。
    pub async fn update_account(&self, request: UpdateAccountRequest) -> CoreResult<Account> {
        // 1. 获取现有账户
        let mut account = self
            .ctx
            .account_repository()
            .find_by_id(&request.id)
            .await?
            .ok_or_else(|| CoreError::AccountNotFound(request.id.clone()))?;

        // 2. 如果提供了新凭证，验证并更新
        let old_credentials = if let Some(ref new_credentials) = request.credentials {
            let new_provider = self.validate_and_create_provider(new_credentials).await?;

            // 备份旧凭证用于回滚
            let old_creds = self.load_credentials(&request.id).await.ok();

            log::info!("Updating credentials for account: {}", request.id);
            self.save_credentials(&request.id, new_credentials).await?;
            self.register_provider(request.id.clone(), new_provider)
                .await;

            account.status = Some(AccountStatus::Active);
            account.error = None;

            old_creds
        } else {
            None
        };

        // 3. 更新名称（如果提供）
        if let Some(new_name) = request.name {
            account.name = new_name;
        }

        // 4. 更新时间戳
        account.updated_at = Utc::now();

        // 5. 保存更新后的账户，失败时回滚凭证
        if let Err(e) = self.ctx.account_repository().save(&account).await {
            if let Some(old_creds) = old_credentials {
                log::warn!("Rolling back credentials for account: {}", request.id);
                if let Err(rollback_err) = self.save_credentials(&request.id, &old_creds).await {
                    log::error!(
                        "Failed to rollback credentials for {}: {rollback_err}",
                        request.id
                    );
                }
                // 回滚 provider
                if let Ok(old_provider) = create_provider(old_creds) {
                    self.register_provider(request.id.clone(), old_provider)
                        .await;
                }
            }
            return Err(e);
        }

        Ok(account)
    }

    /// 删除账户
    ///
    /// 流程：先删除元数据，再清理内存和凭证（避免出现"幽灵账户"）
    pub async fn delete_account(&self, account_id: &str) -> CoreResult<()> {
        // 1. 检查账户存在
        self.ctx
            .account_repository()
            .find_by_id(account_id)
            .await?
            .ok_or_else(|| CoreError::AccountNotFound(account_id.to_string()))?;

        // 2. 先删除账号元数据
        self.ctx.account_repository().delete(account_id).await?;

        // 3. 注销 provider
        self.unregister_provider(account_id).await;

        // 4. 删除凭证
        if let Err(e) = self.delete_credentials(account_id).await {
            log::warn!("Failed to delete credentials for {account_id}: {e}");
        }

        // 5. 清理域名元数据
        if let Err(e) = self
            .ctx
            .domain_metadata_repository()
            .delete_by_account(account_id)
            .await
        {
            log::warn!("Failed to delete domain metadata for {account_id}: {e}");
        }

        Ok(())
    }

    /// 批量删除账户
    pub async fn batch_delete_accounts(
        &self,
        account_ids: Vec<String>,
    ) -> CoreResult<BatchDeleteResult> {
        let mut success_count = 0;
        let mut failures = Vec::new();

        for account_id in account_ids {
            match self.delete_account(&account_id).await {
                Ok(()) => success_count += 1,
                Err(e) => {
                    failures.push(BatchDeleteFailure {
                        record_id: account_id,
                        reason: e.to_string(),
                    });
                }
            }
        }

        Ok(BatchDeleteResult {
            success_count,
            failed_count: failures.len(),
            failures,
        })
    }

    // ===== 凭证操作 =====

    /// 验证凭证并创建 Provider 实例
    pub async fn validate_and_create_provider(
        &self,
        credentials: &ProviderCredentials,
    ) -> CoreResult<Arc<dyn DnsProvider>> {
        let provider = create_provider(credentials.clone())?;

        let is_valid = provider.validate_credentials().await?;
        if !is_valid {
            return Err(CoreError::InvalidCredentials(
                credentials.provider_type().to_string(),
            ));
        }

        Ok(provider)
    }

    /// 保存凭证
    pub async fn save_credentials(
        &self,
        account_id: &str,
        credentials: &ProviderCredentials,
    ) -> CoreResult<()> {
        self.ctx
            .credential_store()
            .set(account_id, credentials)
            .await
    }

    /// 加载凭证
    pub async fn load_credentials(&self, account_id: &str) -> CoreResult<ProviderCredentials> {
        self.ctx
            .credential_store()
            .get(account_id)
            .await?
            .ok_or_else(|| {
                CoreError::CredentialError(format!(
                    "No credentials found for account: {account_id}"
                ))
            })
    }

    /// 删除凭证
    pub async fn delete_credentials(&self, account_id: &str) -> CoreResult<()> {
        self.ctx.credential_store().remove(account_id).await
    }

    /// 加载所有凭证
    pub async fn load_all_credentials(&self) -> CoreResult<CredentialsMap> {
        self.ctx.credential_store().load_all().await
    }

    // ===== Provider 注册 =====

    /// 注册 Provider 到 Registry
    pub async fn register_provider(&self, account_id: String, provider: Arc<dyn DnsProvider>) {
        self.ctx
            .provider_registry()
            .register(account_id, provider)
            .await;
    }

    /// 注销 Provider
    pub async fn unregister_provider(&self, account_id: &str) {
        self.ctx.provider_registry().unregister(account_id).await;
    }

    // ===== 启动恢复 =====

    /// 恢复账户（启动时调用）
    pub async fn restore_accounts(&self) -> CoreResult<RestoreResult> {
        let mut success_count = 0;
        let mut error_count = 0;

        // 1. 加载所有账户元数据
        let accounts = self.list_accounts().await?;

        // 2. 加载所有凭证
        let all_credentials = match self.load_all_credentials().await {
            Ok(creds) => creds,
            Err(e) => {
                log::error!("Failed to load credentials: {e}");
                for account in &accounts {
                    if let Err(update_err) = self
                        .update_status(&account.id, AccountStatus::Error, Some(e.to_string()))
                        .await
                    {
                        log::warn!(
                            "Failed to update status for account {}: {update_err}",
                            account.id
                        );
                    }
                }
                return Ok(RestoreResult {
                    success_count: 0,
                    error_count: accounts.len(),
                });
            }
        };

        // 3. 逐个恢复账户
        for account in &accounts {
            let Some(credentials) = all_credentials.get(&account.id) else {
                log::warn!("No credentials found for account: {}", account.id);
                if let Err(e) = self
                    .update_status(
                        &account.id,
                        AccountStatus::Error,
                        Some("凭证不存在".to_string()),
                    )
                    .await
                {
                    log::warn!("Failed to update status for account {}: {e}", account.id);
                }
                error_count += 1;
                continue;
            };

            let provider = match create_provider(credentials.clone()) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!(
                        "Failed to create provider for account {}: {}",
                        account.id,
                        e
                    );
                    if let Err(update_err) = self
                        .update_status(
                            &account.id,
                            AccountStatus::Error,
                            Some(format!("创建 Provider 失败: {e}")),
                        )
                        .await
                    {
                        log::warn!(
                            "Failed to update status for account {}: {update_err}",
                            account.id
                        );
                    }
                    error_count += 1;
                    continue;
                }
            };

            self.register_provider(account.id.clone(), provider).await;

            if let Err(e) = self
                .update_status(&account.id, AccountStatus::Active, None)
                .await
            {
                log::warn!("Failed to update status for account {}: {e}", account.id);
            }

            success_count += 1;
        }

        Ok(RestoreResult {
            success_count,
            error_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{create_test_account_service, test_credentials};
    use crate::traits::{AccountRepository, CredentialStore, DomainMetadataRepository};
    use dns_orchestrator_provider::ProviderType;

    #[tokio::test]
    async fn create_account_from_import_success() {
        let (svc, account_repo, credential_store, _) = create_test_account_service();

        let account = svc
            .create_account_from_import(
                "Test CF".to_string(),
                ProviderType::Cloudflare,
                test_credentials(),
            )
            .await
            .unwrap();

        assert_eq!(account.name, "Test CF");
        assert_eq!(account.provider, ProviderType::Cloudflare);
        assert_eq!(account.status, Some(AccountStatus::Active));

        // 验证凭证已保存
        let creds = credential_store.get(&account.id).await.unwrap();
        assert!(creds.is_some());

        // 验证账户元数据已保存
        let saved = account_repo.find_by_id(&account.id).await.unwrap();
        assert!(saved.is_some());

        // 验证 provider 已注册
        let provider = svc.ctx.provider_registry().get(&account.id).await;
        assert!(provider.is_some());
    }

    #[tokio::test]
    async fn create_account_from_import_save_failure_cleanup() {
        let (svc, account_repo, credential_store, _) = create_test_account_service();

        // 设置 save 必定失败
        account_repo
            .set_save_error(Some("disk full".to_string()))
            .await;

        let result = svc
            .create_account_from_import(
                "Fail".to_string(),
                ProviderType::Cloudflare,
                test_credentials(),
            )
            .await;

        assert!(result.is_err());

        // 验证 cleanup：凭证被清理
        let all_creds = credential_store.load_all().await.unwrap();
        assert!(all_creds.is_empty());

        // 验证 cleanup：provider 已注销
        let ids = svc.ctx.provider_registry().list_account_ids().await;
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn delete_account_success() {
        let (svc, account_repo, credential_store, _) = create_test_account_service();

        let account = svc
            .create_account_from_import(
                "To Delete".to_string(),
                ProviderType::Cloudflare,
                test_credentials(),
            )
            .await
            .unwrap();
        let id = account.id.clone();

        svc.delete_account(&id).await.unwrap();

        // 账户元数据已删除
        assert!(account_repo.find_by_id(&id).await.unwrap().is_none());
        // 凭证已删除
        assert!(credential_store.get(&id).await.unwrap().is_none());
        // provider 已注销
        assert!(svc.ctx.provider_registry().get(&id).await.is_none());
    }

    #[tokio::test]
    async fn delete_account_not_found() {
        let (svc, _, _, _) = create_test_account_service();
        let result = svc.delete_account("nonexistent").await;
        assert!(matches!(result, Err(CoreError::AccountNotFound(_))));
    }

    #[tokio::test]
    async fn delete_account_cleans_domain_metadata() {
        let (svc, _, _, domain_meta_repo) = create_test_account_service();

        let account = svc
            .create_account_from_import(
                "Meta Test".to_string(),
                ProviderType::Cloudflare,
                test_credentials(),
            )
            .await
            .unwrap();
        let id = account.id.clone();

        // 为该账户的域名添加一些元数据
        use crate::types::{DomainMetadata, DomainMetadataKey};
        let key = DomainMetadataKey::new(id.clone(), "example.com".to_string());
        let mut meta = DomainMetadata::default();
        meta.is_favorite = true;
        meta.favorited_at = Some(chrono::Utc::now());
        domain_meta_repo.save(&key, &meta).await.unwrap();

        // 删除账户
        svc.delete_account(&id).await.unwrap();

        // 域名元数据也被清理了
        let found = domain_meta_repo.find_by_key(&key).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn batch_delete_accounts_partial_failure() {
        let (svc, _, _, _) = create_test_account_service();

        let acc = svc
            .create_account_from_import(
                "Keep".to_string(),
                ProviderType::Cloudflare,
                test_credentials(),
            )
            .await
            .unwrap();

        let result = svc
            .batch_delete_accounts(vec![acc.id.clone(), "nonexistent".to_string()])
            .await
            .unwrap();

        assert_eq!(result.success_count, 1);
        assert_eq!(result.failed_count, 1);
        assert_eq!(result.failures[0].record_id, "nonexistent");
    }

    #[tokio::test]
    async fn list_accounts() {
        let (svc, _, _, _) = create_test_account_service();

        svc.create_account_from_import(
            "A".to_string(),
            ProviderType::Cloudflare,
            test_credentials(),
        )
        .await
        .unwrap();
        svc.create_account_from_import(
            "B".to_string(),
            ProviderType::Cloudflare,
            test_credentials(),
        )
        .await
        .unwrap();

        let accounts = svc.list_accounts().await.unwrap();
        assert_eq!(accounts.len(), 2);
    }

    #[tokio::test]
    async fn get_account_found() {
        let (svc, _, _, _) = create_test_account_service();

        let acc = svc
            .create_account_from_import(
                "Find Me".to_string(),
                ProviderType::Cloudflare,
                test_credentials(),
            )
            .await
            .unwrap();

        let found = svc.get_account(&acc.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Find Me");
    }

    #[tokio::test]
    async fn get_account_not_found() {
        let (svc, _, _, _) = create_test_account_service();
        let found = svc.get_account("ghost").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn update_status() {
        let (svc, _, _, _) = create_test_account_service();

        let acc = svc
            .create_account_from_import(
                "Status".to_string(),
                ProviderType::Cloudflare,
                test_credentials(),
            )
            .await
            .unwrap();

        svc.update_status(&acc.id, AccountStatus::Error, Some("broken".to_string()))
            .await
            .unwrap();

        let updated = svc.get_account(&acc.id).await.unwrap().unwrap();
        assert_eq!(updated.status, Some(AccountStatus::Error));
        assert_eq!(updated.error, Some("broken".to_string()));
    }
}
