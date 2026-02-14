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
