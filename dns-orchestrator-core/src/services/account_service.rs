//! 账户管理服务

use std::sync::Arc;

use dns_orchestrator_provider::{create_provider, get_all_provider_metadata, ProviderCredentials};

use crate::error::{CoreError, CoreResult};
use crate::services::ServiceContext;
use crate::types::{Account, AccountStatus, CreateAccountRequest, ProviderMetadata};

/// 账户管理服务
pub struct AccountService {
    ctx: Arc<ServiceContext>,
}

impl AccountService {
    /// 创建账户服务实例
    #[must_use]
    pub fn new(ctx: Arc<ServiceContext>) -> Self {
        Self { ctx }
    }

    /// 列出所有账户
    pub async fn list_accounts(&self) -> CoreResult<Vec<Account>> {
        let accounts = self.ctx.account_repository.find_all().await?;
        Ok((*accounts).clone())
    }

    /// 创建账户
    ///
    /// 流程: 验证凭证 -> 保存凭证 -> 注册 Provider -> 保存元数据
    /// 如果保存元数据失败，会自动清理已保存的凭证和已注册的 Provider
    pub async fn create_account(&self, request: CreateAccountRequest) -> CoreResult<Account> {
        // 1. 转换凭证并创建 provider 实例
        let credentials = ProviderCredentials::from_map(&request.provider, &request.credentials)
            .map_err(CoreError::CredentialValidation)?;
        let provider = create_provider(credentials)?;

        // 2. 验证凭证
        let is_valid = provider.validate_credentials().await?;
        if !is_valid {
            return Err(CoreError::InvalidCredentials(request.provider.to_string()));
        }

        // 3. 生成账号 ID
        let account_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        // 4. 保存凭证
        log::info!("Saving credentials for account: {account_id}");
        self.ctx
            .credential_store
            .save(&account_id, &request.credentials)
            .await
            .map_err(|e| {
                log::error!("Failed to save credentials: {e}");
                CoreError::CredentialError(e.to_string())
            })?;
        log::info!("Credentials saved successfully");

        // 5. 注册 provider 到 registry
        self.ctx
            .provider_registry
            .register(account_id.clone(), provider)
            .await;

        // 6. 创建账号元数据
        let account = Account {
            id: account_id.clone(),
            name: request.name,
            provider: request.provider,
            created_at: now.clone(),
            updated_at: now,
            status: Some(AccountStatus::Active),
            error: None,
        };

        // 7. 保存账号元数据，失败时 cleanup
        if let Err(e) = self.ctx.account_repository.save(&account).await {
            log::error!("Failed to save account metadata, cleaning up: {e}");
            // Cleanup: 删除凭证和注销 provider
            let _ = self.ctx.credential_store.delete(&account_id).await;
            self.ctx.provider_registry.unregister(&account_id).await;
            return Err(e);
        }

        Ok(account)
    }

    /// 删除账户
    ///
    /// 流程: 注销 Provider -> 删除凭证 -> 删除元数据
    pub async fn delete_account(&self, account_id: &str) -> CoreResult<()> {
        // 1. 检查账户存在
        self.ctx
            .account_repository
            .find_by_id(account_id)
            .await?
            .ok_or_else(|| CoreError::AccountNotFound(account_id.to_string()))?;

        // 2. 注销 provider
        self.ctx.provider_registry.unregister(account_id).await;

        // 3. 删除凭证 (忽略错误，凭证可能不存在)
        let _ = self.ctx.credential_store.delete(account_id).await;

        // 4. 删除账号元数据
        self.ctx.account_repository.delete(account_id).await?;

        Ok(())
    }

    /// 获取所有支持的提供商列表
    #[must_use]
    pub fn list_providers(&self) -> Vec<ProviderMetadata> {
        get_all_provider_metadata()
    }

    /// 恢复账户（启动时调用）
    ///
    /// 从持久化存储加载账户，并重建 Provider 实例
    pub async fn restore_accounts(&self) -> CoreResult<RestoreResult> {
        let mut success_count = 0;
        let mut error_count = 0;

        // 1. 加载所有账户元数据
        let accounts = self.ctx.account_repository.find_all().await?;

        // 2. 加载所有凭证
        let all_credentials = match self.ctx.credential_store.load_all().await {
            Ok(creds) => creds,
            Err(e) => {
                log::error!("Failed to load credentials: {e}");
                // 标记所有账户为错误状态
                for account in accounts.iter() {
                    let _ = self
                        .ctx
                        .account_repository
                        .update_status(&account.id, AccountStatus::Error, Some(e.to_string()))
                        .await;
                }
                return Ok(RestoreResult {
                    success_count: 0,
                    error_count: accounts.len(),
                });
            }
        };

        // 3. 逐个恢复账户
        for account in accounts.iter() {
            let Some(credentials) = all_credentials.get(&account.id) else {
                log::warn!("No credentials found for account: {}", account.id);
                let _ = self
                    .ctx
                    .account_repository
                    .update_status(
                        &account.id,
                        AccountStatus::Error,
                        Some("凭证不存在".to_string()),
                    )
                    .await;
                error_count += 1;
                continue;
            };

            // 转换凭证并创建 provider
            let provider_credentials =
                match ProviderCredentials::from_map(&account.provider, credentials) {
                    Ok(c) => c,
                    Err(e) => {
                        log::warn!("Invalid credentials for account {}: {}", account.id, e);
                        let _ = self
                            .ctx
                            .account_repository
                            .update_status(
                                &account.id,
                                AccountStatus::Error,
                                Some(format!("凭证格式错误: {e}")),
                            )
                            .await;
                        error_count += 1;
                        continue;
                    }
                };

            let provider = match create_provider(provider_credentials) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!(
                        "Failed to create provider for account {}: {}",
                        account.id,
                        e
                    );
                    let _ = self
                        .ctx
                        .account_repository
                        .update_status(
                            &account.id,
                            AccountStatus::Error,
                            Some(format!("创建 Provider 失败: {e}")),
                        )
                        .await;
                    error_count += 1;
                    continue;
                }
            };

            // 注册 provider
            self.ctx
                .provider_registry
                .register(account.id.clone(), provider)
                .await;

            // 更新状态为 Active
            let _ = self
                .ctx
                .account_repository
                .update_status(&account.id, AccountStatus::Active, None)
                .await;

            success_count += 1;
        }

        Ok(RestoreResult {
            success_count,
            error_count,
        })
    }
}

/// 账户恢复结果
#[derive(Debug, Clone)]
pub struct RestoreResult {
    /// 成功恢复的账户数
    pub success_count: usize,
    /// 恢复失败的账户数
    pub error_count: usize,
}
