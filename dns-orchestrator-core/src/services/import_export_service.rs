//! 账户导入导出服务

use std::collections::HashSet;
use std::sync::Arc;

use dns_orchestrator_provider::{create_provider, ProviderCredentials};

use crate::crypto;
use crate::error::{CoreError, CoreResult};
use crate::services::ServiceContext;
use crate::types::{
    Account, AccountStatus, ExportAccountsRequest, ExportAccountsResponse, ExportFile,
    ExportFileHeader, ExportedAccount, ImportAccountsRequest, ImportFailure, ImportPreview,
    ImportPreviewAccount, ImportResult,
};

/// 账户导入导出服务
pub struct ImportExportService {
    ctx: Arc<ServiceContext>,
}

impl ImportExportService {
    /// 创建导入导出服务实例
    #[must_use]
    pub fn new(ctx: Arc<ServiceContext>) -> Self {
        Self { ctx }
    }

    /// 导出账户
    ///
    /// # Arguments
    /// * `request` - 导出请求（包含账户 ID 列表和加密选项）
    /// * `app_version` - 应用版本号
    pub async fn export_accounts(
        &self,
        request: ExportAccountsRequest,
        app_version: &str,
    ) -> CoreResult<ExportAccountsResponse> {
        // 1. 获取选中账号的元数据
        let all_accounts = self.ctx.account_repository.find_all().await?;
        let selected_accounts: Vec<&Account> = all_accounts
            .iter()
            .filter(|a| request.account_ids.contains(&a.id))
            .collect();

        if selected_accounts.is_empty() {
            return Err(CoreError::NoAccountsSelected);
        }

        // 2. 加载凭证并构建导出数据
        let mut exported_accounts = Vec::new();
        for account in selected_accounts {
            let credentials = match self.ctx.credential_store.load(&account.id).await {
                Ok(creds) => creds,
                Err(e) => {
                    log::warn!("Failed to load credentials for {}: {}", account.id, e);
                    continue;
                }
            };

            exported_accounts.push(ExportedAccount {
                id: uuid::Uuid::new_v4().to_string(), // 生成新 ID，避免导入时冲突
                name: account.name.clone(),
                provider: account.provider.clone(),
                created_at: account.created_at.clone(),
                updated_at: account.updated_at.clone(),
                credentials,
            });
        }

        // 3. 序列化账号数据
        let accounts_json = serde_json::to_value(&exported_accounts)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        // 4. 构建导出文件
        let now = chrono::Utc::now().to_rfc3339();

        let export_file = if request.encrypt {
            let password = request
                .password
                .as_ref()
                .ok_or_else(|| CoreError::ValidationError("加密导出需要提供密码".to_string()))?;

            let plaintext = serde_json::to_vec(&accounts_json)
                .map_err(|e| CoreError::SerializationError(e.to_string()))?;

            let (salt, nonce, ciphertext) = crypto::encrypt(&plaintext, password)
                .map_err(|e| CoreError::ImportExportError(e.to_string()))?;

            ExportFile {
                header: ExportFileHeader {
                    version: 1,
                    encrypted: true,
                    salt: Some(salt),
                    nonce: Some(nonce),
                    exported_at: now,
                    app_version: app_version.to_string(),
                },
                data: serde_json::Value::String(ciphertext),
            }
        } else {
            ExportFile {
                header: ExportFileHeader {
                    version: 1,
                    encrypted: false,
                    salt: None,
                    nonce: None,
                    exported_at: now,
                    app_version: app_version.to_string(),
                },
                data: accounts_json,
            }
        };

        // 5. 生成文件内容
        let content = serde_json::to_string_pretty(&export_file)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        let suggested_filename = format!(
            "dns-orchestrator-backup-{}.dnso",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        );

        Ok(ExportAccountsResponse {
            content,
            suggested_filename,
        })
    }

    /// 预览导入文件
    pub async fn preview_import(
        &self,
        content: &str,
        password: Option<&str>,
    ) -> CoreResult<ImportPreview> {
        // 1. 解析文件
        let export_file: ExportFile = serde_json::from_str(content)
            .map_err(|e| CoreError::ImportExportError(format!("无效的导入文件: {e}")))?;

        // 2. 检查版本
        if export_file.header.version > 1 {
            return Err(CoreError::UnsupportedFileVersion);
        }

        // 3. 如果加密但未提供密码，返回需要密码的提示
        if export_file.header.encrypted && password.is_none() {
            return Ok(ImportPreview {
                encrypted: true,
                account_count: 0,
                accounts: None,
            });
        }

        // 4. 解密或直接解析账号数据
        let accounts: Vec<ExportedAccount> = if export_file.header.encrypted {
            let password = password
                .ok_or_else(|| CoreError::ImportExportError("加密文件需要提供密码".to_string()))?;
            let ciphertext = export_file
                .data
                .as_str()
                .ok_or_else(|| CoreError::ImportExportError("无效的加密数据".to_string()))?;
            let salt = export_file
                .header
                .salt
                .as_ref()
                .ok_or_else(|| CoreError::ImportExportError("缺少加密盐值".to_string()))?;
            let nonce = export_file
                .header
                .nonce
                .as_ref()
                .ok_or_else(|| CoreError::ImportExportError("缺少加密 nonce".to_string()))?;

            let plaintext = crypto::decrypt(ciphertext, password, salt, nonce).map_err(|_| {
                CoreError::ImportExportError("解密失败，请检查密码是否正确".to_string())
            })?;

            serde_json::from_slice(&plaintext)
                .map_err(|e| CoreError::ImportExportError(format!("解析账号数据失败: {e}")))?
        } else {
            serde_json::from_value(export_file.data)
                .map_err(|e| CoreError::ImportExportError(format!("解析账号数据失败: {e}")))?
        };

        // 5. 检查与现有账号的冲突
        let existing_accounts = self.ctx.account_repository.find_all().await?;
        let existing_names: HashSet<_> =
            existing_accounts.iter().map(|a| a.name.as_str()).collect();

        let preview_accounts: Vec<ImportPreviewAccount> = accounts
            .iter()
            .map(|a| ImportPreviewAccount {
                name: a.name.clone(),
                provider: a.provider.clone(),
                has_conflict: existing_names.contains(a.name.as_str()),
            })
            .collect();

        Ok(ImportPreview {
            encrypted: export_file.header.encrypted,
            account_count: accounts.len(),
            accounts: Some(preview_accounts),
        })
    }

    /// 执行导入
    pub async fn import_accounts(
        &self,
        request: ImportAccountsRequest,
    ) -> CoreResult<ImportResult> {
        // 1. 解析和解密
        let export_file: ExportFile = serde_json::from_str(&request.content)
            .map_err(|e| CoreError::ImportExportError(format!("无效的导入文件: {e}")))?;

        let accounts: Vec<ExportedAccount> = if export_file.header.encrypted {
            let password = request
                .password
                .as_ref()
                .ok_or_else(|| CoreError::ImportExportError("加密文件需要提供密码".to_string()))?;
            let ciphertext = export_file
                .data
                .as_str()
                .ok_or_else(|| CoreError::ImportExportError("无效的加密数据".to_string()))?;
            let salt = export_file
                .header
                .salt
                .as_ref()
                .ok_or_else(|| CoreError::ImportExportError("缺少加密盐值".to_string()))?;
            let nonce = export_file
                .header
                .nonce
                .as_ref()
                .ok_or_else(|| CoreError::ImportExportError("缺少加密 nonce".to_string()))?;

            let plaintext = crypto::decrypt(ciphertext, password, salt, nonce).map_err(|_| {
                CoreError::ImportExportError("解密失败，请检查密码是否正确".to_string())
            })?;

            serde_json::from_slice(&plaintext)
                .map_err(|e| CoreError::ImportExportError(format!("解析账号数据失败: {e}")))?
        } else {
            serde_json::from_value(export_file.data)
                .map_err(|e| CoreError::ImportExportError(format!("解析账号数据失败: {e}")))?
        };

        // 2. 逐个导入账号
        let mut success_count = 0;
        let mut failures = Vec::new();
        let now = chrono::Utc::now().to_rfc3339();

        for exported in accounts {
            // 2.1 转换凭证并创建 provider 实例
            let credentials =
                match ProviderCredentials::from_map(&exported.provider, &exported.credentials) {
                    Ok(c) => c,
                    Err(e) => {
                        failures.push(ImportFailure {
                            name: exported.name.clone(),
                            reason: format!("凭证格式错误: {e}"),
                        });
                        continue;
                    }
                };
            let provider = match create_provider(credentials) {
                Ok(p) => p,
                Err(e) => {
                    failures.push(ImportFailure {
                        name: exported.name.clone(),
                        reason: format!("创建 Provider 失败: {e}"),
                    });
                    continue;
                }
            };

            // 2.2 生成新的账号 ID
            let account_id = uuid::Uuid::new_v4().to_string();

            // 2.3 保存凭证
            if let Err(e) = self
                .ctx
                .credential_store
                .save(&account_id, &exported.credentials)
                .await
            {
                failures.push(ImportFailure {
                    name: exported.name.clone(),
                    reason: format!("保存凭证失败: {e}"),
                });
                continue;
            }

            // 2.4 注册 provider
            self.ctx
                .provider_registry
                .register(account_id.clone(), provider)
                .await;

            // 2.5 创建账号元数据
            let account = Account {
                id: account_id.clone(),
                name: exported.name.clone(),
                provider: exported.provider,
                created_at: now.clone(),
                updated_at: now.clone(),
                status: Some(AccountStatus::Active),
                error: None,
            };

            // 2.6 保存到仓库，失败时 cleanup
            if let Err(e) = self.ctx.account_repository.save(&account).await {
                // Cleanup: 删除凭证和注销 provider
                let _ = self.ctx.credential_store.delete(&account_id).await;
                self.ctx.provider_registry.unregister(&account_id).await;

                failures.push(ImportFailure {
                    name: exported.name,
                    reason: format!("保存账户失败: {e}"),
                });
                continue;
            }

            success_count += 1;
        }

        Ok(ImportResult {
            success_count,
            failures,
        })
    }
}
