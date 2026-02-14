//! Account import and export service

use std::collections::HashSet;
use std::sync::Arc;

use dns_orchestrator_provider::ProviderCredentials;

use crate::crypto;
use crate::error::{CoreError, CoreResult};
use crate::services::account_service::AccountService;
use crate::types::{
    Account, ExportAccountsRequest, ExportAccountsResponse, ExportFile, ExportFileHeader,
    ExportedAccount, ImportAccountsRequest, ImportFailure, ImportPreview, ImportPreviewAccount,
    ImportResult,
};

/// Account import and export service
pub struct ImportExportService {
    account_service: Arc<AccountService>,
}

impl ImportExportService {
    /// Create an import and export service instance
    #[must_use]
    pub fn new(account_service: Arc<AccountService>) -> Self {
        Self { account_service }
    }

    /// Parse and decrypt the exported file and return the account list
    fn parse_and_decrypt_accounts(
        content: &str,
        password: Option<&str>,
    ) -> CoreResult<(ExportFile, Option<Vec<ExportedAccount>>)> {
        // 1. Parse the file
        let export_file: ExportFile = serde_json::from_str(content)
            .map_err(|e| CoreError::ImportExportError(format!("无效的导入文件: {e}")))?;

        // 2. Check the file format version and obtain encryption parameters
        let kdf_iterations = if export_file.header.encrypted {
            crypto::get_pbkdf2_iterations(export_file.header.version).ok_or_else(|| {
                CoreError::ImportExportError(format!(
                    "不支持的文件版本: {}",
                    export_file.header.version
                ))
            })?
        } else {
            0 // No iterations required for unencrypted files
        };

        // 3. If encrypted but no password is provided, return None indicating that a password is required.
        if export_file.header.encrypted && password.is_none() {
            return Ok((export_file, None));
        }

        // 4. Decrypt or directly parse account data
        let accounts: Vec<ExportedAccount> = if export_file.header.encrypted {
            let password = password
                .ok_or_else(|| CoreError::ImportExportError("加密文件需要提供密码".to_string()))?;

            log::info!(
                "解密版本 {} 的文件，使用 PBKDF2-HMAC-SHA256 ({} 次迭代)",
                export_file.header.version,
                kdf_iterations
            );

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

            // Decrypt using the number of iterations corresponding to the version
            let plaintext =
                crypto::decrypt_with_iterations(ciphertext, password, salt, nonce, kdf_iterations)
                    .map_err(|_| {
                        CoreError::ImportExportError("解密失败，请检查密码是否正确".to_string())
                    })?;

            serde_json::from_slice(&plaintext)
                .map_err(|e| CoreError::ImportExportError(format!("解析账号数据失败: {e}")))?
        } else {
            serde_json::from_value(export_file.data.clone())
                .map_err(|e| CoreError::ImportExportError(format!("解析账号数据失败: {e}")))?
        };

        Ok((export_file, Some(accounts)))
    }

    /// Export account
    ///
    /// # Arguments
    /// * `request` - export request (contains list of account IDs and encryption options)
    /// * `app_version` - application version number
    pub async fn export_accounts(
        &self,
        request: ExportAccountsRequest,
        app_version: &str,
    ) -> CoreResult<ExportAccountsResponse> {
        // 1. Get the metadata of the selected account
        let all_accounts = self.account_service.list_accounts().await?;
        let selected_accounts: Vec<&Account> = all_accounts
            .iter()
            .filter(|a| request.account_ids.contains(&a.id))
            .collect();

        if selected_accounts.is_empty() {
            return Err(CoreError::NoAccountsSelected);
        }

        // 2. Load credentials and build export data
        let mut exported_accounts = Vec::new();
        for account in selected_accounts {
            let Ok(credentials) = self.account_service.load_credentials(&account.id).await else {
                log::warn!(
                    "Failed to load credentials for account {}, skipping export",
                    account.id
                );
                continue;
            };

            // Convert ProviderCredentials to HashMap
            let credentials_map = credentials.to_map();

            exported_accounts.push(ExportedAccount {
                id: uuid::Uuid::new_v4().to_string(), // Generate new IDs to avoid conflicts when importing
                name: account.name.clone(),
                provider: account.provider.clone(),
                created_at: account.created_at,
                updated_at: account.updated_at,
                credentials: credentials_map,
            });
        }

        // 3. Serialize account data
        let accounts_json = serde_json::to_value(&exported_accounts)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        // 4. Build the export file
        let now = chrono::Utc::now();

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
                    version: crypto::CURRENT_FILE_VERSION,
                    encrypted: true,
                    salt: Some(salt),
                    nonce: Some(nonce),
                    exported_at: now.to_rfc3339(),
                    app_version: app_version.to_string(),
                },
                data: serde_json::Value::String(ciphertext),
            }
        } else {
            ExportFile {
                header: ExportFileHeader {
                    version: crypto::CURRENT_FILE_VERSION,
                    encrypted: false,
                    salt: None,
                    nonce: None,
                    exported_at: now.to_rfc3339(),
                    app_version: app_version.to_string(),
                },
                data: accounts_json,
            }
        };

        // 5. Generate file content
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

    /// Preview imported files
    pub async fn preview_import(
        &self,
        content: &str,
        password: Option<&str>,
    ) -> CoreResult<ImportPreview> {
        // 1. Parse and decrypt
        let (export_file, accounts_opt) = Self::parse_and_decrypt_accounts(content, password)?;

        // 2. If a password is required but not provided, return the prompt
        let Some(accounts) = accounts_opt else {
            return Ok(ImportPreview {
                encrypted: true,
                account_count: 0,
                accounts: None,
            });
        };

        // 3. Check for conflicts with existing accounts
        let existing_accounts = self.account_service.list_accounts().await?;
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

    /// Execute import
    pub async fn import_accounts(
        &self,
        request: ImportAccountsRequest,
    ) -> CoreResult<ImportResult> {
        // 1. Parse and decrypt
        let (_, accounts_opt) =
            Self::parse_and_decrypt_accounts(&request.content, request.password.as_deref())?;

        let accounts = accounts_opt
            .ok_or_else(|| CoreError::ImportExportError("加密文件需要提供密码".to_string()))?;

        // 2. Import accounts one by one
        let mut success_count = 0;
        let mut failures = Vec::new();

        for exported in accounts {
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

            match self
                .account_service
                .create_account_from_import(exported.name.clone(), exported.provider, credentials)
                .await
            {
                Ok(_) => success_count += 1,
                Err(e) => failures.push(ImportFailure {
                    name: exported.name,
                    reason: e.to_string(),
                }),
            }
        }

        Ok(ImportResult {
            success_count,
            failures,
        })
    }
}
