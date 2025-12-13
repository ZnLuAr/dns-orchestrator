//! Tauri 凭证存储适配器
//!
//! 将同步的 keyring/stronghold 实现包装为 async trait

use async_trait::async_trait;
use std::collections::HashMap;

use dns_orchestrator_core::error::{CoreError, CoreResult};
use dns_orchestrator_core::traits::{CredentialStore, CredentialsMap};

// ============ 桌面端实现 (Keychain) ============

#[cfg(not(target_os = "android"))]
mod desktop {
    use super::{async_trait, CoreError, CoreResult, CredentialStore, CredentialsMap, HashMap};
    use keyring::Entry;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    const SERVICE_NAME: &str = "dns-orchestrator";
    const CREDENTIALS_KEY: &str = "all-credentials";

    /// Tauri 桌面端凭证存储（使用系统 Keychain + 内存缓存）
    pub struct TauriCredentialStore {
        /// 内存缓存，减少 Keychain 访问频率
        cache: Arc<RwLock<Option<CredentialsMap>>>,
    }

    impl TauriCredentialStore {
        pub fn new() -> Self {
            Self {
                cache: Arc::new(RwLock::new(None)),
            }
        }

        fn get_entry() -> CoreResult<Entry> {
            Entry::new(SERVICE_NAME, CREDENTIALS_KEY)
                .map_err(|e| CoreError::CredentialError(e.to_string()))
        }

        fn read_all_sync() -> CoreResult<CredentialsMap> {
            let entry = Self::get_entry()?;

            match entry.get_password() {
                Ok(json) => serde_json::from_str(&json)
                    .map_err(|e| CoreError::SerializationError(e.to_string())),
                Err(keyring::Error::NoEntry) => Ok(HashMap::new()),
                Err(e) => Err(CoreError::CredentialError(e.to_string())),
            }
        }

        fn write_all_sync(credentials: &CredentialsMap) -> CoreResult<()> {
            let entry = Self::get_entry()?;

            let json = serde_json::to_string(credentials)
                .map_err(|e| CoreError::SerializationError(e.to_string()))?;

            entry
                .set_password(&json)
                .map_err(|e| CoreError::CredentialError(e.to_string()))?;

            Ok(())
        }
    }

    impl Default for TauriCredentialStore {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl CredentialStore for TauriCredentialStore {
        async fn load_all(&self) -> CoreResult<CredentialsMap> {
            // 先检查缓存
            {
                let cache = self.cache.read().await;
                if let Some(ref creds) = *cache {
                    return Ok(creds.clone());
                }
            }

            // 从 Keychain 加载
            let credentials = tokio::task::spawn_blocking(|| {
                log::debug!("Loading all credentials from Keychain");
                Self::read_all_sync()
            })
            .await
            .map_err(|e| CoreError::CredentialError(format!("Task join error: {e}")))??;

            // 更新缓存
            {
                let mut cache = self.cache.write().await;
                *cache = Some(credentials.clone());
            }

            log::info!("Loaded {} accounts from Keychain", credentials.len());
            Ok(credentials)
        }

        async fn save(
            &self,
            account_id: &str,
            credentials: &HashMap<String, String>,
        ) -> CoreResult<()> {
            let mut all_credentials = self.load_all().await?;
            all_credentials.insert(account_id.to_string(), credentials.clone());

            let all_creds_for_save = all_credentials.clone();
            tokio::task::spawn_blocking(move || Self::write_all_sync(&all_creds_for_save))
                .await
                .map_err(|e| CoreError::CredentialError(format!("Task join error: {e}")))??;

            // 更新缓存
            {
                let mut cache = self.cache.write().await;
                *cache = Some(all_credentials);
            }

            log::info!("Credentials saved for account: {account_id}");
            Ok(())
        }

        async fn load(&self, account_id: &str) -> CoreResult<HashMap<String, String>> {
            let all_credentials = self.load_all().await?;

            all_credentials.get(account_id).cloned().ok_or_else(|| {
                CoreError::CredentialError(format!(
                    "No credentials found for account: {account_id}"
                ))
            })
        }

        async fn delete(&self, account_id: &str) -> CoreResult<()> {
            let mut all_credentials = self.load_all().await?;
            all_credentials.remove(account_id);

            let all_creds_for_save = all_credentials.clone();
            tokio::task::spawn_blocking(move || Self::write_all_sync(&all_creds_for_save))
                .await
                .map_err(|e| CoreError::CredentialError(format!("Task join error: {e}")))??;

            // 更新缓存
            {
                let mut cache = self.cache.write().await;
                *cache = Some(all_credentials);
            }

            log::info!("Credentials deleted for account: {account_id}");
            Ok(())
        }

        async fn exists(&self, account_id: &str) -> CoreResult<bool> {
            let creds = self.load_all().await?;
            Ok(creds.contains_key(account_id))
        }
    }
}

// ============ Android 实现 (Stronghold via Store) ============

#[cfg(target_os = "android")]
mod android {
    use super::*;
    use std::sync::Arc;
    use tauri::AppHandle;
    use tauri_plugin_store::StoreExt;
    use tokio::sync::RwLock;

    const STORE_FILE_NAME: &str = "credentials.json";
    const CREDENTIALS_KEY: &str = "credentials";

    /// Tauri Android 凭证存储
    ///
    /// 使用 tauri-plugin-store 将凭证持久化到应用私有目录。
    /// 注意：这不是加密存储，依赖 Android 沙箱机制保护数据。
    pub struct TauriCredentialStore {
        app_handle: AppHandle,
        cache: Arc<RwLock<Option<CredentialsMap>>>,
    }

    impl TauriCredentialStore {
        pub fn new(app_handle: AppHandle) -> Self {
            Self {
                app_handle,
                cache: Arc::new(RwLock::new(None)),
            }
        }

        fn load_from_store(&self) -> CoreResult<CredentialsMap> {
            let store = self
                .app_handle
                .store(STORE_FILE_NAME)
                .map_err(|e| CoreError::StorageError(format!("Failed to access store: {e}")))?;

            let Some(value) = store.get(CREDENTIALS_KEY) else {
                return Ok(HashMap::new());
            };

            serde_json::from_value(value.clone())
                .map_err(|e| CoreError::SerializationError(e.to_string()))
        }

        fn save_to_store(&self, credentials: &CredentialsMap) -> CoreResult<()> {
            let store = self
                .app_handle
                .store(STORE_FILE_NAME)
                .map_err(|e| CoreError::StorageError(format!("Failed to access store: {e}")))?;

            let value = serde_json::to_value(credentials)
                .map_err(|e| CoreError::SerializationError(e.to_string()))?;

            store.set(CREDENTIALS_KEY.to_string(), value);
            store
                .save()
                .map_err(|e| CoreError::StorageError(format!("Failed to save store: {e}")))?;

            Ok(())
        }
    }

    #[async_trait]
    impl CredentialStore for TauriCredentialStore {
        async fn load_all(&self) -> CoreResult<CredentialsMap> {
            // 先检查缓存
            {
                let cache = self.cache.read().await;
                if let Some(ref creds) = *cache {
                    return Ok(creds.clone());
                }
            }

            // 从 Store 加载
            let credentials = self.load_from_store()?;

            // 更新缓存
            {
                let mut cache = self.cache.write().await;
                *cache = Some(credentials.clone());
            }

            log::info!("Loaded {} accounts from Store", credentials.len());
            Ok(credentials)
        }

        async fn save(
            &self,
            account_id: &str,
            credentials: &HashMap<String, String>,
        ) -> CoreResult<()> {
            let mut all_credentials = self.load_all().await?;
            all_credentials.insert(account_id.to_string(), credentials.clone());

            self.save_to_store(&all_credentials)?;

            // 更新缓存
            {
                let mut cache = self.cache.write().await;
                *cache = Some(all_credentials);
            }

            log::info!("Credentials saved for account: {account_id}");
            Ok(())
        }

        async fn load(&self, account_id: &str) -> CoreResult<HashMap<String, String>> {
            let all_credentials = self.load_all().await?;

            all_credentials.get(account_id).cloned().ok_or_else(|| {
                CoreError::CredentialError(format!(
                    "No credentials found for account: {account_id}"
                ))
            })
        }

        async fn delete(&self, account_id: &str) -> CoreResult<()> {
            let mut all_credentials = self.load_all().await?;
            all_credentials.remove(account_id);

            self.save_to_store(&all_credentials)?;

            // 更新缓存
            {
                let mut cache = self.cache.write().await;
                *cache = Some(all_credentials);
            }

            log::info!("Credentials deleted for account: {account_id}");
            Ok(())
        }

        async fn exists(&self, account_id: &str) -> CoreResult<bool> {
            let creds = self.load_all().await?;
            Ok(creds.contains_key(account_id))
        }
    }
}

// Re-export 平台特定实现
#[cfg(not(target_os = "android"))]
pub use desktop::TauriCredentialStore;

#[cfg(target_os = "android")]
pub use android::TauriCredentialStore;
