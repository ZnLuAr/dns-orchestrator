//! Tauri 账户仓库适配器
//!
//! 使用 tauri-plugin-store 实现账户持久化

use async_trait::async_trait;
use std::sync::Arc;
use tauri::AppHandle;
use tauri_plugin_store::StoreExt;
use tokio::sync::RwLock;

use dns_orchestrator_core::error::{CoreError, CoreResult};
use dns_orchestrator_core::traits::AccountRepository;
use dns_orchestrator_core::types::{Account, AccountStatus};

const STORE_FILE_NAME: &str = "accounts.json";
const ACCOUNTS_KEY: &str = "accounts";

/// Tauri 账户仓库实现
pub struct TauriAccountRepository {
    app_handle: AppHandle,
    /// 内存缓存
    cache: Arc<RwLock<Option<Vec<Account>>>>,
}

impl TauriAccountRepository {
    /// 创建新的账户仓库实例
    pub fn new(app_handle: AppHandle) -> Self {
        Self {
            app_handle,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// 从 Store 加载账户
    fn load_from_store(&self) -> CoreResult<Vec<Account>> {
        let store = self
            .app_handle
            .store(STORE_FILE_NAME)
            .map_err(|e| CoreError::StorageError(format!("Failed to access store: {e}")))?;

        let Some(value) = store.get(ACCOUNTS_KEY) else {
            return Ok(Vec::new());
        };

        serde_json::from_value(value.clone())
            .map_err(|e| CoreError::SerializationError(e.to_string()))
    }

    /// 保存账户到 Store
    fn save_to_store(&self, accounts: &[Account]) -> CoreResult<()> {
        let store = self
            .app_handle
            .store(STORE_FILE_NAME)
            .map_err(|e| CoreError::StorageError(format!("Failed to access store: {e}")))?;

        let value = serde_json::to_value(accounts)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        store.set(ACCOUNTS_KEY.to_string(), value);
        store
            .save()
            .map_err(|e| CoreError::StorageError(format!("Failed to save store: {e}")))?;

        log::debug!("Saved {} accounts to store", accounts.len());
        Ok(())
    }

    /// 确保写锁内的缓存已初始化，返回可变引用
    fn ensure_cache_loaded<'a>(
        &self,
        cache: &'a mut Option<Vec<Account>>,
    ) -> CoreResult<&'a mut Vec<Account>> {
        if cache.is_none() {
            let loaded = self.load_from_store()?;
            *cache = Some(loaded);
        }
        // SAFETY: `is_none()` 检查后立即填充，此处一定是 `Some`
        #[allow(clippy::unwrap_used)]
        Ok(cache.as_mut().unwrap())
    }
}

#[async_trait]
impl AccountRepository for TauriAccountRepository {
    async fn find_all(&self) -> CoreResult<Vec<Account>> {
        // 先检查缓存（读锁）
        {
            let cache = self.cache.read().await;
            if let Some(ref accounts) = *cache {
                return Ok(accounts.clone());
            }
        }

        // 缓存为空，拿写锁加载（double-check）
        let mut cache = self.cache.write().await;
        if let Some(ref accounts) = *cache {
            return Ok(accounts.clone());
        }

        let accounts = self.load_from_store()?;
        *cache = Some(accounts.clone());
        Ok(accounts)
    }

    async fn find_by_id(&self, id: &str) -> CoreResult<Option<Account>> {
        let accounts = self.find_all().await?;
        Ok(accounts.iter().find(|a| a.id == id).cloned())
    }

    async fn save(&self, account: &Account) -> CoreResult<()> {
        let mut cache = self.cache.write().await;
        let accounts = self.ensure_cache_loaded(&mut cache)?;

        // 查找是否已存在
        if let Some(pos) = accounts.iter().position(|a| a.id == account.id) {
            accounts[pos] = account.clone();
        } else {
            accounts.push(account.clone());
        }

        self.save_to_store(accounts)?;
        Ok(())
    }

    async fn delete(&self, id: &str) -> CoreResult<()> {
        let mut cache = self.cache.write().await;
        let accounts = self.ensure_cache_loaded(&mut cache)?;

        let initial_len = accounts.len();
        accounts.retain(|a| a.id != id);

        if accounts.len() == initial_len {
            return Err(CoreError::AccountNotFound(id.to_string()));
        }

        self.save_to_store(accounts)?;
        log::info!("Deleted account {id} from store");
        Ok(())
    }

    async fn save_all(&self, accounts: &[Account]) -> CoreResult<()> {
        self.save_to_store(accounts)?;

        let mut cache = self.cache.write().await;
        *cache = Some(accounts.to_vec());
        Ok(())
    }

    async fn update_status(
        &self,
        id: &str,
        status: AccountStatus,
        error: Option<String>,
    ) -> CoreResult<()> {
        let mut cache = self.cache.write().await;
        let accounts = self.ensure_cache_loaded(&mut cache)?;

        let account = accounts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| CoreError::AccountNotFound(id.to_string()))?;

        account.status = Some(status);
        account.error = error;
        account.updated_at = chrono::Utc::now();

        self.save_to_store(accounts)?;
        Ok(())
    }
}
