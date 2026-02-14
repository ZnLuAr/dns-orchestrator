//! Provider registry abstract Trait

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use dns_orchestrator_provider::DnsProvider;

/// Provider Registry Trait
///
/// Manages all registered Provider instances, indexed by `account_id`.
/// Provides a default memory implementation of `InMemoryProviderRegistry`.
#[async_trait]
pub trait ProviderRegistry: Send + Sync {
    /// Register a Provider instance
    ///
    /// # Arguments
    /// * `account_id` - Account ID
    /// * `provider` - Provider instance
    async fn register(&self, account_id: String, provider: Arc<dyn DnsProvider>);

    /// Log out Provider
    ///
    /// # Arguments
    /// * `account_id` - Account ID
    async fn unregister(&self, account_id: &str);

    /// Get Provider instance
    ///
    /// # Arguments
    /// * `account_id` - Account ID
    async fn get(&self, account_id: &str) -> Option<Arc<dyn DnsProvider>>;

    /// List all registered `account_id`
    async fn list_account_ids(&self) -> Vec<String>;
}

/// In-memory Provider registry
///
/// Default implementation, available on all platforms.
#[derive(Clone)]
pub struct InMemoryProviderRegistry {
    providers: Arc<RwLock<HashMap<String, Arc<dyn DnsProvider>>>>,
}

impl InMemoryProviderRegistry {
    /// Create a new memory registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderRegistry for InMemoryProviderRegistry {
    async fn register(&self, account_id: String, provider: Arc<dyn DnsProvider>) {
        self.providers.write().await.insert(account_id, provider);
    }

    async fn unregister(&self, account_id: &str) {
        self.providers.write().await.remove(account_id);
    }

    async fn get(&self, account_id: &str) -> Option<Arc<dyn DnsProvider>> {
        self.providers.read().await.get(account_id).cloned()
    }

    async fn list_account_ids(&self) -> Vec<String> {
        self.providers.read().await.keys().cloned().collect()
    }
}
