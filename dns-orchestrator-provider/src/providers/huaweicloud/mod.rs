//! Huawei Cloud DNS Provider

mod error;
mod http;
mod provider;
mod sign;
/// Huawei Cloud API-specific request/response types.
pub(crate) mod types;

use reqwest::Client;

use crate::providers::common::{DomainCache, create_http_client};

/// Huawei Cloud DNS API host.
pub(crate) const HUAWEICLOUD_DNS_HOST: &str = "dns.myhuaweicloud.com";
/// Maximum number of records on a single page of Huawei Cloud API
pub(crate) const MAX_PAGE_SIZE: u32 = 500;

/// Huawei Cloud DNS provider implementation.
///
/// Authenticates via AK/SK request signing.
///
/// # Construction
///
/// ```rust,no_run
/// use dns_orchestrator_provider::HuaweicloudProvider;
///
/// let provider = HuaweicloudProvider::new(
///     "your-access-key-id".to_string(),
///     "your-secret-access-key".to_string(),
/// );
/// ```
pub struct HuaweicloudProvider {
    pub(crate) client: Client,
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
    pub(crate) max_retries: u32,
    pub(crate) domain_cache: DomainCache,
}

/// Builder for [`HuaweicloudProvider`] with configurable retry behavior.
pub struct HuaweicloudProviderBuilder {
    access_key_id: String,
    secret_access_key: String,
    max_retries: u32,
}

impl HuaweicloudProviderBuilder {
    fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            max_retries: 2,
        }
    }

    /// Set the maximum number of automatic retries for transient errors (default: 2).
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Build the [`HuaweicloudProvider`] instance.
    pub fn build(self) -> HuaweicloudProvider {
        HuaweicloudProvider {
            client: create_http_client(),
            access_key_id: self.access_key_id,
            secret_access_key: self.secret_access_key,
            max_retries: self.max_retries,
            domain_cache: DomainCache::new(),
        }
    }
}

impl HuaweicloudProvider {
    /// Creates a new Huawei Cloud provider with default settings (2 retries).
    pub fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self::builder(access_key_id, secret_access_key).build()
    }

    /// Returns a builder for customizing the provider configuration.
    pub fn builder(access_key_id: String, secret_access_key: String) -> HuaweicloudProviderBuilder {
        HuaweicloudProviderBuilder::new(access_key_id, secret_access_key)
    }
}
