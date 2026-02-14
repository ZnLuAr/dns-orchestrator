//! Tencent Cloud `DNSPod` Provider

mod error;
mod http;
mod provider;
mod sign;
mod types;

use reqwest::Client;

use crate::providers::common::{DomainCache, create_http_client};

pub(crate) use types::{
    CreateRecordResponse, DescribeDomainResponse, DomainListResponse, ModifyRecordResponse,
    RecordListResponse, TencentError, TencentResponse,
};

/// Tencent Cloud `DNSPod` API host.
pub(crate) const DNSPOD_API_HOST: &str = "dnspod.tencentcloudapi.com";
/// Tencent Cloud service name used in TC3 signing scope.
pub(crate) const DNSPOD_SERVICE: &str = "dnspod";
/// Tencent Cloud `DNSPod` API version.
pub(crate) const DNSPOD_VERSION: &str = "2021-03-23";
/// `DNSPod` API maximum number of records in a single page
pub(crate) const MAX_PAGE_SIZE: u32 = 100;

/// Tencent Cloud `DNSPod` provider implementation.
///
/// Authenticates via TC3-HMAC-SHA256 signing with Secret ID/Key.
///
/// # Construction
///
/// ```rust,no_run
/// use dns_orchestrator_provider::DnspodProvider;
///
/// let provider = DnspodProvider::new(
///     "your-secret-id".to_string(),
///     "your-secret-key".to_string(),
/// );
/// ```
pub struct DnspodProvider {
    pub(crate) client: Client,
    pub(crate) secret_id: String,
    pub(crate) secret_key: String,
    pub(crate) max_retries: u32,
    pub(crate) domain_cache: DomainCache,
}

/// Builder for [`DnspodProvider`] with configurable retry behavior.
pub struct DnspodProviderBuilder {
    secret_id: String,
    secret_key: String,
    max_retries: u32,
}

impl DnspodProviderBuilder {
    fn new(secret_id: String, secret_key: String) -> Self {
        Self {
            secret_id,
            secret_key,
            max_retries: 2,
        }
    }

    /// Set the maximum number of automatic retries for transient errors (default: 2).
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Build the [`DnspodProvider`] instance.
    pub fn build(self) -> DnspodProvider {
        DnspodProvider {
            client: create_http_client(),
            secret_id: self.secret_id,
            secret_key: self.secret_key,
            max_retries: self.max_retries,
            domain_cache: DomainCache::new(),
        }
    }
}

impl DnspodProvider {
    /// Creates a new `DNSPod` provider with default settings (2 retries).
    pub fn new(secret_id: String, secret_key: String) -> Self {
        Self::builder(secret_id, secret_key).build()
    }

    /// Returns a builder for customizing the provider configuration.
    pub fn builder(secret_id: String, secret_key: String) -> DnspodProviderBuilder {
        DnspodProviderBuilder::new(secret_id, secret_key)
    }
}
