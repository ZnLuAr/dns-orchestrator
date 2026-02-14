//! 腾讯云 `DNSPod` Provider

mod error;
mod http;
mod provider;
mod sign;
mod types;

use reqwest::Client;

use crate::providers::common::create_http_client;

pub(crate) use types::{
    CreateRecordResponse, DescribeDomainResponse, DomainListResponse, ModifyRecordResponse,
    RecordListResponse, TencentResponse,
};

pub(crate) const DNSPOD_API_HOST: &str = "dnspod.tencentcloudapi.com";
pub(crate) const DNSPOD_SERVICE: &str = "dnspod";
pub(crate) const DNSPOD_VERSION: &str = "2021-03-23";
/// `DNSPod` API 单页最大记录数
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
