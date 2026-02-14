//! 阿里云 DNS Provider

mod error;
mod http;
mod provider;
mod sign;
mod types;

use reqwest::Client;

use crate::providers::common::create_http_client;

pub(crate) use types::{
    AddDomainRecordResponse, DeleteDomainRecordResponse, DescribeDomainInfoResponse,
    DescribeDomainRecordsResponse, DescribeDomainsResponse, UpdateDomainRecordResponse,
    serialize_to_query_string,
};

pub(crate) const ALIYUN_DNS_HOST: &str = "alidns.cn-hangzhou.aliyuncs.com";
pub(crate) const ALIYUN_DNS_VERSION: &str = "2015-01-09";
/// 空 body 的 SHA256 hash (固定值)
pub(crate) const EMPTY_BODY_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// 阿里云 API 单页最大记录数
pub(crate) const MAX_PAGE_SIZE: u32 = 100;

/// Aliyun DNS provider implementation.
///
/// Authenticates via HMAC-SHA256 V3 signing with Access Key ID/Secret.
///
/// # Construction
///
/// ```rust,no_run
/// use dns_orchestrator_provider::AliyunProvider;
///
/// let provider = AliyunProvider::new(
///     "your-access-key-id".to_string(),
///     "your-access-key-secret".to_string(),
/// );
/// ```
pub struct AliyunProvider {
    pub(crate) client: Client,
    pub(crate) access_key_id: String,
    pub(crate) access_key_secret: String,
    pub(crate) max_retries: u32,
}

/// Builder for [`AliyunProvider`] with configurable retry behavior.
pub struct AliyunProviderBuilder {
    access_key_id: String,
    access_key_secret: String,
    max_retries: u32,
}

impl AliyunProviderBuilder {
    fn new(access_key_id: String, access_key_secret: String) -> Self {
        Self {
            access_key_id,
            access_key_secret,
            max_retries: 2,
        }
    }

    /// Set the maximum number of automatic retries for transient errors (default: 2).
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Build the [`AliyunProvider`] instance.
    pub fn build(self) -> AliyunProvider {
        AliyunProvider {
            client: create_http_client(),
            access_key_id: self.access_key_id,
            access_key_secret: self.access_key_secret,
            max_retries: self.max_retries,
        }
    }
}

impl AliyunProvider {
    /// Creates a new Aliyun provider with default settings (2 retries).
    pub fn new(access_key_id: String, access_key_secret: String) -> Self {
        Self::builder(access_key_id, access_key_secret).build()
    }

    /// Returns a builder for customizing the provider configuration.
    pub fn builder(access_key_id: String, access_key_secret: String) -> AliyunProviderBuilder {
        AliyunProviderBuilder::new(access_key_id, access_key_secret)
    }
}
