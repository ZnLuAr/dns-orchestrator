//! Cloudflare DNS Provider

mod error;
mod http;
mod provider;
mod types;

use reqwest::Client;

use crate::providers::common::{DomainCache, create_http_client};

pub(crate) use types::{
    CloudflareCaaData, CloudflareDnsRecord, CloudflareResponse, CloudflareSrvData, CloudflareZone,
};

pub(crate) const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";
/// Cloudflare Zones API 单页最大记录数
pub(crate) const MAX_PAGE_SIZE_ZONES: u32 = 50;
/// Cloudflare DNS Records API 单页最大记录数
pub(crate) const MAX_PAGE_SIZE_RECORDS: u32 = 100;

/// Cloudflare DNS provider implementation.
///
/// Authenticates via Bearer token against the Cloudflare API v4.
///
/// # Construction
///
/// ```rust,no_run
/// use dns_orchestrator_provider::CloudflareProvider;
///
/// // Simple construction
/// let provider = CloudflareProvider::new("your-api-token".to_string());
///
/// // With custom retry count
/// let provider = CloudflareProvider::builder("your-api-token".to_string())
///     .max_retries(3)
///     .build();
/// ```
pub struct CloudflareProvider {
    pub(crate) client: Client,
    pub(crate) api_token: String,
    pub(crate) max_retries: u32,
    pub(crate) domain_cache: DomainCache,
}

/// Builder for [`CloudflareProvider`] with configurable retry behavior.
pub struct CloudflareProviderBuilder {
    api_token: String,
    max_retries: u32,
}

impl CloudflareProviderBuilder {
    fn new(api_token: String) -> Self {
        Self {
            api_token,
            max_retries: 2, // 默认重试 2 次
        }
    }

    /// Set the maximum number of automatic retries for transient errors (default: 2).
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Build the [`CloudflareProvider`] instance.
    pub fn build(self) -> CloudflareProvider {
        CloudflareProvider {
            client: create_http_client(),
            api_token: self.api_token,
            max_retries: self.max_retries,
            domain_cache: DomainCache::new(),
        }
    }
}

impl CloudflareProvider {
    /// Creates a new Cloudflare provider with default settings (2 retries).
    pub fn new(api_token: String) -> Self {
        Self::builder(api_token).build()
    }

    /// Returns a builder for customizing the provider configuration.
    pub fn builder(api_token: String) -> CloudflareProviderBuilder {
        CloudflareProviderBuilder::new(api_token)
    }
}
