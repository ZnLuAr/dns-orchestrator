//! Provider factory functions and metadata.

use std::sync::Arc;

use crate::error::Result;
use crate::traits::DnsProvider;
use crate::types::{ProviderCredentials, ProviderMetadata};

#[cfg(feature = "aliyun")]
use crate::providers::AliyunProvider;
#[cfg(feature = "cloudflare")]
use crate::providers::CloudflareProvider;
#[cfg(feature = "dnspod")]
use crate::providers::DnspodProvider;
#[cfg(feature = "huaweicloud")]
use crate::providers::HuaweicloudProvider;

/// Creates a [`DnsProvider`] instance from the given credentials.
///
/// The concrete provider type is determined by the [`ProviderCredentials`] variant.
/// The returned provider is wrapped in `Arc<dyn DnsProvider>` for easy sharing
/// across async tasks.
///
/// # Examples
///
/// ```rust,no_run
/// use dns_orchestrator_provider::{create_provider, ProviderCredentials};
///
/// let provider = create_provider(ProviderCredentials::Cloudflare {
///     api_token: "your-token".to_string(),
/// }).unwrap();
/// ```
pub fn create_provider(credentials: ProviderCredentials) -> Result<Arc<dyn DnsProvider>> {
    match credentials {
        #[cfg(feature = "cloudflare")]
        ProviderCredentials::Cloudflare { api_token } => {
            Ok(Arc::new(CloudflareProvider::new(api_token)))
        }
        #[cfg(feature = "aliyun")]
        ProviderCredentials::Aliyun {
            access_key_id,
            access_key_secret,
        } => Ok(Arc::new(AliyunProvider::new(
            access_key_id,
            access_key_secret,
        ))),
        #[cfg(feature = "dnspod")]
        ProviderCredentials::Dnspod {
            secret_id,
            secret_key,
        } => Ok(Arc::new(DnspodProvider::new(secret_id, secret_key))),
        #[cfg(feature = "huaweicloud")]
        ProviderCredentials::Huaweicloud {
            access_key_id,
            secret_access_key,
        } => Ok(Arc::new(HuaweicloudProvider::new(
            access_key_id,
            secret_access_key,
        ))),
    }
}

/// Returns metadata for all providers enabled via feature flags.
///
/// Useful for building dynamic UIs that enumerate available providers
/// and their required credential fields.
pub fn get_all_provider_metadata() -> Vec<ProviderMetadata> {
    vec![
        #[cfg(feature = "cloudflare")]
        CloudflareProvider::metadata(),
        #[cfg(feature = "aliyun")]
        AliyunProvider::metadata(),
        #[cfg(feature = "dnspod")]
        DnspodProvider::metadata(),
        #[cfg(feature = "huaweicloud")]
        HuaweicloudProvider::metadata(),
    ]
}
