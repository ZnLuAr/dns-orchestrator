//! Provider factory functions and metadata

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

/// 工厂函数 - 根据凭证类型创建 Provider 实例
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

/// 获取所有支持的提供商元数据
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
