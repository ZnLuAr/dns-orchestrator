//! 华为云 DNS Provider

mod error;
mod http;
mod provider;
mod sign;
pub(crate) mod types;

use reqwest::Client;

use crate::providers::common::create_http_client;

pub(crate) const HUAWEICLOUD_DNS_HOST: &str = "dns.myhuaweicloud.com";
/// 华为云 API 单页最大记录数
pub(crate) const MAX_PAGE_SIZE: u32 = 500;

/// 华为云 DNS Provider
pub struct HuaweicloudProvider {
    pub(crate) client: Client,
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
    pub(crate) max_retries: u32,
}

/// 华为云 Provider Builder
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

    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    pub fn build(self) -> HuaweicloudProvider {
        HuaweicloudProvider {
            client: create_http_client(),
            access_key_id: self.access_key_id,
            secret_access_key: self.secret_access_key,
            max_retries: self.max_retries,
        }
    }
}

impl HuaweicloudProvider {
    pub fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self::builder(access_key_id, secret_access_key).build()
    }

    pub fn builder(access_key_id: String, secret_access_key: String) -> HuaweicloudProviderBuilder {
        HuaweicloudProviderBuilder::new(access_key_id, secret_access_key)
    }
}
