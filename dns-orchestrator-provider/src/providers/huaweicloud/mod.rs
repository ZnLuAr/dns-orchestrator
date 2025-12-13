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
}

impl HuaweicloudProvider {
    pub fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self {
            client: create_http_client(),
            access_key_id,
            secret_access_key,
        }
    }
}
