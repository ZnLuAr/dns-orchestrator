//! 腾讯云 DNSPod Provider

mod error;
mod http;
mod provider;
mod sign;
mod types;

use reqwest::Client;

use crate::providers::common::create_http_client;

pub(crate) use types::{
    CreateRecordResponse, DomainListResponse, ModifyRecordResponse, RecordListResponse,
    TencentResponse,
};

pub(crate) const DNSPOD_API_HOST: &str = "dnspod.tencentcloudapi.com";
pub(crate) const DNSPOD_SERVICE: &str = "dnspod";
pub(crate) const DNSPOD_VERSION: &str = "2021-03-23";
/// DNSPod API 单页最大记录数
pub(crate) const MAX_PAGE_SIZE: u32 = 100;

/// 腾讯云 DNSPod Provider
pub struct DnspodProvider {
    pub(crate) client: Client,
    pub(crate) secret_id: String,
    pub(crate) secret_key: String,
}

impl DnspodProvider {
    pub fn new(secret_id: String, secret_key: String) -> Self {
        Self {
            client: create_http_client(),
            secret_id,
            secret_key,
        }
    }
}
