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

/// 腾讯云 `DNSPod` Provider
pub struct DnspodProvider {
    pub(crate) client: Client,
    pub(crate) secret_id: String,
    pub(crate) secret_key: String,
    pub(crate) max_retries: u32,
}

/// `DNSPod` Provider Builder
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

    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

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
    pub fn new(secret_id: String, secret_key: String) -> Self {
        Self::builder(secret_id, secret_key).build()
    }

    pub fn builder(secret_id: String, secret_key: String) -> DnspodProviderBuilder {
        DnspodProviderBuilder::new(secret_id, secret_key)
    }
}
