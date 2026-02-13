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

/// 阿里云 DNS Provider
pub struct AliyunProvider {
    pub(crate) client: Client,
    pub(crate) access_key_id: String,
    pub(crate) access_key_secret: String,
    pub(crate) max_retries: u32,
}

/// 阿里云 Provider Builder
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

    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

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
    pub fn new(access_key_id: String, access_key_secret: String) -> Self {
        Self::builder(access_key_id, access_key_secret).build()
    }

    pub fn builder(access_key_id: String, access_key_secret: String) -> AliyunProviderBuilder {
        AliyunProviderBuilder::new(access_key_id, access_key_secret)
    }
}
