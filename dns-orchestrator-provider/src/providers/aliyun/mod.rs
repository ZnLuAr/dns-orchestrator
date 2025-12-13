//! 阿里云 DNS Provider

mod error;
mod http;
mod provider;
mod sign;
mod types;

use reqwest::Client;

use crate::providers::common::create_http_client;

pub(crate) use types::{
    AddDomainRecordResponse, AliyunResponse, DeleteDomainRecordResponse,
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
}

impl AliyunProvider {
    pub fn new(access_key_id: String, access_key_secret: String) -> Self {
        Self {
            client: create_http_client(),
            access_key_id,
            access_key_secret,
        }
    }
}
