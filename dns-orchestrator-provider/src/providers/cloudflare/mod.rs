//! Cloudflare DNS Provider

mod error;
mod http;
mod provider;
mod types;

use reqwest::Client;

use crate::providers::common::create_http_client;

pub(crate) use types::{CloudflareDnsRecord, CloudflareResponse, CloudflareZone};

pub(crate) const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";
/// Cloudflare Zones API 单页最大记录数
pub(crate) const MAX_PAGE_SIZE_ZONES: u32 = 50;
/// Cloudflare DNS Records API 单页最大记录数
pub(crate) const MAX_PAGE_SIZE_RECORDS: u32 = 100;

/// Cloudflare DNS Provider
pub struct CloudflareProvider {
    pub(crate) client: Client,
    pub(crate) api_token: String,
}

impl CloudflareProvider {
    pub fn new(api_token: String) -> Self {
        Self {
            client: create_http_client(),
            api_token,
        }
    }
}
