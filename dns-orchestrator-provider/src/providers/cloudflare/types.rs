//! Cloudflare API type definitions

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Cloudflare API generic response
#[derive(Debug, Deserialize)]
pub struct CloudflareResponse<T> {
    pub success: bool,
    pub result: Option<T>,
    pub errors: Option<Vec<CloudflareError>>,
    pub result_info: Option<CloudflareResultInfo>,
}

/// Error entry returned in `errors` by Cloudflare APIs.
#[derive(Debug, Deserialize)]
pub struct CloudflareError {
    pub code: i32,
    pub message: String,
}

/// Pagination metadata from Cloudflare list endpoints.
#[derive(Debug, Deserialize)]
pub struct CloudflareResultInfo {
    pub total_count: u32,
}

/// Cloudflare Zone structure
#[derive(Debug, Deserialize)]
pub struct CloudflareZone {
    pub id: String,
    pub name: String,
    pub status: String,
}

/// Cloudflare DNS Record structure (response)
#[derive(Debug, Deserialize)]
pub struct CloudflareDnsRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_on: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_on: Option<String>,
    /// Structured data of complex record types such as SRV/CAA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// The data field of the SRV record
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudflareSrvData {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
    /// Service name and protocol of SRV record (optional, API may return)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The data field of the CAA record
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudflareCaaData {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}
