//! Tencent Cloud `DNSPod` API type definition

use serde::Deserialize;

// ============ Tencent Cloud API response structure ============

/// Generic Tencent Cloud response envelope.
#[derive(Debug, Deserialize)]
pub struct TencentResponse {
    #[serde(rename = "Response")]
    pub response: serde_json::Value,
}

/// Error payload nested inside Tencent Cloud responses.
#[derive(Debug, Deserialize)]
pub struct TencentError {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
}

// ============ DNSPod domain name related structure ============

/// Response payload for `DescribeDomainList`.
#[derive(Debug, Deserialize)]
pub struct DomainListResponse {
    #[serde(rename = "DomainList")]
    pub domain_list: Option<Vec<DnspodDomain>>,
    #[serde(rename = "DomainCountInfo")]
    pub domain_count_info: Option<DomainCountInfo>,
}

/// Domain count metadata from `DescribeDomainList`.
#[derive(Debug, Deserialize)]
pub struct DomainCountInfo {
    #[serde(rename = "AllTotal")]
    pub all_total: Option<u32>,
}

/// Domain item returned by DNSPod domain APIs.
#[derive(Debug, Deserialize)]
pub struct DnspodDomain {
    #[serde(rename = "DomainId")]
    pub domain_id: u64,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "DNSStatus")]
    pub dns_status: String,
    #[serde(rename = "RecordCount")]
    pub record_count: Option<u32>,
}

/// `DescribeDomain` API response structure
/// Response payload for `DescribeDomainList` with a single domain query.
#[derive(Debug, Deserialize)]
pub struct DescribeDomainResponse {
    #[serde(rename = "DomainInfo")]
    pub domain_info: DescribeDomainInfo,
}

/// `DomainInfo` nested structure
/// Nested domain information in `DescribeDomain`.
#[derive(Debug, Deserialize)]
pub struct DescribeDomainInfo {
    #[serde(rename = "DomainId")]
    pub domain_id: u64,
    #[serde(rename = "Domain")]
    pub domain: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "DNSStatus")]
    pub dns_status: String,
    #[serde(rename = "RecordCount")]
    pub record_count: Option<u32>,
}

// ============ DNSPod record related structure ============

/// Response payload for `DescribeRecordList`.
#[derive(Debug, Deserialize)]
pub struct RecordListResponse {
    #[serde(rename = "RecordList")]
    pub record_list: Option<Vec<DnspodRecord>>,
    #[serde(rename = "RecordCountInfo")]
    pub record_count_info: Option<RecordCountInfo>,
}

/// Record count metadata from `DescribeRecordList`.
#[derive(Debug, Deserialize)]
pub struct RecordCountInfo {
    #[serde(rename = "TotalCount")]
    pub total_count: Option<u32>,
}

/// DNS record item returned by DNSPod record APIs.
#[derive(Debug, Deserialize)]
pub struct DnspodRecord {
    #[serde(rename = "RecordId")]
    pub record_id: u64,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Type")]
    pub record_type: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    #[serde(rename = "MX")]
    pub mx: Option<u16>,
    #[serde(rename = "UpdatedOn")]
    pub updated_on: Option<String>,
}

/// Response payload for `CreateRecord`.
#[derive(Debug, Deserialize)]
pub struct CreateRecordResponse {
    #[serde(rename = "RecordId")]
    pub record_id: u64,
}

/// Response payload for `ModifyRecord`.
#[derive(Debug, Deserialize)]
pub struct ModifyRecordResponse {}
