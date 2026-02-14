//! Huawei Cloud DNS API type definition

use serde::Deserialize;

// ============ Huawei Cloud API response structure ============

/// Response payload for `ListPublicZones`.
#[derive(Debug, Deserialize)]
pub struct ListZonesResponse {
    pub zones: Option<Vec<HuaweicloudZone>>,
    #[serde(rename = "metadata")]
    pub metadata: Option<ListMetadata>,
}

/// Pagination metadata for list APIs.
#[derive(Debug, Deserialize)]
pub struct ListMetadata {
    pub total_count: Option<u32>,
}

/// Public zone item returned by Huawei Cloud DNS APIs.
#[derive(Debug, Deserialize)]
pub struct HuaweicloudZone {
    pub id: String,
    pub name: String,
    pub status: Option<String>,
    pub record_num: Option<u32>,
}

/// Response payload for `ShowPublicZone`.
///
/// The API returns the zone object directly, so this is an alias.
pub type ShowPublicZoneResponse = HuaweicloudZone;

/// Response payload for `ListRecordSetsByZone`.
#[derive(Debug, Deserialize)]
pub struct ListRecordSetsResponse {
    pub recordsets: Option<Vec<HuaweicloudRecordSet>>,
    #[serde(rename = "metadata")]
    pub metadata: Option<ListMetadata>,
}

/// Record set item returned by Huawei Cloud DNS APIs.
#[derive(Debug, Deserialize)]
pub struct HuaweicloudRecordSet {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub records: Option<Vec<String>>,
    pub ttl: Option<u32>,
    #[serde(rename = "created_at")]
    pub created_at: Option<String>,
    #[serde(rename = "updated_at")]
    pub updated_at: Option<String>,
}

/// Response payload for `CreateRecordSet`.
#[derive(Debug, Deserialize)]
pub struct CreateRecordSetResponse {
    pub id: String,
}

/// Error payload returned by Huawei Cloud DNS APIs.
#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub code: Option<String>,
    pub message: Option<String>,
}
