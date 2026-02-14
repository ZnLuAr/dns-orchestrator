//! DNS record related type definitions

use serde::{Deserialize, Serialize};

/// Bulk delete DNS record requests
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeleteRequest {
    /// Domain ID
    pub domain_id: String,
    /// Record ID list
    pub record_ids: Vec<String>,
}
