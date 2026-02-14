//! DNS 记录相关类型定义

use serde::{Deserialize, Serialize};

/// 批量删除 DNS 记录请求
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeleteRequest {
    /// 域名 ID
    pub domain_id: String,
    /// 记录 ID 列表
    pub record_ids: Vec<String>,
}
