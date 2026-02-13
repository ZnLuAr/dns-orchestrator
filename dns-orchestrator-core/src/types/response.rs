//! API 响应相关类型定义

use serde::{Deserialize, Serialize};

/// API 响应包装类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// 是否成功
    pub success: bool,
    /// 响应数据
    pub data: Option<T>,
}

impl<T> ApiResponse<T> {
    /// 创建成功响应
    #[must_use]
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
        }
    }
}

/// 批量删除 DNS 记录请求
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeleteRequest {
    /// 域名 ID
    pub domain_id: String,
    /// 记录 ID 列表
    pub record_ids: Vec<String>,
}
