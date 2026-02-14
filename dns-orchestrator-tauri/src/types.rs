use serde::{Deserialize, Serialize};

// Re-export Core 应用层类型
pub use dns_orchestrator_core::types::{
    Account, AppDomain, BatchDeleteRequest, BatchTagRequest, BatchTagResult, CreateAccountRequest,
    DomainMetadata, DomainMetadataUpdate, ExportAccountsRequest, ExportAccountsResponse,
    ImportAccountsRequest, ImportPreview, ImportResult, UpdateAccountRequest,
};

// Re-export Provider 类型（通过 core re-export）
pub use dns_orchestrator_core::types::{
    BatchDeleteResult, CreateDnsRecordRequest, DnsRecord, DnsRecordType, PaginatedResponse,
    ProviderMetadata, UpdateDnsRecordRequest,
};

/// Domain 别名（保持命令层命名习惯）
pub type Domain = AppDomain;

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
