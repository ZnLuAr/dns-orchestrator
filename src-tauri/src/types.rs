// Re-export Core 应用层类型
pub use dns_orchestrator_core::types::{
    Account, ApiResponse, AppDomain, BatchDeleteRequest, BatchTagRequest, BatchTagResult,
    CreateAccountRequest, DomainMetadata, DomainMetadataUpdate, ExportAccountsRequest,
    ExportAccountsResponse, ImportAccountsRequest, ImportPreview, ImportResult,
    UpdateAccountRequest,
};

// Re-export Provider 类型（通过 core re-export）
pub use dns_orchestrator_core::types::{
    BatchDeleteResult, CreateDnsRecordRequest, DnsRecord, DnsRecordType, PaginatedResponse,
    ProviderMetadata, UpdateDnsRecordRequest,
};

/// Domain 别名（保持命令层命名习惯）
pub type Domain = AppDomain;
