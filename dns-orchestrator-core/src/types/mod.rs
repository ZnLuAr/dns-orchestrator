//! 类型定义模块

mod account;
mod domain;
mod domain_metadata;
mod export;
mod response;

pub use account::{Account, AccountStatus, CreateAccountRequest, UpdateAccountRequest};
pub use domain::AppDomain;
pub use domain_metadata::{
    BatchTagFailure, BatchTagRequest, BatchTagResult, DomainMetadata, DomainMetadataKey,
    DomainMetadataUpdate,
};
pub use export::{
    ExportAccountsRequest, ExportAccountsResponse, ExportFile, ExportFileHeader, ExportedAccount,
    ImportAccountsRequest, ImportFailure, ImportPreview, ImportPreviewAccount, ImportResult,
};
pub use response::{ApiResponse, BatchDeleteRequest};

// Re-export provider 库的公共类型
pub use dns_orchestrator_provider::{
    BatchCreateFailure, BatchCreateResult, BatchDeleteFailure, BatchDeleteResult,
    BatchUpdateFailure, BatchUpdateItem, BatchUpdateResult, CreateDnsRecordRequest,
    CredentialValidationError, DnsRecord, DnsRecordType, DomainStatus, PaginatedResponse,
    PaginationParams, ProviderCredentials, ProviderDomain, ProviderMetadata, ProviderType,
    RecordData, RecordQueryParams, UpdateDnsRecordRequest,
};
