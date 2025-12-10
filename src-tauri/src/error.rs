use serde::Serialize;
use thiserror::Error;

// ============ Re-export 库错误类型 ============

pub use dns_orchestrator_provider::{
    // 凭证验证错误
    CredentialValidationError,
    // Provider 错误
    ProviderError,
};

// ============ 应用层错误类型 ============

#[derive(Error, Debug, Serialize)]
#[serde(tag = "code", content = "details")]
pub enum DnsError {
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Domain not found: {0}")]
    DomainNotFound(String),

    #[error("Record not found: {0}")]
    RecordNotFound(String),

    #[error("Credential error: {0}")]
    CredentialError(String),

    /// 凭证验证错误（结构化，支持字段级别错误）
    #[error("{0}")]
    CredentialValidation(CredentialValidationError),

    #[error("API error: {provider} - {message}")]
    ApiError { provider: String, message: String },

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Import/Export error: {0}")]
    ImportExportError(String),

    /// 没有选中任何账号（导出时）
    #[error("No accounts selected")]
    NoAccountsSelected,

    /// 不支持的文件版本（导入时）
    #[error("Unsupported file version")]
    UnsupportedFileVersion,

    /// Provider 错误（从库转换）
    #[error("{0}")]
    Provider(#[from] ProviderError),
}

pub type Result<T> = std::result::Result<T, DnsError>;
