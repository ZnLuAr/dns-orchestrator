//! Unified error type definition

use serde::Serialize;
use thiserror::Error;

// Re-export library error type
pub use dns_orchestrator_provider::{CredentialValidationError, ProviderError};

/// Core layer error type
#[derive(Error, Debug, Serialize)]
#[serde(tag = "code", content = "details")]
pub enum CoreError {
    /// Provider not found
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    /// Account not found
    #[error("Account not found: {0}")]
    AccountNotFound(String),

    /// Domain name not found
    #[error("Domain not found: {0}")]
    DomainNotFound(String),

    /// Record not found
    #[error("Record not found: {0}")]
    RecordNotFound(String),

    /// Credential storage error
    #[error("Credential error: {0}")]
    CredentialError(String),

    /// Credential validation errors (structured, supports field level errors)
    #[error("{0}")]
    CredentialValidation(CredentialValidationError),

    /// API error
    #[error("API error: {provider} - {message}")]
    ApiError { provider: String, message: String },

    /// Invalid voucher
    #[error("Invalid credentials for: {0}")]
    InvalidCredentials(String),

    /// serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Validation error
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Import and export errors
    #[error("Import/Export error: {0}")]
    ImportExportError(String),

    /// No account is selected (when exporting)
    #[error("No accounts selected")]
    NoAccountsSelected,

    /// Unsupported file version (when importing)
    #[error("Unsupported file version")]
    UnsupportedFileVersion,

    /// Storage layer error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Data format needs to be migrated (v1.7.0 voucher format upgrade)
    #[error("Credential data migration required")]
    MigrationRequired,

    /// Migration failed
    #[error("Migration failed: {0}")]
    MigrationFailed(String),

    /// Provider error (converting from library)
    #[error("{0}")]
    Provider(#[from] ProviderError),
}

impl CoreError {
    /// Whether it is expected behavior (user input, resource does not exist, etc.) is used for log classification.
    ///
    /// Level `warn` should be used when returning `true` and level `error` when returning `false`.
    /// **Please update this method simultaneously when new variants are added. **
    #[must_use]
    pub fn is_expected(&self) -> bool {
        match self {
            Self::AccountNotFound(_)
            | Self::DomainNotFound(_)
            | Self::RecordNotFound(_)
            | Self::ProviderNotFound(_)
            | Self::ValidationError(_)
            | Self::NoAccountsSelected
            | Self::UnsupportedFileVersion
            | Self::CredentialValidation(_)
            | Self::InvalidCredentials(_) => true,
            Self::Provider(e) => e.is_expected(),
            _ => false,
        }
    }
}

/// Core layer Result type alias
pub type CoreResult<T> = std::result::Result<T, CoreError>;
