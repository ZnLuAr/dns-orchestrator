//! Account related type definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use dns_orchestrator_provider::{ProviderCredentials, ProviderType};

/// Account status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// active state
    Active,
    /// Error status (voucher invalid, etc.)
    Error,
}

/// Account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Account ID (UUID)
    pub id: String,
    /// Account name
    pub name: String,
    /// DNS provider type
    pub provider: ProviderType,
    /// creation time
    #[serde(rename = "createdAt")]
    #[serde(with = "crate::utils::datetime")]
    pub created_at: DateTime<Utc>,
    /// Update time
    #[serde(rename = "updatedAt")]
    #[serde(with = "crate::utils::datetime")]
    pub updated_at: DateTime<Utc>,
    /// Account status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AccountStatus>,
    /// Error message (when the status is Error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Create account request (v1.7.0 type safety refactoring)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    /// Account name
    pub name: String,
    /// DNS provider type
    pub provider: ProviderType,
    /// Credentials (structured type)
    pub credentials: ProviderCredentials,
}

/// Update account request (v1.7.0 type safety refactoring)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAccountRequest {
    /// Account ID
    pub id: String,
    /// New account name (optional)
    pub name: Option<String>,
    /// New credentials (optional, will overwrite the original credentials when provided)
    pub credentials: Option<ProviderCredentials>,
}
