//! Import and export related type definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use dns_orchestrator_provider::ProviderType;

/// Export data of a single account (including credentials)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedAccount {
    /// Account ID
    pub id: String,
    /// Account name
    pub name: String,
    /// DNS provider type
    pub provider: ProviderType,
    /// creation time
    #[serde(with = "crate::utils::datetime")]
    pub created_at: DateTime<Utc>,
    /// Update time
    #[serde(with = "crate::utils::datetime")]
    pub updated_at: DateTime<Utc>,
    /// Voucher data
    pub credentials: HashMap<String, String>,
}

/// Export file header (plain text part)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFileHeader {
    /// File format version
    pub version: u32,
    /// Whether to encrypt
    pub encrypted: bool,
    /// Salt value used when encrypting (Base64 encoding)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    /// IV/Nonce used for encryption (Base64 encoding)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Export time
    pub exported_at: String,
    /// Application version
    pub app_version: String,
}

/// Complete export file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFile {
    /// File header
    pub header: ExportFileHeader,
    /// Account data (base64 encoded ciphertext when encrypted, JSON array when unencrypted)
    pub data: serde_json::Value,
}

/// Export request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportAccountsRequest {
    /// List of account IDs to export
    pub account_ids: Vec<String>,
    /// Whether to encrypt
    pub encrypt: bool,
    /// Encryption password (only required when encrypt=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// export response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportAccountsResponse {
    /// Exported JSON content
    pub content: String,
    /// Suggested file name
    pub suggested_filename: String,
}

/// import request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportAccountsRequest {
    /// Import the contents of the file
    pub content: String,
    /// Decryption password (if file is encrypted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Import preview (used to display the accounts to be imported)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    /// Whether the file is encrypted
    pub encrypted: bool,
    /// Number of accounts
    pub account_count: usize,
    /// Account preview list (only available if unencrypted or decrypted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<ImportPreviewAccount>>,
}

/// Import the account information in the preview (excluding sensitive credentials)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreviewAccount {
    /// Account name
    pub name: String,
    /// DNS provider type
    pub provider: ProviderType,
    /// Does it conflict with the existing account name?
    pub has_conflict: bool,
}

/// Import results
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    /// Number of accounts successfully imported
    pub success_count: usize,
    /// Failed accounts and reasons
    pub failures: Vec<ImportFailure>,
}

/// Import failed items
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportFailure {
    /// Account name
    pub name: String,
    /// Reason for failure
    pub reason: String,
}
