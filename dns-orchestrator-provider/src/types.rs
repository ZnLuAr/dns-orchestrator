use serde::{Deserialize, Serialize};

// ============ Pagination ============

/// Pagination parameters for list operations.
///
/// All list endpoints accept these parameters to control page-based pagination.
/// Pages are 1-indexed.
///
/// # Default
///
/// The default is `page = 1, page_size = 20`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationParams {
    /// Page number (1-indexed).
    pub page: u32,
    /// Number of items per page.
    pub page_size: u32,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 20,
        }
    }
}

impl PaginationParams {
    /// Clamp pagination values to valid ranges.
    ///
    /// - `page` is clamped to `>= 1`
    /// - `page_size` is clamped to `1..=max_page_size`
    #[must_use]
    pub fn validated(&self, max_page_size: u32) -> Self {
        Self {
            page: self.page.max(1),
            page_size: self.page_size.clamp(1, max_page_size),
        }
    }
}

/// Query parameters for DNS record listing, with optional search and filtering.
///
/// Extends basic pagination with keyword search and record type filtering.
///
/// # Default
///
/// The default is `page = 1, page_size = 20`, with no keyword or type filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordQueryParams {
    /// Page number (1-indexed).
    pub page: u32,
    /// Number of items per page.
    pub page_size: u32,
    /// Optional keyword to match against record names or values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyword: Option<String>,
    /// Optional record type filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_type: Option<DnsRecordType>,
}

impl Default for RecordQueryParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 20,
            keyword: None,
            record_type: None,
        }
    }
}

impl RecordQueryParams {
    /// Convert to basic [`PaginationParams`], discarding search/filter fields.
    pub fn to_pagination(&self) -> PaginationParams {
        PaginationParams {
            page: self.page,
            page_size: self.page_size,
        }
    }

    /// Clamp pagination values to valid ranges.
    ///
    /// - `page` is clamped to `>= 1`
    /// - `page_size` is clamped to `1..=max_page_size`
    /// - `keyword` and `record_type` are preserved as-is
    #[must_use]
    pub fn validated(&self, max_page_size: u32) -> Self {
        Self {
            page: self.page.max(1),
            page_size: self.page_size.clamp(1, max_page_size),
            keyword: self.keyword.clone(),
            record_type: self.record_type.clone(),
        }
    }
}

/// A paginated response wrapper.
///
/// Returned by all list operations. Contains the current page of items
/// along with pagination metadata.
///
/// # Type Parameters
///
/// * `T` — The item type (e.g., [`ProviderDomain`], [`DnsRecord`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResponse<T> {
    /// Items in the current page.
    pub items: Vec<T>,
    /// Current page number.
    pub page: u32,
    /// Page size used for this request.
    pub page_size: u32,
    /// Total number of items across all pages.
    pub total_count: u32,
    /// Whether there are more pages after this one.
    pub has_more: bool,
}

impl<T> PaginatedResponse<T> {
    /// Create a new paginated response, automatically computing [`has_more`](Self::has_more).
    pub fn new(items: Vec<T>, page: u32, page_size: u32, total_count: u32) -> Self {
        let has_more = (page * page_size) < total_count;
        Self {
            items,
            page,
            page_size,
            total_count,
            has_more,
        }
    }
}

// ============ Provider Types ============

/// Identifies which DNS provider implementation to use.
///
/// Each variant is gated behind its corresponding feature flag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    /// Cloudflare DNS. Requires feature `cloudflare`.
    #[cfg(feature = "cloudflare")]
    Cloudflare,
    /// Aliyun (China) DNS. Requires feature `aliyun`.
    #[cfg(feature = "aliyun")]
    Aliyun,
    /// Tencent Cloud `DNSPod`. Requires feature `dnspod`.
    #[cfg(feature = "dnspod")]
    Dnspod,
    /// Huawei Cloud DNS. Requires feature `huaweicloud`.
    #[cfg(feature = "huaweicloud")]
    Huaweicloud,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "cloudflare")]
            Self::Cloudflare => write!(f, "cloudflare"),
            #[cfg(feature = "aliyun")]
            Self::Aliyun => write!(f, "aliyun"),
            #[cfg(feature = "dnspod")]
            Self::Dnspod => write!(f, "dnspod"),
            #[cfg(feature = "huaweicloud")]
            Self::Huaweicloud => write!(f, "huaweicloud"),
        }
    }
}

// ============ Domain Types ============

/// Status of a domain/zone within a DNS provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainStatus {
    /// Domain is active and resolving.
    Active,
    /// Domain is paused (not resolving).
    Paused,
    /// Domain is pending activation/verification.
    Pending,
    /// Domain is in an error state.
    Error,
    /// Status could not be determined.
    Unknown,
}

/// A domain (zone) managed by a DNS provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDomain {
    /// Provider-specific domain/zone identifier.
    pub id: String,
    /// Domain name (e.g., `"example.com"`).
    pub name: String,
    /// Which provider manages this domain.
    pub provider: ProviderType,
    /// Current domain status.
    pub status: DomainStatus,
    /// Number of DNS records in this domain, if known.
    #[serde(rename = "recordCount", skip_serializing_if = "Option::is_none")]
    pub record_count: Option<u32>,
}

// ============ DNS Record Types ============

/// DNS record type identifier, used for query filtering.
///
/// Serialized as uppercase strings (`"A"`, `"AAAA"`, `"CNAME"`, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    /// IPv4 address record.
    A,
    /// IPv6 address record.
    Aaaa,
    /// Canonical name (alias) record.
    Cname,
    /// Mail exchange record.
    Mx,
    /// Text record.
    Txt,
    /// Name server record.
    Ns,
    /// Service locator record.
    Srv,
    /// Certificate Authority Authorization record.
    Caa,
}

/// Type-safe representation of DNS record data.
///
/// Each variant carries the fields specific to that record type.
/// Use [`record_type()`](Self::record_type) to get the [`DnsRecordType`] discriminant,
/// or [`display_value()`](Self::display_value) to get the primary value for display.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "content")]
pub enum RecordData {
    /// A record — maps a hostname to an IPv4 address.
    A {
        /// IPv4 address (e.g., `"1.2.3.4"`).
        address: String,
    },

    /// AAAA record — maps a hostname to an IPv6 address.
    AAAA {
        /// IPv6 address (e.g., `"2001:db8::1"`).
        address: String,
    },

    /// CNAME record — alias from one name to another.
    CNAME {
        /// Target hostname.
        target: String,
    },

    /// MX record — mail exchange server.
    MX {
        /// Priority (lower = preferred).
        priority: u16,
        /// Mail server hostname.
        exchange: String,
    },

    /// TXT record — arbitrary text data.
    TXT {
        /// Text content.
        text: String,
    },

    /// NS record — authoritative name server.
    NS {
        /// Name server hostname.
        nameserver: String,
    },

    /// SRV record — service locator.
    SRV {
        /// Priority (lower = preferred).
        priority: u16,
        /// Weight for load balancing among same-priority targets.
        weight: u16,
        /// TCP/UDP port number.
        port: u16,
        /// Target hostname providing the service.
        target: String,
    },

    /// CAA record — Certificate Authority Authorization.
    CAA {
        /// Issuer critical flag (0 or 128).
        flags: u8,
        /// Property tag (`"issue"`, `"issuewild"`, or `"iodef"`).
        tag: String,
        /// CA domain or reporting URI.
        value: String,
    },
}

impl RecordData {
    /// Returns the [`DnsRecordType`] discriminant for this record data.
    pub fn record_type(&self) -> DnsRecordType {
        match self {
            Self::A { .. } => DnsRecordType::A,
            Self::AAAA { .. } => DnsRecordType::Aaaa,
            Self::CNAME { .. } => DnsRecordType::Cname,
            Self::MX { .. } => DnsRecordType::Mx,
            Self::TXT { .. } => DnsRecordType::Txt,
            Self::NS { .. } => DnsRecordType::Ns,
            Self::SRV { .. } => DnsRecordType::Srv,
            Self::CAA { .. } => DnsRecordType::Caa,
        }
    }

    /// Returns the primary display value for this record (e.g., the IP address for A/AAAA,
    /// the target for CNAME/SRV, the exchange for MX).
    pub fn display_value(&self) -> &str {
        match self {
            Self::A { address } | Self::AAAA { address } => address,
            Self::CNAME { target } | Self::SRV { target, .. } => target,
            Self::MX { exchange, .. } => exchange,
            Self::TXT { text } => text,
            Self::NS { nameserver } => nameserver,
            Self::CAA { value, .. } => value,
        }
    }
}

/// A DNS record as returned by a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecord {
    /// Provider-specific record identifier.
    pub id: String,
    /// Domain/zone identifier this record belongs to.
    pub domain_id: String,
    /// Record name (e.g., `"www"` or `"@"` for apex).
    pub name: String,
    /// Time to live in seconds.
    pub ttl: u32,
    /// Type-specific record data.
    pub data: RecordData,

    /// Whether Cloudflare CDN proxy is enabled (Cloudflare only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,

    /// When the record was created, if known.
    #[serde(with = "crate::utils::datetime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,

    /// When the record was last updated, if known.
    #[serde(with = "crate::utils::datetime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request to create a new DNS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDnsRecordRequest {
    /// Domain/zone identifier to create the record in.
    pub domain_id: String,
    /// Record name (e.g., `"www"`).
    pub name: String,
    /// Time to live in seconds.
    pub ttl: u32,
    /// Type-specific record data.
    pub data: RecordData,
    /// Enable Cloudflare CDN proxy (Cloudflare only, ignored by other providers).
    pub proxied: Option<bool>,
}

/// Request to update an existing DNS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDnsRecordRequest {
    /// Domain/zone identifier the record belongs to.
    pub domain_id: String,
    /// New record name.
    pub name: String,
    /// New TTL in seconds.
    pub ttl: u32,
    /// New type-specific record data.
    pub data: RecordData,
    /// Enable Cloudflare CDN proxy (Cloudflare only, ignored by other providers).
    pub proxied: Option<bool>,
}

// ============ Batch Operation Types ============

/// Result of a batch create operation.
///
/// Contains both successfully created records and any per-record failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchCreateResult {
    /// Number of records successfully created.
    pub success_count: usize,
    /// Number of records that failed to create.
    pub failed_count: usize,
    /// Successfully created records.
    pub created_records: Vec<DnsRecord>,
    /// Details about each failed creation.
    pub failures: Vec<BatchCreateFailure>,
}

/// Information about a single failed record creation in a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchCreateFailure {
    /// Index of the failed request in the original request slice.
    pub request_index: usize,
    /// Name of the record that failed.
    pub record_name: String,
    /// Human-readable reason for the failure.
    pub reason: String,
}

/// Result of a batch update operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateResult {
    /// Number of records successfully updated.
    pub success_count: usize,
    /// Number of records that failed to update.
    pub failed_count: usize,
    /// Successfully updated records.
    pub updated_records: Vec<DnsRecord>,
    /// Details about each failed update.
    pub failures: Vec<BatchUpdateFailure>,
}

/// Information about a single failed record update in a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateFailure {
    /// ID of the record that failed to update.
    pub record_id: String,
    /// Human-readable reason for the failure.
    pub reason: String,
}

/// A single item in a batch update request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateItem {
    /// ID of the record to update.
    pub record_id: String,
    /// The update payload.
    pub request: UpdateDnsRecordRequest,
}

/// Result of a batch delete operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeleteResult {
    /// Number of records successfully deleted.
    pub success_count: usize,
    /// Number of records that failed to delete.
    pub failed_count: usize,
    /// Details about each failed deletion.
    pub failures: Vec<BatchDeleteFailure>,
}

/// Information about a single failed record deletion in a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeleteFailure {
    /// ID of the record that failed to delete.
    pub record_id: String,
    /// Human-readable reason for the failure.
    pub reason: String,
}

// ============ Provider Metadata Types ============

/// The input type of a credential field (affects UI rendering).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    /// Plain text input.
    Text,
    /// Masked/password input.
    Password,
}

/// Definition of a single credential field required by a provider.
///
/// Used to dynamically build credential forms in UIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCredentialField {
    /// Machine-readable field key (e.g., `"apiToken"`).
    pub key: String,
    /// Human-readable label (e.g., `"API Token"`).
    pub label: String,
    /// Input type for UI rendering.
    #[serde(rename = "type")]
    pub field_type: FieldType,
    /// Optional placeholder text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Optional help/description text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_text: Option<String>,
}

/// Provider-specific feature support flags.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProviderFeatures {
    /// Whether the provider supports CDN proxy (e.g., Cloudflare's orange-cloud proxy).
    pub proxy: bool,
}

/// Provider-specific pagination limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderLimits {
    /// Maximum page size for domain list requests.
    pub max_page_size_domains: u32,
    /// Maximum page size for DNS record list requests.
    pub max_page_size_records: u32,
}

/// Static metadata describing a DNS provider.
///
/// Contains the provider's identity, required credential fields, supported features,
/// and API limits. Useful for building dynamic UIs or validating configuration.
///
/// Obtain via [`DnsProvider::metadata()`](crate::DnsProvider::metadata) or
/// [`get_all_provider_metadata()`](crate::get_all_provider_metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderMetadata {
    /// Provider type identifier.
    pub id: ProviderType,
    /// Human-readable provider name.
    pub name: String,
    /// Short description of the provider.
    pub description: String,
    /// Credential fields required to authenticate with this provider.
    pub required_fields: Vec<ProviderCredentialField>,
    /// Feature flags for this provider.
    pub features: ProviderFeatures,
    /// API pagination limits for this provider.
    pub limits: ProviderLimits,
}

// ============ Credential Types ============

/// Validation error for provider credentials.
///
/// Returned when credential fields are missing, empty, or have an invalid format.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CredentialValidationError {
    /// A required credential field is missing entirely.
    MissingField {
        /// Which provider the error relates to.
        provider: ProviderType,
        /// Machine-readable field key.
        field: String,
        /// Human-readable field label.
        label: String,
    },
    /// A credential field is present but empty/whitespace-only.
    EmptyField {
        /// Which provider the error relates to.
        provider: ProviderType,
        /// Machine-readable field key.
        field: String,
        /// Human-readable field label.
        label: String,
    },
    /// A credential field has an invalid format.
    InvalidFormat {
        /// Which provider the error relates to.
        provider: ProviderType,
        /// Machine-readable field key.
        field: String,
        /// Human-readable field label.
        label: String,
        /// Description of what's wrong with the format.
        reason: String,
    },
}

impl std::fmt::Display for CredentialValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField { label, .. } => write!(f, "Missing required field: {label}"),
            Self::EmptyField { label, .. } => write!(f, "Field must not be empty: {label}"),
            Self::InvalidFormat { label, reason, .. } => write!(f, "{label}: {reason}"),
        }
    }
}

impl std::error::Error for CredentialValidationError {}

/// Type-safe credential container for all supported DNS providers.
///
/// Each variant holds the authentication fields required by that provider.
/// Pass this to [`create_provider()`](crate::create_provider) to instantiate a provider.
///
/// # Serialization
///
/// Serialized as a tagged enum with `"provider"` as the tag and `"credentials"` as the content:
///
/// ```json
/// { "provider": "cloudflare", "credentials": { "api_token": "..." } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "provider", content = "credentials")]
pub enum ProviderCredentials {
    /// Cloudflare credentials. Requires feature `cloudflare`.
    #[cfg(feature = "cloudflare")]
    #[serde(rename = "cloudflare")]
    Cloudflare {
        /// Cloudflare API token.
        api_token: String,
    },

    /// Aliyun DNS credentials. Requires feature `aliyun`.
    #[cfg(feature = "aliyun")]
    #[serde(rename = "aliyun")]
    Aliyun {
        /// Aliyun Access Key ID.
        access_key_id: String,
        /// Aliyun Access Key Secret.
        access_key_secret: String,
    },

    /// Tencent Cloud `DNSPod` credentials. Requires feature `dnspod`.
    #[cfg(feature = "dnspod")]
    #[serde(rename = "dnspod")]
    Dnspod {
        /// Tencent Cloud Secret ID.
        secret_id: String,
        /// Tencent Cloud Secret Key.
        secret_key: String,
    },

    /// Huawei Cloud DNS credentials. Requires feature `huaweicloud`.
    #[cfg(feature = "huaweicloud")]
    #[serde(rename = "huaweicloud")]
    Huaweicloud {
        /// Huawei Cloud Access Key ID.
        access_key_id: String,
        /// Huawei Cloud Secret Access Key.
        secret_access_key: String,
    },
}

impl ProviderCredentials {
    /// Construct credentials from a `HashMap`, validating required fields.
    ///
    /// Useful for deserializing credentials stored in a flat key-value format.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialValidationError`] if a required field is missing or empty.
    pub fn from_map(
        provider: &ProviderType,
        map: &std::collections::HashMap<String, String>,
    ) -> Result<Self, CredentialValidationError> {
        match provider {
            #[cfg(feature = "cloudflare")]
            ProviderType::Cloudflare => Ok(Self::Cloudflare {
                api_token: Self::get_required_field(provider, map, "apiToken", "API Token")?,
            }),
            #[cfg(feature = "aliyun")]
            ProviderType::Aliyun => Ok(Self::Aliyun {
                access_key_id: Self::get_required_field(
                    provider,
                    map,
                    "accessKeyId",
                    "Access Key ID",
                )?,
                access_key_secret: Self::get_required_field(
                    provider,
                    map,
                    "accessKeySecret",
                    "Access Key Secret",
                )?,
            }),
            #[cfg(feature = "dnspod")]
            ProviderType::Dnspod => Ok(Self::Dnspod {
                secret_id: Self::get_required_field(provider, map, "secretId", "Secret ID")?,
                secret_key: Self::get_required_field(provider, map, "secretKey", "Secret Key")?,
            }),
            #[cfg(feature = "huaweicloud")]
            ProviderType::Huaweicloud => Ok(Self::Huaweicloud {
                access_key_id: Self::get_required_field(
                    provider,
                    map,
                    "accessKeyId",
                    "Access Key ID",
                )?,
                secret_access_key: Self::get_required_field(
                    provider,
                    map,
                    "secretAccessKey",
                    "Secret Access Key",
                )?,
            }),
            #[allow(unreachable_patterns)]
            _ => Err(CredentialValidationError::InvalidFormat {
                provider: provider.clone(),
                field: "provider".to_string(),
                label: "Provider".to_string(),
                reason: format!(
                    "Provider '{provider}' is not supported or its feature is not enabled."
                ),
            }),
        }
    }

    /// Obtain required fields from `HashMap` and verify that it is not empty
    fn get_required_field(
        provider: &ProviderType,
        map: &std::collections::HashMap<String, String>,
        key: &str,
        label: &str,
    ) -> Result<String, CredentialValidationError> {
        match map.get(key) {
            None => Err(CredentialValidationError::MissingField {
                provider: provider.clone(),
                field: key.to_string(),
                label: label.to_string(),
            }),
            Some(v) if v.trim().is_empty() => Err(CredentialValidationError::EmptyField {
                provider: provider.clone(),
                field: key.to_string(),
                label: label.to_string(),
            }),
            Some(v) => Ok(v.clone()),
        }
    }

    /// Convert credentials to a `HashMap` for flat key-value storage.
    pub fn to_map(&self) -> std::collections::HashMap<String, String> {
        match self {
            Self::Cloudflare { api_token } => [("apiToken".to_string(), api_token.clone())].into(),
            Self::Aliyun {
                access_key_id,
                access_key_secret,
            } => [
                ("accessKeyId".to_string(), access_key_id.clone()),
                ("accessKeySecret".to_string(), access_key_secret.clone()),
            ]
            .into(),
            Self::Dnspod {
                secret_id,
                secret_key,
            } => [
                ("secretId".to_string(), secret_id.clone()),
                ("secretKey".to_string(), secret_key.clone()),
            ]
            .into(),
            Self::Huaweicloud {
                access_key_id,
                secret_access_key,
            } => [
                ("accessKeyId".to_string(), access_key_id.clone()),
                ("secretAccessKey".to_string(), secret_access_key.clone()),
            ]
            .into(),
        }
    }

    /// Returns the [`ProviderType`] corresponding to this credential variant.
    pub fn provider_type(&self) -> ProviderType {
        match self {
            Self::Cloudflare { .. } => ProviderType::Cloudflare,
            Self::Aliyun { .. } => ProviderType::Aliyun,
            Self::Dnspod { .. } => ProviderType::Dnspod,
            Self::Huaweicloud { .. } => ProviderType::Huaweicloud,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ============ ProviderCredentials Round Trip Test ============

    #[test]
    fn credentials_cloudflare_roundtrip() {
        let map: HashMap<String, String> =
            [("apiToken".to_string(), "my-token".to_string())].into();
        let res = ProviderCredentials::from_map(&ProviderType::Cloudflare, &map);
        assert!(res.is_ok(), "expected Ok(..), got {res:?}");
        let Ok(cred) = res else {
            return;
        };
        let back = cred.to_map();
        assert_eq!(back.get("apiToken").map(String::as_str), Some("my-token"));
        assert_eq!(cred.provider_type(), ProviderType::Cloudflare);
    }

    #[test]
    fn credentials_aliyun_roundtrip() {
        let map: HashMap<String, String> = [
            ("accessKeyId".to_string(), "id123".to_string()),
            ("accessKeySecret".to_string(), "secret456".to_string()),
        ]
        .into();
        let res = ProviderCredentials::from_map(&ProviderType::Aliyun, &map);
        assert!(res.is_ok(), "expected Ok(..), got {res:?}");
        let Ok(cred) = res else {
            return;
        };
        let back = cred.to_map();
        assert_eq!(back.get("accessKeyId").map(String::as_str), Some("id123"));
        assert_eq!(
            back.get("accessKeySecret").map(String::as_str),
            Some("secret456")
        );
    }

    #[test]
    fn credentials_dnspod_roundtrip() {
        let map: HashMap<String, String> = [
            ("secretId".to_string(), "sid".to_string()),
            ("secretKey".to_string(), "skey".to_string()),
        ]
        .into();
        let res = ProviderCredentials::from_map(&ProviderType::Dnspod, &map);
        assert!(res.is_ok(), "expected Ok(..), got {res:?}");
        let Ok(cred) = res else {
            return;
        };
        let back = cred.to_map();
        assert_eq!(back.get("secretId").map(String::as_str), Some("sid"));
        assert_eq!(back.get("secretKey").map(String::as_str), Some("skey"));
    }

    #[test]
    fn credentials_huaweicloud_roundtrip() {
        let map: HashMap<String, String> = [
            ("accessKeyId".to_string(), "ak".to_string()),
            ("secretAccessKey".to_string(), "sk".to_string()),
        ]
        .into();
        let res = ProviderCredentials::from_map(&ProviderType::Huaweicloud, &map);
        assert!(res.is_ok(), "expected Ok(..), got {res:?}");
        let Ok(cred) = res else {
            return;
        };
        let back = cred.to_map();
        assert_eq!(back.get("accessKeyId").map(String::as_str), Some("ak"));
        assert_eq!(back.get("secretAccessKey").map(String::as_str), Some("sk"));
    }

    #[test]
    fn credentials_missing_field() {
        let map: HashMap<String, String> = HashMap::new();
        let res = ProviderCredentials::from_map(&ProviderType::Cloudflare, &map);
        assert!(
            matches!(&res, Err(CredentialValidationError::MissingField { .. })),
            "unexpected result: {res:?}"
        );
    }

    #[test]
    fn credentials_empty_field() {
        let map: HashMap<String, String> = [("apiToken".to_string(), "  ".to_string())].into();
        let res = ProviderCredentials::from_map(&ProviderType::Cloudflare, &map);
        assert!(
            matches!(&res, Err(CredentialValidationError::EmptyField { .. })),
            "unexpected result: {res:?}"
        );
    }

    // ============ PaginatedResponse paging calculation test ============

    #[test]
    fn paginated_response_has_more() {
        let resp = PaginatedResponse::new(vec![1, 2, 3], 1, 3, 10);
        assert!(resp.has_more);
        assert_eq!(resp.total_count, 10);
    }

    #[test]
    fn paginated_response_no_more() {
        let resp = PaginatedResponse::new(vec![1, 2], 2, 3, 5);
        assert!(!resp.has_more); // page 2 * page_size 3 = 6 >= 5
    }

    #[test]
    fn paginated_response_exact_boundary() {
        let resp = PaginatedResponse::new(vec![1, 2, 3], 1, 3, 3);
        assert!(!resp.has_more); // 1 * 3 = 3, not < 3
    }

    #[test]
    fn paginated_response_empty() {
        let resp: PaginatedResponse<i32> = PaginatedResponse::new(vec![], 1, 20, 0);
        assert!(!resp.has_more);
        assert_eq!(resp.items.len(), 0);
    }

    // ============ DnsRecordType serde test ============

    #[test]
    fn dns_record_type_serialize() {
        let a = DnsRecordType::A;
        let json_res = serde_json::to_string(&a);
        assert!(
            json_res.is_ok(),
            "serde_json::to_string failed: {json_res:?}"
        );
        let Ok(json) = json_res else {
            return;
        };
        assert_eq!(json, "\"A\"");
    }

    #[test]
    fn dns_record_type_deserialize() {
        let a_res: serde_json::Result<DnsRecordType> = serde_json::from_str("\"AAAA\"");
        assert!(a_res.is_ok(), "serde_json::from_str failed: {a_res:?}");
        let Ok(a) = a_res else {
            return;
        };
        assert_eq!(a, DnsRecordType::Aaaa);
    }

    #[test]
    fn dns_record_type_roundtrip_all() {
        let types = vec![
            DnsRecordType::A,
            DnsRecordType::Aaaa,
            DnsRecordType::Cname,
            DnsRecordType::Mx,
            DnsRecordType::Txt,
            DnsRecordType::Ns,
            DnsRecordType::Srv,
            DnsRecordType::Caa,
        ];
        for t in types {
            let json_res = serde_json::to_string(&t);
            assert!(
                json_res.is_ok(),
                "serde_json::to_string failed: {json_res:?}"
            );
            let Ok(json) = json_res else {
                return;
            };

            let back_res: serde_json::Result<DnsRecordType> = serde_json::from_str(&json);
            assert!(
                back_res.is_ok(),
                "serde_json::from_str failed: {back_res:?}"
            );
            let Ok(back) = back_res else {
                return;
            };
            assert_eq!(back, t);
        }
    }

    // ============ RecordData serde test ============

    #[test]
    fn record_data_srv_serde_roundtrip() {
        let data = RecordData::SRV {
            priority: 10,
            weight: 20,
            port: 443,
            target: "example.com".to_string(),
        };
        let json_res = serde_json::to_string(&data);
        assert!(
            json_res.is_ok(),
            "serde_json::to_string failed: {json_res:?}"
        );
        let Ok(json) = json_res else {
            return;
        };

        let back_res: serde_json::Result<RecordData> = serde_json::from_str(&json);
        assert!(
            back_res.is_ok(),
            "serde_json::from_str failed: {back_res:?}"
        );
        let Ok(back) = back_res else {
            return;
        };
        assert_eq!(back, data);
    }

    #[test]
    fn record_data_caa_serde_roundtrip() {
        let data = RecordData::CAA {
            flags: 0,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
        };
        let json_res = serde_json::to_string(&data);
        assert!(
            json_res.is_ok(),
            "serde_json::to_string failed: {json_res:?}"
        );
        let Ok(json) = json_res else {
            return;
        };

        let back_res: serde_json::Result<RecordData> = serde_json::from_str(&json);
        assert!(
            back_res.is_ok(),
            "serde_json::from_str failed: {back_res:?}"
        );
        let Ok(back) = back_res else {
            return;
        };
        assert_eq!(back, data);
    }

    #[test]
    fn record_data_record_type() {
        assert_eq!(
            RecordData::A {
                address: "1.2.3.4".into()
            }
            .record_type(),
            DnsRecordType::A
        );
        assert_eq!(
            RecordData::SRV {
                priority: 0,
                weight: 0,
                port: 0,
                target: ".".into()
            }
            .record_type(),
            DnsRecordType::Srv
        );
    }

    #[test]
    fn record_data_display_value() {
        assert_eq!(
            RecordData::A {
                address: "1.2.3.4".into()
            }
            .display_value(),
            "1.2.3.4"
        );
        assert_eq!(
            RecordData::MX {
                priority: 10,
                exchange: "mail.x.com".into()
            }
            .display_value(),
            "mail.x.com"
        );
        assert_eq!(
            RecordData::CAA {
                flags: 0,
                tag: "issue".into(),
                value: "le.org".into()
            }
            .display_value(),
            "le.org"
        );
    }

    // ============ PaginationParams::validated Test ============

    #[test]
    fn pagination_validated_clamps_page_zero() {
        let p = PaginationParams {
            page: 0,
            page_size: 20,
        };
        let v = p.validated(100);
        assert_eq!(v.page, 1);
        assert_eq!(v.page_size, 20);
    }

    #[test]
    fn pagination_validated_clamps_page_size_over_max() {
        let p = PaginationParams {
            page: 1,
            page_size: 9999,
        };
        let v = p.validated(100);
        assert_eq!(v.page_size, 100);
    }

    #[test]
    fn pagination_validated_clamps_page_size_zero() {
        let p = PaginationParams {
            page: 1,
            page_size: 0,
        };
        let v = p.validated(100);
        assert_eq!(v.page_size, 1);
    }

    #[test]
    fn pagination_validated_normal_values_unchanged() {
        let p = PaginationParams {
            page: 3,
            page_size: 50,
        };
        let v = p.validated(100);
        assert_eq!(v.page, 3);
        assert_eq!(v.page_size, 50);
    }

    #[test]
    fn record_query_validated_preserves_filters() {
        let p = RecordQueryParams {
            page: 0,
            page_size: 9999,
            keyword: Some("test".to_string()),
            record_type: Some(DnsRecordType::A),
        };
        let v = p.validated(100);
        assert_eq!(v.page, 1);
        assert_eq!(v.page_size, 100);
        assert_eq!(v.keyword.as_deref(), Some("test"));
        assert_eq!(v.record_type, Some(DnsRecordType::A));
    }
}
