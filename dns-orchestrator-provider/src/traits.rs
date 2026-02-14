use async_trait::async_trait;
use futures::stream::{self, StreamExt};

use crate::error::{ProviderError, Result};
use crate::types::{
    BatchCreateFailure, BatchCreateResult, BatchDeleteFailure, BatchDeleteResult,
    BatchUpdateFailure, BatchUpdateItem, BatchUpdateResult, CreateDnsRecordRequest, DnsRecord,
    PaginatedResponse, PaginationParams, ProviderDomain, ProviderMetadata, RecordQueryParams,
    UpdateDnsRecordRequest,
};

/// Default number of concurrent batch operations
const DEFAULT_BATCH_CONCURRENCY: usize = 5;

/// Raw API error (internal use)
#[derive(Debug, Clone)]
pub(crate) struct RawApiError {
    /// Error code (the format is different for each Provider)
    pub code: Option<String>,
    /// Original error message
    pub message: String,
}

impl RawApiError {
    /// Creates a raw API error without a provider-specific code.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            code: None,
            message: message.into(),
        }
    }

    /// Creates a raw API error with a provider-specific code.
    pub fn with_code(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: Some(code.into()),
            message: message.into(),
        }
    }
}

/// Error context information (internal use)
/// Used to provide additional information in case of mapping errors
#[derive(Debug, Clone, Default)]
pub(crate) struct ErrorContext {
    /// Record name (used for errors such as `RecordExists`)
    pub record_name: Option<String>,
    /// Record ID (used for errors such as `RecordNotFound`)
    pub record_id: Option<String>,
    /// Domain name (used for errors such as `DomainNotFound`)
    pub domain: Option<String>,
}

/// Provider error mapping Trait (internally used)
/// Each Provider implements this trait to map raw API errors to a unified error type
pub(crate) trait ProviderErrorMapper {
    /// Returns the Provider identifier
    fn provider_name(&self) -> &'static str;

    /// Map raw API errors to unified error types
    fn map_error(&self, raw: RawApiError, context: ErrorContext) -> ProviderError;

    /// Shortcut: Parsing Errors
    fn parse_error(&self, detail: impl ToString) -> ProviderError {
        ProviderError::ParseError {
            provider: self.provider_name().to_string(),
            detail: detail.to_string(),
        }
    }

    /// Shortcut method: unknown error (fallback)
    fn unknown_error(&self, raw: RawApiError) -> ProviderError {
        ProviderError::Unknown {
            provider: self.provider_name().to_string(),
            raw_code: raw.code,
            raw_message: raw.message,
        }
    }
}

/// The core DNS provider trait.
///
/// All DNS providers implement this trait, providing a uniform interface for
/// managing DNS records across different cloud platforms.
///
/// # Usage
///
/// You typically obtain a `dyn DnsProvider` via [`create_provider()`](crate::create_provider)
/// rather than constructing provider instances directly.
///
/// # Batch Operations
///
/// The batch methods ([`batch_create_records`](Self::batch_create_records),
/// [`batch_update_records`](Self::batch_update_records),
/// [`batch_delete_records`](Self::batch_delete_records)) have default
/// implementations that call the single-record methods concurrently.
/// Providers may override these with native batch APIs for better performance.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Returns the provider's unique identifier string (e.g., `"cloudflare"`, `"aliyun"`).
    fn id(&self) -> &'static str;

    /// Returns static metadata about this provider type.
    ///
    /// Includes the provider name, description, required credential fields,
    /// supported features, and API limits.
    fn metadata() -> ProviderMetadata
    where
        Self: Sized;

    /// Validates the stored credentials by making a lightweight API call.
    ///
    /// Returns `Ok(true)` if the credentials are valid, or a [`ProviderError`]
    /// (typically [`InvalidCredentials`](ProviderError::InvalidCredentials)) on failure.
    async fn validate_credentials(&self) -> Result<bool>;

    /// Lists domains (zones) managed by this provider.
    ///
    /// Results are paginated according to `params`.
    async fn list_domains(
        &self,
        params: &PaginationParams,
    ) -> Result<PaginatedResponse<ProviderDomain>>;

    /// Retrieves details for a single domain by its provider-specific ID.
    async fn get_domain(&self, domain_id: &str) -> Result<ProviderDomain>;

    /// Lists DNS records within a domain, with optional search and type filtering.
    async fn list_records(
        &self,
        domain_id: &str,
        params: &RecordQueryParams,
    ) -> Result<PaginatedResponse<DnsRecord>>;

    /// Creates a new DNS record.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::RecordExists`] if a conflicting record already exists.
    async fn create_record(&self, req: &CreateDnsRecordRequest) -> Result<DnsRecord>;

    /// Updates an existing DNS record.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::RecordNotFound`] if the record does not exist.
    async fn update_record(
        &self,
        record_id: &str,
        req: &UpdateDnsRecordRequest,
    ) -> Result<DnsRecord>;

    /// Deletes a DNS record.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::RecordNotFound`] if the record does not exist.
    async fn delete_record(&self, record_id: &str, domain_id: &str) -> Result<()>;

    /// Creates multiple DNS records in a single logical operation.
    ///
    /// The default implementation calls [`create_record()`](Self::create_record)
    /// concurrently for each request and collects successes/failures.
    /// Providers may override this with a native batch API for better performance.
    async fn batch_create_records(
        &self,
        requests: &[CreateDnsRecordRequest],
    ) -> Result<BatchCreateResult> {
        let indexed_requests: Vec<_> = requests
            .iter()
            .enumerate()
            .map(|(i, req)| (i, req.clone()))
            .collect();

        let results: Vec<(usize, std::result::Result<DnsRecord, ProviderError>)> =
            stream::iter(indexed_requests)
                .map(|(i, req)| async move { (i, self.create_record(&req).await) })
                .buffer_unordered(DEFAULT_BATCH_CONCURRENCY)
                .collect()
                .await;

        let mut created_records = Vec::new();
        let mut failures = Vec::new();

        for (i, result) in results {
            match result {
                Ok(record) => created_records.push(record),
                Err(e) => failures.push(BatchCreateFailure {
                    request_index: i,
                    record_name: requests[i].name.clone(),
                    reason: e.to_string(),
                }),
            }
        }

        Ok(BatchCreateResult {
            success_count: created_records.len(),
            failed_count: failures.len(),
            created_records,
            failures,
        })
    }

    /// Updates multiple DNS records in a single logical operation.
    ///
    /// The default implementation calls [`update_record()`](Self::update_record)
    /// concurrently for each item and collects successes/failures.
    /// Providers may override this with a native batch API for better performance.
    async fn batch_update_records(&self, updates: &[BatchUpdateItem]) -> Result<BatchUpdateResult> {
        let indexed_updates: Vec<_> = updates
            .iter()
            .enumerate()
            .map(|(i, item)| (i, item.record_id.clone(), item.request.clone()))
            .collect();

        let results: Vec<(usize, std::result::Result<DnsRecord, ProviderError>)> =
            stream::iter(indexed_updates)
                .map(|(i, record_id, req)| async move {
                    (i, self.update_record(&record_id, &req).await)
                })
                .buffer_unordered(DEFAULT_BATCH_CONCURRENCY)
                .collect()
                .await;

        let mut updated_records = Vec::new();
        let mut failures = Vec::new();

        for (i, result) in results {
            match result {
                Ok(record) => updated_records.push(record),
                Err(e) => failures.push(BatchUpdateFailure {
                    record_id: updates[i].record_id.clone(),
                    reason: e.to_string(),
                }),
            }
        }

        Ok(BatchUpdateResult {
            success_count: updated_records.len(),
            failed_count: failures.len(),
            updated_records,
            failures,
        })
    }

    /// Deletes multiple DNS records in a single logical operation.
    ///
    /// The default implementation calls [`delete_record()`](Self::delete_record)
    /// concurrently for each ID and collects successes/failures.
    /// Providers may override this with a native batch API for better performance.
    async fn batch_delete_records(
        &self,
        domain_id: &str,
        record_ids: &[String],
    ) -> Result<BatchDeleteResult> {
        let indexed_ids: Vec<_> = record_ids
            .iter()
            .enumerate()
            .map(|(i, id)| (i, id.clone()))
            .collect();
        let domain_id_owned = domain_id.to_string();

        let results: Vec<(usize, std::result::Result<(), ProviderError>)> =
            stream::iter(indexed_ids)
                .map(|(i, id)| {
                    let domain_id = &domain_id_owned;
                    async move { (i, self.delete_record(&id, domain_id).await) }
                })
                .buffer_unordered(DEFAULT_BATCH_CONCURRENCY)
                .collect()
                .await;

        let mut success_count = 0;
        let mut failures = Vec::new();

        for (i, result) in results {
            match result {
                Ok(()) => success_count += 1,
                Err(e) => failures.push(BatchDeleteFailure {
                    record_id: record_ids[i].clone(),
                    reason: e.to_string(),
                }),
            }
        }

        Ok(BatchDeleteResult {
            success_count,
            failed_count: failures.len(),
            failures,
        })
    }
}
