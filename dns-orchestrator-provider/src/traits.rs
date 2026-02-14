use async_trait::async_trait;

use crate::error::{ProviderError, Result};
use crate::types::{
    BatchCreateFailure, BatchCreateResult, BatchDeleteFailure, BatchDeleteResult,
    BatchUpdateFailure, BatchUpdateItem, BatchUpdateResult, CreateDnsRecordRequest, DnsRecord,
    PaginatedResponse, PaginationParams, ProviderDomain, ProviderMetadata, RecordQueryParams,
    UpdateDnsRecordRequest,
};

/// 原始 API 错误（内部使用）
#[derive(Debug, Clone)]
pub(crate) struct RawApiError {
    /// 错误码（各 Provider 格式不同）
    pub code: Option<String>,
    /// 原始错误消息
    pub message: String,
}

impl RawApiError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            code: None,
            message: message.into(),
        }
    }

    pub fn with_code(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: Some(code.into()),
            message: message.into(),
        }
    }
}

/// 错误上下文信息（内部使用）
/// 用于在映射错误时提供额外信息
#[derive(Debug, Clone, Default)]
pub(crate) struct ErrorContext {
    /// 记录名称（用于 `RecordExists` 等错误）
    pub record_name: Option<String>,
    /// 记录 ID（用于 `RecordNotFound` 等错误）
    pub record_id: Option<String>,
    /// 域名（用于 `DomainNotFound` 等错误）
    pub domain: Option<String>,
}

/// Provider 错误映射 Trait（内部使用）
/// 各 Provider 实现此 trait 以将原始 API 错误映射到统一错误类型
pub(crate) trait ProviderErrorMapper {
    /// 返回 Provider 标识符
    fn provider_name(&self) -> &'static str;

    /// 将原始 API 错误映射到统一错误类型
    fn map_error(&self, raw: RawApiError, context: ErrorContext) -> ProviderError;

    /// 快捷方法：解析错误
    fn parse_error(&self, detail: impl ToString) -> ProviderError {
        ProviderError::ParseError {
            provider: self.provider_name().to_string(),
            detail: detail.to_string(),
        }
    }

    /// 快捷方法：未知错误（fallback）
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
        let futures: Vec<_> = requests.iter().map(|req| self.create_record(req)).collect();
        let results = futures::future::join_all(futures).await;

        let mut created_records = Vec::new();
        let mut failures = Vec::new();

        for (i, result) in results.into_iter().enumerate() {
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
        let futures: Vec<_> = updates
            .iter()
            .map(|item| self.update_record(&item.record_id, &item.request))
            .collect();
        let results = futures::future::join_all(futures).await;

        let mut updated_records = Vec::new();
        let mut failures = Vec::new();

        for (i, result) in results.into_iter().enumerate() {
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
        let futures: Vec<_> = record_ids
            .iter()
            .map(|id| self.delete_record(id, domain_id))
            .collect();
        let results = futures::future::join_all(futures).await;

        let mut success_count = 0;
        let mut failures = Vec::new();

        for (i, result) in results.into_iter().enumerate() {
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
