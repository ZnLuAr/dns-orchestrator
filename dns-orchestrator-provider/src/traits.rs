use async_trait::async_trait;

use crate::error::{ProviderError, Result};
use crate::types::{
    CreateDnsRecordRequest, DnsRecord, PaginatedResponse, PaginationParams, ProviderDomain,
    ProviderMetadata, RecordQueryParams, UpdateDnsRecordRequest,
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

    /// 快捷方法：网络错误
    fn network_error(&self, detail: impl ToString) -> ProviderError {
        ProviderError::NetworkError {
            provider: self.provider_name().to_string(),
            detail: detail.to_string(),
        }
    }

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

/// DNS 提供商 Trait
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// 提供商标识符
    fn id(&self) -> &'static str;

    /// 获取 Provider 元数据（类型级别）
    ///
    /// 返回该 Provider 的元数据，包括名称、描述、凭证字段等。
    /// 此方法不需要实例，可以在创建 Provider 之前调用。
    fn metadata() -> ProviderMetadata
    where
        Self: Sized;

    /// 验证凭证是否有效
    async fn validate_credentials(&self) -> Result<bool>;

    /// 获取域名列表 (分页)
    async fn list_domains(
        &self,
        params: &PaginationParams,
    ) -> Result<PaginatedResponse<ProviderDomain>>;

    /// 获取域名详情
    async fn get_domain(&self, domain_id: &str) -> Result<ProviderDomain>;

    /// 获取 DNS 记录列表 (分页 + 搜索)
    async fn list_records(
        &self,
        domain_id: &str,
        params: &RecordQueryParams,
    ) -> Result<PaginatedResponse<DnsRecord>>;

    /// 创建 DNS 记录
    async fn create_record(&self, req: &CreateDnsRecordRequest) -> Result<DnsRecord>;

    /// 更新 DNS 记录
    async fn update_record(
        &self,
        record_id: &str,
        req: &UpdateDnsRecordRequest,
    ) -> Result<DnsRecord>;

    /// 删除 DNS 记录
    async fn delete_record(&self, record_id: &str, domain_id: &str) -> Result<()>;
}
