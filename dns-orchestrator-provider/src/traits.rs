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

    /// 批量创建 DNS 记录
    ///
    /// 默认实现逐条调用 `create_record()`，收集成功/失败结果。
    /// Provider 可覆写以使用原生批量 API 提升性能。
    ///
    /// # TODO — 各 Provider 原生批量 API 覆写
    /// - [ ] Cloudflare: `POST /zones/{zone_id}/dns_records/batch`
    ///       <https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/batch/>
    /// - [ ] `DNSPod`: `CreateRecordBatch`（异步任务）
    ///       <https://cloud.tencent.com/document/product/1427/56194>
    /// - [ ] Aliyun: 批量操作 API
    ///       <https://help.aliyun.com/zh/dns/pubz-batch-operation/>
    /// - [ ] Huaweicloud: 待调研
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

    /// 批量更新 DNS 记录
    ///
    /// 默认实现逐条调用 `update_record()`，收集成功/失败结果。
    /// Provider 可覆写以使用原生批量 API 提升性能。
    ///
    /// # TODO — 各 Provider 原生批量 API 覆写
    /// - [ ] Cloudflare: 批量 API
    /// - [ ] `DNSPod`: `ModifyRecordBatch`
    ///       <https://cloud.tencent.com/document/product/1427/56198>
    /// - [ ] Huaweicloud: `BatchUpdateRecordSetWithLine`
    ///       <https://support.huaweicloud.com/api-dns/BatchUpdateRecordSetWithLine.html>
    /// - [ ] Aliyun: 调研批量 API 支持
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

    /// 批量删除 DNS 记录
    ///
    /// 默认实现逐条调用 `delete_record()`，收集成功/失败结果。
    /// Provider 可覆写以使用原生批量 API 提升性能。
    ///
    /// # TODO — 各 Provider 原生批量 API 覆写
    /// - [ ] Cloudflare: 批量 API
    /// - [ ] `DNSPod`: 批量删除 API
    /// - [ ] Aliyun: 调研批量 API 支持
    /// - [ ] Huaweicloud: 调研批量 API 支持
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
