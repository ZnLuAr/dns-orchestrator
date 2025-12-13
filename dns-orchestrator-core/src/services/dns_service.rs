//! DNS 记录管理服务

use std::sync::Arc;

use dns_orchestrator_provider::{DnsProvider, ProviderError};

use crate::error::{CoreError, CoreResult};
use crate::services::ServiceContext;
use crate::types::{
    AccountStatus, BatchDeleteFailure, BatchDeleteRequest, BatchDeleteResult,
    CreateDnsRecordRequest, DnsRecord, DnsRecordType, PaginatedResponse, RecordQueryParams,
    UpdateDnsRecordRequest,
};

/// DNS 记录管理服务
pub struct DnsService {
    ctx: Arc<ServiceContext>,
}

impl DnsService {
    /// 创建 DNS 服务实例
    #[must_use]
    pub fn new(ctx: Arc<ServiceContext>) -> Self {
        Self { ctx }
    }

    /// 列出域名下的所有 DNS 记录（分页 + 搜索）
    pub async fn list_records(
        &self,
        account_id: &str,
        domain_id: &str,
        page: Option<u32>,
        page_size: Option<u32>,
        keyword: Option<String>,
        record_type: Option<DnsRecordType>,
    ) -> CoreResult<PaginatedResponse<DnsRecord>> {
        let provider = self.get_provider(account_id).await?;

        let params = RecordQueryParams {
            page: page.unwrap_or(1),
            page_size: page_size.unwrap_or(20),
            keyword,
            record_type,
        };

        match provider.list_records(domain_id, &params).await {
            Ok(response) => Ok(response),
            Err(e) => Err(self.handle_provider_error(account_id, e).await),
        }
    }

    /// 创建 DNS 记录
    pub async fn create_record(
        &self,
        account_id: &str,
        request: CreateDnsRecordRequest,
    ) -> CoreResult<DnsRecord> {
        let provider = self.get_provider(account_id).await?;
        match provider.create_record(&request).await {
            Ok(record) => Ok(record),
            Err(e) => Err(self.handle_provider_error(account_id, e).await),
        }
    }

    /// 更新 DNS 记录
    pub async fn update_record(
        &self,
        account_id: &str,
        record_id: &str,
        request: UpdateDnsRecordRequest,
    ) -> CoreResult<DnsRecord> {
        let provider = self.get_provider(account_id).await?;
        match provider.update_record(record_id, &request).await {
            Ok(record) => Ok(record),
            Err(e) => Err(self.handle_provider_error(account_id, e).await),
        }
    }

    /// 删除 DNS 记录
    pub async fn delete_record(
        &self,
        account_id: &str,
        record_id: &str,
        domain_id: &str,
    ) -> CoreResult<()> {
        let provider = self.get_provider(account_id).await?;
        match provider.delete_record(record_id, domain_id).await {
            Ok(()) => Ok(()),
            Err(e) => Err(self.handle_provider_error(account_id, e).await),
        }
    }

    /// 批量删除 DNS 记录
    pub async fn batch_delete_records(
        &self,
        account_id: &str,
        request: BatchDeleteRequest,
    ) -> CoreResult<BatchDeleteResult> {
        let provider = self.get_provider(account_id).await?;

        let mut success_count = 0;
        let mut failures = Vec::new();

        // 并行删除所有记录
        let delete_futures: Vec<_> = request
            .record_ids
            .iter()
            .map(|record_id| {
                let provider = provider.clone();
                let domain_id = request.domain_id.clone();
                let record_id = record_id.clone();
                async move {
                    match provider.delete_record(&record_id, &domain_id).await {
                        Ok(()) => Ok(record_id),
                        Err(e) => Err((record_id, e)),
                    }
                }
            })
            .collect();

        let results = futures::future::join_all(delete_futures).await;

        for result in results {
            match result {
                Ok(_) => success_count += 1,
                Err((record_id, e)) => {
                    // 检查是否是凭证失效
                    if let ProviderError::InvalidCredentials { .. } = &e {
                        self.mark_account_invalid(account_id, "凭证已失效").await;
                    }
                    failures.push(BatchDeleteFailure {
                        record_id,
                        reason: e.to_string(),
                    });
                }
            }
        }

        Ok(BatchDeleteResult {
            success_count,
            failed_count: failures.len(),
            failures,
        })
    }

    /// 获取 Provider 实例
    async fn get_provider(&self, account_id: &str) -> CoreResult<Arc<dyn DnsProvider>> {
        self.ctx
            .provider_registry
            .get(account_id)
            .await
            .ok_or_else(|| CoreError::AccountNotFound(account_id.to_string()))
    }

    /// 处理 Provider 错误，如果是凭证失效则更新账户状态
    async fn handle_provider_error(&self, account_id: &str, err: ProviderError) -> CoreError {
        if let ProviderError::InvalidCredentials { .. } = &err {
            self.mark_account_invalid(account_id, "凭证已失效").await;
        }
        CoreError::Provider(err)
    }

    /// 标记账户为无效状态
    async fn mark_account_invalid(&self, account_id: &str, error_msg: &str) {
        let _ = self
            .ctx
            .account_repository
            .update_status(
                account_id,
                AccountStatus::Error,
                Some(error_msg.to_string()),
            )
            .await;
        log::warn!("Account {account_id} marked as invalid: {error_msg}");
    }
}
