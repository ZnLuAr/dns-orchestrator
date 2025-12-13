//! 阿里云 DnsProvider trait 实现

use async_trait::async_trait;
use chrono::DateTime;
use serde::Serialize;

use crate::error::{ProviderError, Result};
use crate::providers::common::{parse_record_type, record_type_to_string};
use crate::traits::{DnsProvider, ProviderErrorMapper};
use crate::types::{
    CreateDnsRecordRequest, DnsRecord, DomainStatus, PaginatedResponse, PaginationParams,
    ProviderDomain, ProviderType, RecordQueryParams, UpdateDnsRecordRequest,
};

use super::{
    AddDomainRecordResponse, AliyunProvider, DeleteDomainRecordResponse,
    DescribeDomainRecordsResponse, DescribeDomainsResponse, MAX_PAGE_SIZE,
    UpdateDomainRecordResponse,
};

impl AliyunProvider {
    /// 将阿里云域名状态转换为内部状态
    /// 注意：阿里云 `DescribeDomains` API 实际上不返回 `DomainStatus` 字段
    pub(crate) fn convert_domain_status(status: Option<&str>) -> DomainStatus {
        match status {
            Some("ENABLE" | "enable") => DomainStatus::Active,
            Some("PAUSE" | "pause") => DomainStatus::Paused,
            Some("SPAM" | "spam") => DomainStatus::Error,
            _ => DomainStatus::Unknown,
        }
    }

    /// 将时间戳转换为 RFC3339 格式
    pub(crate) fn timestamp_to_rfc3339(timestamp: Option<i64>) -> Option<String> {
        timestamp.and_then(|ts| DateTime::from_timestamp(ts / 1000, 0).map(|dt| dt.to_rfc3339()))
    }
}

#[async_trait]
impl DnsProvider for AliyunProvider {
    fn id(&self) -> &'static str {
        "aliyun"
    }

    async fn validate_credentials(&self) -> Result<bool> {
        #[derive(Serialize)]
        struct DescribeDomainsRequest {
            #[serde(rename = "PageNumber")]
            page_number: u32,
            #[serde(rename = "PageSize")]
            page_size: u32,
        }

        let req = DescribeDomainsRequest {
            page_number: 1,
            page_size: 1,
        };

        match self
            .request::<DescribeDomainsResponse, _>("DescribeDomains", &req)
            .await
        {
            Ok(_) => Ok(true),
            Err(ProviderError::InvalidCredentials { .. }) => Ok(false),
            Err(e) => {
                log::warn!("凭证验证失败: {e}");
                Ok(false)
            }
        }
    }

    async fn list_domains(
        &self,
        params: &PaginationParams,
    ) -> Result<PaginatedResponse<ProviderDomain>> {
        #[derive(Serialize)]
        struct DescribeDomainsRequest {
            #[serde(rename = "PageNumber")]
            page_number: u32,
            #[serde(rename = "PageSize")]
            page_size: u32,
        }

        let req = DescribeDomainsRequest {
            page_number: params.page,
            page_size: params.page_size.min(MAX_PAGE_SIZE),
        };

        let response: DescribeDomainsResponse = self.request("DescribeDomains", &req).await?;

        let total_count = response.total_count.unwrap_or(0);
        let domains = response
            .domains
            .and_then(|d| d.domain)
            .unwrap_or_default()
            .into_iter()
            .map(|d| ProviderDomain {
                id: d.domain_id.unwrap_or_else(|| d.domain_name.clone()),
                name: d.domain_name,
                provider: ProviderType::Aliyun,
                status: Self::convert_domain_status(d.domain_status.as_deref()),
                record_count: d.record_count,
            })
            .collect();

        Ok(PaginatedResponse::new(
            domains,
            params.page,
            params.page_size,
            total_count,
        ))
    }

    async fn get_domain(&self, domain_id: &str) -> Result<ProviderDomain> {
        // 阿里云 API 需要域名名称，先从域名列表中查找
        // 使用大页面一次性获取用于查找
        let params = PaginationParams {
            page: 1,
            page_size: 100,
        };
        let response = self.list_domains(&params).await?;

        response
            .items
            .into_iter()
            .find(|d| d.id == domain_id || d.name == domain_id)
            .ok_or_else(|| ProviderError::DomainNotFound {
                provider: self.provider_name().to_string(),
                domain: domain_id.to_string(),
                raw_message: None,
            })
    }

    async fn list_records(
        &self,
        domain_id: &str,
        params: &RecordQueryParams,
    ) -> Result<PaginatedResponse<DnsRecord>> {
        #[derive(Serialize)]
        struct DescribeDomainRecordsRequest {
            #[serde(rename = "DomainName")]
            domain_name: String,
            #[serde(rename = "PageNumber")]
            page_number: u32,
            #[serde(rename = "PageSize")]
            page_size: u32,
            /// 主机记录关键字（模糊搜索）
            #[serde(rename = "RRKeyWord", skip_serializing_if = "Option::is_none")]
            rr_keyword: Option<String>,
            /// 记录类型过滤
            #[serde(rename = "Type", skip_serializing_if = "Option::is_none")]
            record_type: Option<String>,
        }

        // 获取域名信息 (因为 API 需要域名名称而不是 ID)
        let domain_info = self.get_domain(domain_id).await?;

        let req = DescribeDomainRecordsRequest {
            domain_name: domain_info.name,
            page_number: params.page,
            page_size: params.page_size.min(MAX_PAGE_SIZE),
            rr_keyword: params.keyword.clone().filter(|k| !k.is_empty()),
            record_type: params
                .record_type
                .as_ref()
                .map(|t| record_type_to_string(t).to_string()),
        };

        let response: DescribeDomainRecordsResponse =
            self.request("DescribeDomainRecords", &req).await?;

        let total_count = response.total_count.unwrap_or(0);
        let records = response
            .domain_records
            .and_then(|r| r.record)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| {
                let record_type = parse_record_type(&r.record_type, "aliyun").ok()?;
                Some(DnsRecord {
                    id: r.record_id,
                    domain_id: domain_id.to_string(),
                    record_type,
                    name: r.rr,
                    value: r.value,
                    ttl: r.ttl,
                    priority: r.priority,
                    proxied: None, // 阿里云不支持代理
                    created_at: Self::timestamp_to_rfc3339(r.create_timestamp),
                    updated_at: Self::timestamp_to_rfc3339(r.update_timestamp),
                })
            })
            .collect();

        Ok(PaginatedResponse::new(
            records,
            params.page,
            params.page_size,
            total_count,
        ))
    }

    async fn create_record(&self, req: &CreateDnsRecordRequest) -> Result<DnsRecord> {
        #[derive(Serialize)]
        struct AddDomainRecordRequest {
            #[serde(rename = "DomainName")]
            domain_name: String,
            #[serde(rename = "RR")]
            rr: String,
            #[serde(rename = "Type")]
            record_type: String,
            #[serde(rename = "Value")]
            value: String,
            #[serde(rename = "TTL")]
            ttl: u32,
            #[serde(rename = "Priority", skip_serializing_if = "Option::is_none")]
            priority: Option<u16>,
        }

        // 获取域名信息
        let domain_info = self.get_domain(&req.domain_id).await?;

        let api_req = AddDomainRecordRequest {
            domain_name: domain_info.name,
            rr: req.name.clone(),
            record_type: record_type_to_string(&req.record_type).to_string(),
            value: req.value.clone(),
            ttl: req.ttl,
            priority: req.priority,
        };

        let response: AddDomainRecordResponse = self.request("AddDomainRecord", &api_req).await?;

        let now = chrono::Utc::now().to_rfc3339();
        Ok(DnsRecord {
            id: response.record_id,
            domain_id: req.domain_id.clone(),
            record_type: req.record_type.clone(),
            name: req.name.clone(),
            value: req.value.clone(),
            ttl: req.ttl,
            priority: req.priority,
            proxied: None,
            created_at: Some(now.clone()),
            updated_at: Some(now),
        })
    }

    async fn update_record(
        &self,
        record_id: &str,
        req: &UpdateDnsRecordRequest,
    ) -> Result<DnsRecord> {
        #[derive(Serialize)]
        struct UpdateDomainRecordRequest {
            #[serde(rename = "RecordId")]
            record_id: String,
            #[serde(rename = "RR")]
            rr: String,
            #[serde(rename = "Type")]
            record_type: String,
            #[serde(rename = "Value")]
            value: String,
            #[serde(rename = "TTL")]
            ttl: u32,
            #[serde(rename = "Priority", skip_serializing_if = "Option::is_none")]
            priority: Option<u16>,
        }

        let api_req = UpdateDomainRecordRequest {
            record_id: record_id.to_string(),
            rr: req.name.clone(),
            record_type: record_type_to_string(&req.record_type).to_string(),
            value: req.value.clone(),
            ttl: req.ttl,
            priority: req.priority,
        };

        let _response: UpdateDomainRecordResponse =
            self.request("UpdateDomainRecord", &api_req).await?;

        let now = chrono::Utc::now().to_rfc3339();
        Ok(DnsRecord {
            id: record_id.to_string(),
            domain_id: req.domain_id.clone(),
            record_type: req.record_type.clone(),
            name: req.name.clone(),
            value: req.value.clone(),
            ttl: req.ttl,
            priority: req.priority,
            proxied: None,
            created_at: None,
            updated_at: Some(now),
        })
    }

    async fn delete_record(&self, record_id: &str, _domain_id: &str) -> Result<()> {
        #[derive(Serialize)]
        struct DeleteDomainRecordRequest {
            #[serde(rename = "RecordId")]
            record_id: String,
        }

        let api_req = DeleteDomainRecordRequest {
            record_id: record_id.to_string(),
        };

        let _response: DeleteDomainRecordResponse =
            self.request("DeleteDomainRecord", &api_req).await?;

        Ok(())
    }
}
