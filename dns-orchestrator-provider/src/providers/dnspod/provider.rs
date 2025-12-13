//! DNSPod DnsProvider trait 实现

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{ProviderError, Result};
use crate::providers::common::{parse_record_type, record_type_to_string};
use crate::traits::{DnsProvider, ProviderErrorMapper};
use crate::types::{
    CreateDnsRecordRequest, DnsRecord, DomainStatus, PaginatedResponse, PaginationParams,
    ProviderDomain, ProviderType, RecordQueryParams, UpdateDnsRecordRequest,
};

use super::{
    CreateRecordResponse, DnspodProvider, DomainListResponse, MAX_PAGE_SIZE, ModifyRecordResponse,
    RecordListResponse,
};

impl DnspodProvider {
    /// 将 DNSPod 域名状态转换为内部状态
    pub(crate) fn convert_domain_status(status: &str, dns_status: &str) -> DomainStatus {
        match (status, dns_status) {
            ("ENABLE" | "enable", "") => DomainStatus::Active,
            ("PAUSE" | "pause", _) => DomainStatus::Paused,
            ("ENABLE" | "enable", "DNSERROR") => DomainStatus::Error,
            ("SPAM" | "spam", _) => DomainStatus::Error,
            _ => DomainStatus::Unknown,
        }
    }
}

#[async_trait]
impl DnsProvider for DnspodProvider {
    fn id(&self) -> &'static str {
        "dnspod"
    }

    async fn validate_credentials(&self) -> Result<bool> {
        #[derive(Serialize)]
        struct DescribeDomainListRequest {
            #[serde(rename = "Offset")]
            offset: u32,
            #[serde(rename = "Limit")]
            limit: u32,
        }

        let req = DescribeDomainListRequest {
            offset: 0,
            limit: 1,
        };

        match self
            .request::<DomainListResponse, _>("DescribeDomainList", &req)
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
        struct DescribeDomainListRequest {
            #[serde(rename = "Offset")]
            offset: u32,
            #[serde(rename = "Limit")]
            limit: u32,
        }

        // 将 page/page_size 转换为 offset/limit
        let offset = (params.page - 1) * params.page_size;
        let req = DescribeDomainListRequest {
            offset,
            limit: params.page_size.min(MAX_PAGE_SIZE),
        };

        let response: DomainListResponse = self.request("DescribeDomainList", &req).await?;

        let total_count = response
            .domain_count_info
            .and_then(|c| c.all_total)
            .unwrap_or(0);

        let domains = response
            .domain_list
            .unwrap_or_default()
            .into_iter()
            .map(|d| ProviderDomain {
                id: d.domain_id.to_string(),
                name: d.name,
                provider: ProviderType::Dnspod,
                status: Self::convert_domain_status(&d.status, &d.dns_status),
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
        let params = PaginationParams {
            page: 1,
            page_size: 100,
        };
        let response = self.list_domains(&params).await?;

        response
            .items
            .into_iter()
            .find(|d| d.id == domain_id)
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
        struct DescribeRecordListRequest {
            #[serde(rename = "Domain")]
            domain: String,
            #[serde(rename = "Offset")]
            offset: u32,
            #[serde(rename = "Limit")]
            limit: u32,
            #[serde(rename = "Keyword", skip_serializing_if = "Option::is_none")]
            keyword: Option<String>,
            #[serde(rename = "RecordType", skip_serializing_if = "Option::is_none")]
            record_type: Option<String>,
        }

        let domain_info = self.get_domain(domain_id).await?;

        let offset = (params.page - 1) * params.page_size;
        let req = DescribeRecordListRequest {
            domain: domain_info.name,
            offset,
            limit: params.page_size.min(MAX_PAGE_SIZE),
            keyword: params.keyword.clone().filter(|k| !k.is_empty()),
            record_type: params
                .record_type
                .as_ref()
                .map(|t| record_type_to_string(t).to_string()),
        };

        let response: Result<RecordListResponse> = self.request("DescribeRecordList", &req).await;

        match response {
            Ok(data) => {
                let total_count = data
                    .record_count_info
                    .and_then(|c| c.total_count)
                    .unwrap_or(0);

                let records = data
                    .record_list
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|r| {
                        let record_type = parse_record_type(&r.record_type, "dnspod").ok()?;
                        Some(DnsRecord {
                            id: r.record_id.to_string(),
                            domain_id: domain_id.to_string(),
                            record_type,
                            name: r.name,
                            value: r.value,
                            ttl: r.ttl,
                            priority: r.mx,
                            proxied: None,
                            created_at: None,
                            updated_at: r.updated_on,
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
            Err(ProviderError::Unknown { raw_code, .. })
                if raw_code.as_deref() == Some("ResourceNotFound.NoDataOfRecord") =>
            {
                Ok(PaginatedResponse::new(
                    vec![],
                    params.page,
                    params.page_size,
                    0,
                ))
            }
            Err(e) => Err(e),
        }
    }

    async fn create_record(&self, req: &CreateDnsRecordRequest) -> Result<DnsRecord> {
        #[derive(Serialize)]
        struct CreateRecordRequest {
            #[serde(rename = "Domain")]
            domain: String,
            #[serde(rename = "SubDomain")]
            sub_domain: String,
            #[serde(rename = "RecordType")]
            record_type: String,
            #[serde(rename = "RecordLine")]
            record_line: String,
            #[serde(rename = "Value")]
            value: String,
            #[serde(rename = "TTL")]
            ttl: u32,
            #[serde(rename = "MX", skip_serializing_if = "Option::is_none")]
            mx: Option<u16>,
        }

        let domain_info = self.get_domain(&req.domain_id).await?;

        let api_req = CreateRecordRequest {
            domain: domain_info.name,
            sub_domain: req.name.clone(),
            record_type: record_type_to_string(&req.record_type).to_string(),
            record_line: "默认".to_string(),
            value: req.value.clone(),
            ttl: req.ttl,
            mx: req.priority,
        };

        let response: CreateRecordResponse = self.request("CreateRecord", &api_req).await?;

        let now = chrono::Utc::now().to_rfc3339();
        Ok(DnsRecord {
            id: response.record_id.to_string(),
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
        struct ModifyRecordRequest {
            #[serde(rename = "Domain")]
            domain: String,
            #[serde(rename = "RecordId")]
            record_id: u64,
            #[serde(rename = "SubDomain")]
            sub_domain: String,
            #[serde(rename = "RecordType")]
            record_type: String,
            #[serde(rename = "RecordLine")]
            record_line: String,
            #[serde(rename = "Value")]
            value: String,
            #[serde(rename = "TTL")]
            ttl: u32,
            #[serde(rename = "MX", skip_serializing_if = "Option::is_none")]
            mx: Option<u16>,
        }

        let record_id_num: u64 = record_id
            .parse()
            .map_err(|_| ProviderError::RecordNotFound {
                provider: self.provider_name().to_string(),
                record_id: record_id.to_string(),
                raw_message: None,
            })?;

        let domain_info = self.get_domain(&req.domain_id).await?;

        let api_req = ModifyRecordRequest {
            domain: domain_info.name,
            record_id: record_id_num,
            sub_domain: req.name.clone(),
            record_type: record_type_to_string(&req.record_type).to_string(),
            record_line: "默认".to_string(),
            value: req.value.clone(),
            ttl: req.ttl,
            mx: req.priority,
        };

        let _response: ModifyRecordResponse = self.request("ModifyRecord", &api_req).await?;

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

    async fn delete_record(&self, record_id: &str, domain_id: &str) -> Result<()> {
        #[derive(Serialize)]
        struct DeleteRecordRequest {
            #[serde(rename = "Domain")]
            domain: String,
            #[serde(rename = "RecordId")]
            record_id: u64,
        }

        #[derive(Debug, Deserialize)]
        struct DeleteRecordResponse {}

        let record_id_num: u64 = record_id
            .parse()
            .map_err(|_| ProviderError::RecordNotFound {
                provider: self.provider_name().to_string(),
                record_id: record_id.to_string(),
                raw_message: None,
            })?;

        let domain_info = self.get_domain(domain_id).await?;

        let api_req = DeleteRecordRequest {
            domain: domain_info.name,
            record_id: record_id_num,
        };

        let _response: DeleteRecordResponse = self.request("DeleteRecord", &api_req).await?;

        Ok(())
    }
}
