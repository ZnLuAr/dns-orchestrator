//! Alibaba Cloud `DnsProvider` trait implementation

use async_trait::async_trait;
use chrono::DateTime;
use serde::Serialize;

use crate::error::{ProviderError, Result};
use crate::providers::common::{
    parse_record_data_with_priority, record_data_to_value_priority, record_type_to_string,
};
use crate::traits::{DnsProvider, ErrorContext};
use crate::types::{
    CreateDnsRecordRequest, DnsRecord, DomainStatus, FieldType, PaginatedResponse,
    PaginationParams, ProviderCredentialField, ProviderDomain, ProviderFeatures, ProviderLimits,
    ProviderMetadata, ProviderType, RecordData, RecordQueryParams, UpdateDnsRecordRequest,
};

use super::{
    AddDomainRecordResponse, AliyunProvider, DeleteDomainRecordResponse,
    DescribeDomainInfoResponse, DescribeDomainRecordsResponse, DescribeDomainsResponse,
    MAX_PAGE_SIZE, UpdateDomainRecordResponse,
};

impl AliyunProvider {
    /// Convert Alibaba Cloud domain name status to internal status
    /// Note: Alibaba Cloud `DescribeDomains` API does not actually return the `DomainStatus` field
    pub(crate) fn convert_domain_status(status: Option<&str>) -> DomainStatus {
        match status {
            Some("ENABLE" | "enable") => DomainStatus::Active,
            Some("PAUSE" | "pause") => DomainStatus::Paused,
            Some("SPAM" | "spam") => DomainStatus::Error,
            _ => DomainStatus::Unknown,
        }
    }

    /// Convert Alibaba Cloud's Unix millisecond timestamp to `DateTime`<Utc>
    pub(crate) fn timestamp_to_datetime(timestamp: Option<i64>) -> Option<DateTime<chrono::Utc>> {
        timestamp.and_then(DateTime::from_timestamp_millis)
    }

    /// Parse Alibaba Cloud record as `RecordData`
    fn parse_record_data(
        record_type: &str,
        value: String,
        priority: Option<u16>,
    ) -> Result<RecordData> {
        parse_record_data_with_priority(record_type, value, priority, "aliyun")
    }

    /// Convert `RecordData` to Alibaba Cloud API format (value, priority)
    fn record_data_to_api(data: &RecordData) -> (String, Option<u16>) {
        record_data_to_value_priority(data)
    }
}

#[async_trait]
impl DnsProvider for AliyunProvider {
    fn id(&self) -> &'static str {
        "aliyun"
    }

    fn metadata() -> ProviderMetadata {
        ProviderMetadata {
            id: ProviderType::Aliyun,
            name: "Aliyun DNS".to_string(),
            description: "Alibaba Cloud DNS resolution service".to_string(),
            required_fields: vec![
                ProviderCredentialField {
                    key: "accessKeyId".to_string(),
                    label: "AccessKey ID".to_string(),
                    field_type: FieldType::Text,
                    placeholder: Some("Enter AccessKey ID".to_string()),
                    help_text: None,
                },
                ProviderCredentialField {
                    key: "accessKeySecret".to_string(),
                    label: "AccessKey Secret".to_string(),
                    field_type: FieldType::Password,
                    placeholder: Some("Enter AccessKey Secret".to_string()),
                    help_text: None,
                },
            ],
            features: ProviderFeatures::default(),
            limits: ProviderLimits {
                max_page_size_domains: 100,
                max_page_size_records: 100,
            },
        }
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
            .request::<DescribeDomainsResponse, _>("DescribeDomains", &req, ErrorContext::default())
            .await
        {
            Ok(_) => Ok(true),
            Err(ProviderError::InvalidCredentials { .. }) => Ok(false),
            Err(e) => Err(e),
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

        let params = params.validated(MAX_PAGE_SIZE);
        let req = DescribeDomainsRequest {
            page_number: params.page,
            page_size: params.page_size,
        };

        let response: DescribeDomainsResponse = self
            .request("DescribeDomains", &req, ErrorContext::default())
            .await?;

        let total_count = response.total_count.unwrap_or(0);
        let domains = response
            .domains
            .and_then(|d| d.domain)
            .unwrap_or_default()
            .into_iter()
            .map(|d| ProviderDomain {
                // Alibaba Cloud API uses domain name as identifier instead of domain_id
                id: d.domain_name.clone(),
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

    /// `ErrorRequireCheck`: Use `DescribeDomainInfo` API to directly obtain domain name information
    /// Note: Alibaba Cloud API requires domain name as parameter
    async fn get_domain(&self, domain_id: &str) -> Result<ProviderDomain> {
        #[derive(Serialize)]
        struct DescribeDomainInfoRequest {
            #[serde(rename = "DomainName")]
            domain_name: String,
        }

        let req = DescribeDomainInfoRequest {
            domain_name: domain_id.to_string(),
        };

        let ctx = ErrorContext {
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };

        let response: DescribeDomainInfoResponse =
            self.request("DescribeDomainInfo", &req, ctx).await?;

        Ok(ProviderDomain {
            // Use the domain name as the ID uniformly, consistent with list_domains
            id: response.domain_name.clone(),
            name: response.domain_name,
            provider: ProviderType::Aliyun,
            status: Self::convert_domain_status(response.domain_status.as_deref()),
            record_count: response.record_count,
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
            /// Host record keywords (fuzzy search)
            #[serde(rename = "RRKeyWord", skip_serializing_if = "Option::is_none")]
            rr_keyword: Option<String>,
            /// Record type filtering
            #[serde(rename = "Type", skip_serializing_if = "Option::is_none")]
            record_type: Option<String>,
        }

        let params = params.validated(MAX_PAGE_SIZE);
        // Alibaba Cloud's domain_id is the domain name and can be used directly
        let req = DescribeDomainRecordsRequest {
            domain_name: domain_id.to_string(),
            page_number: params.page,
            page_size: params.page_size,
            rr_keyword: params.keyword.clone().filter(|k| !k.is_empty()),
            record_type: params
                .record_type
                .as_ref()
                .map(|t| record_type_to_string(t).to_string()),
        };

        let ctx = ErrorContext {
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };

        let response: DescribeDomainRecordsResponse =
            self.request("DescribeDomainRecords", &req, ctx).await?;

        let total_count = response.total_count.unwrap_or(0);
        let records = response
            .domain_records
            .and_then(|r| r.record)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| {
                let data = match Self::parse_record_data(&r.record_type, r.value, r.priority) {
                    Ok(data) => data,
                    Err(ProviderError::UnsupportedRecordType { .. }) => return None,
                    Err(e) => {
                        log::warn!("[aliyun] Skipping record due to parse error: {e}");
                        return None;
                    }
                };
                Some(DnsRecord {
                    id: r.record_id,
                    domain_id: domain_id.to_string(),
                    name: r.rr,
                    ttl: r.ttl,
                    data,
                    proxied: None, // Alibaba Cloud does not support proxy
                    created_at: Self::timestamp_to_datetime(r.create_timestamp),
                    updated_at: Self::timestamp_to_datetime(r.update_timestamp),
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

        // Extract value and priority from RecordData
        let (value, priority) = Self::record_data_to_api(&req.data);
        let record_type = record_type_to_string(&req.data.record_type());

        // Alibaba Cloud's domain_id is the domain name and can be used directly
        let api_req = AddDomainRecordRequest {
            domain_name: req.domain_id.clone(),
            rr: req.name.clone(),
            record_type: record_type.to_string(),
            value,
            ttl: req.ttl,
            priority,
        };

        let ctx = ErrorContext {
            record_name: Some(req.name.clone()),
            domain: Some(req.domain_id.clone()),
            ..Default::default()
        };

        let response: AddDomainRecordResponse =
            self.request("AddDomainRecord", &api_req, ctx).await?;

        let now = chrono::Utc::now();
        Ok(DnsRecord {
            id: response.record_id,
            domain_id: req.domain_id.clone(),
            name: req.name.clone(),
            ttl: req.ttl,
            data: req.data.clone(),
            proxied: None,
            created_at: Some(now),
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

        // Extract value and priority from RecordData
        let (value, priority) = Self::record_data_to_api(&req.data);
        let record_type = record_type_to_string(&req.data.record_type());

        let api_req = UpdateDomainRecordRequest {
            record_id: record_id.to_string(),
            rr: req.name.clone(),
            record_type: record_type.to_string(),
            value,
            ttl: req.ttl,
            priority,
        };

        let ctx = ErrorContext {
            record_name: Some(req.name.clone()),
            record_id: Some(record_id.to_string()),
            domain: Some(req.domain_id.clone()),
        };

        let _response: UpdateDomainRecordResponse =
            self.request("UpdateDomainRecord", &api_req, ctx).await?;

        let now = chrono::Utc::now();
        Ok(DnsRecord {
            id: record_id.to_string(),
            domain_id: req.domain_id.clone(),
            name: req.name.clone(),
            ttl: req.ttl,
            data: req.data.clone(),
            proxied: None,
            created_at: None,
            updated_at: Some(now),
        })
    }

    async fn delete_record(&self, record_id: &str, domain_id: &str) -> Result<()> {
        #[derive(Serialize)]
        struct DeleteDomainRecordRequest {
            #[serde(rename = "RecordId")]
            record_id: String,
        }

        let api_req = DeleteDomainRecordRequest {
            record_id: record_id.to_string(),
        };

        let ctx = ErrorContext {
            record_id: Some(record_id.to_string()),
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };

        let _response: DeleteDomainRecordResponse =
            self.request("DeleteDomainRecord", &api_req, ctx).await?;

        Ok(())
    }
}
