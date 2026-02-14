//! `DNSPod` `DnsProvider` trait implementation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{ProviderError, Result};
use crate::providers::common::{
    parse_record_data_with_priority, record_data_to_value_priority, record_type_to_string,
};
use crate::traits::{DnsProvider, ErrorContext, ProviderErrorMapper};
use crate::types::{
    CreateDnsRecordRequest, DnsRecord, DomainStatus, FieldType, PaginatedResponse,
    PaginationParams, ProviderCredentialField, ProviderDomain, ProviderFeatures, ProviderLimits,
    ProviderMetadata, ProviderType, RecordData, RecordQueryParams, UpdateDnsRecordRequest,
};

use super::{
    CreateRecordResponse, DescribeDomainResponse, DnspodProvider, DomainListResponse,
    MAX_PAGE_SIZE, ModifyRecordResponse, RecordListResponse,
};

impl DnspodProvider {
    /// Get domain name information (use cache first)
    async fn get_domain_cached(&self, domain_id: &str) -> Result<ProviderDomain> {
        if let Some(domain) = self.domain_cache.get(domain_id) {
            return Ok(domain);
        }
        let domain = self.get_domain(domain_id).await?;
        self.domain_cache.insert(domain_id, &domain);
        Ok(domain)
    }

    /// Convert `DNSPod` domain name status to internal status
    pub(crate) fn convert_domain_status(status: &str, dns_status: &str) -> DomainStatus {
        match (status, dns_status) {
            ("ENABLE" | "enable", "") => DomainStatus::Active,
            ("PAUSE" | "pause", _) => DomainStatus::Paused,
            ("ENABLE" | "enable", "DNSERROR") | ("SPAM" | "spam", _) => DomainStatus::Error,
            _ => DomainStatus::Unknown,
        }
    }

    /// Parse `DNSPod` record as `RecordData` (use mx field as priority)
    fn parse_record_data(record_type: &str, value: String, mx: Option<u16>) -> Result<RecordData> {
        parse_record_data_with_priority(record_type, value, mx, "dnspod")
    }

    /// Convert `RecordData` to `DNSPod` API format (value, mx)
    fn record_data_to_api(data: &RecordData) -> (String, Option<u16>) {
        record_data_to_value_priority(data)
    }
}

#[async_trait]
impl DnsProvider for DnspodProvider {
    fn id(&self) -> &'static str {
        "dnspod"
    }

    fn metadata() -> ProviderMetadata {
        ProviderMetadata {
            id: ProviderType::Dnspod,
            name: "Tencent Cloud DNSPod".to_string(),
            description: "Tencent Cloud DNS resolution service".to_string(),
            required_fields: vec![
                ProviderCredentialField {
                    key: "secretId".to_string(),
                    label: "SecretId".to_string(),
                    field_type: FieldType::Text,
                    placeholder: Some("Enter SecretId".to_string()),
                    help_text: None,
                },
                ProviderCredentialField {
                    key: "secretKey".to_string(),
                    label: "SecretKey".to_string(),
                    field_type: FieldType::Password,
                    placeholder: Some("Enter SecretKey".to_string()),
                    help_text: None,
                },
            ],
            features: ProviderFeatures::default(),
            limits: ProviderLimits {
                max_page_size_domains: 3000,
                max_page_size_records: 3000,
            },
        }
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
            .request::<DomainListResponse, _>("DescribeDomainList", &req, ErrorContext::default())
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
        struct DescribeDomainListRequest {
            #[serde(rename = "Offset")]
            offset: u32,
            #[serde(rename = "Limit")]
            limit: u32,
        }

        let params = params.validated(MAX_PAGE_SIZE);
        // Convert page/page_size to offset/limit
        let offset = (params.page - 1) * params.page_size;
        let req = DescribeDomainListRequest {
            offset,
            limit: params.page_size,
        };

        let response: DomainListResponse = self
            .request("DescribeDomainList", &req, ErrorContext::default())
            .await?;

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

    /// Use `DescribeDomain` API to directly obtain domain name information
    /// Note: `DNSPod` API requires a domain name. If a numeric ID is passed in, it will fallback to the list to find it.
    async fn get_domain(&self, domain_id: &str) -> Result<ProviderDomain> {
        // If domain_id contains '.', it is considered to be the domain name and the API is called directly
        if domain_id.contains('.') {
            #[derive(Serialize)]
            struct DescribeDomainRequest {
                #[serde(rename = "Domain")]
                domain: String,
            }

            let req = DescribeDomainRequest {
                domain: domain_id.to_string(),
            };

            let ctx = ErrorContext {
                domain: Some(domain_id.to_string()),
                ..Default::default()
            };

            let response: DescribeDomainResponse =
                self.request("DescribeDomain", &req, ctx).await?;
            let info = response.domain_info;

            return Ok(ProviderDomain {
                id: info.domain_id.to_string(),
                name: info.domain,
                provider: ProviderType::Dnspod,
                status: Self::convert_domain_status(&info.status, &info.dns_status),
                record_count: info.record_count,
            });
        }

        // Fallback: Numeric ID, paging search
        let mut page = 1u32;
        let page_size = 100u32;
        loop {
            let params = PaginationParams { page, page_size };
            let response = self.list_domains(&params).await?;

            if let Some(found) = response.items.into_iter().find(|d| d.id == domain_id) {
                return Ok(found);
            }

            if !response.has_more {
                break;
            }
            page += 1;
        }

        Err(ProviderError::DomainNotFound {
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

        let params = params.validated(MAX_PAGE_SIZE);
        let domain_info = self.get_domain_cached(domain_id).await?;

        let offset = (params.page - 1) * params.page_size;
        let req = DescribeRecordListRequest {
            domain: domain_info.name,
            offset,
            limit: params.page_size,
            keyword: params.keyword.clone().filter(|k| !k.is_empty()),
            record_type: params
                .record_type
                .as_ref()
                .map(|t| record_type_to_string(t).to_string()),
        };

        let ctx = ErrorContext {
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };

        let response: Result<RecordListResponse> =
            self.request("DescribeRecordList", &req, ctx).await;

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
                        let data = match Self::parse_record_data(&r.record_type, r.value, r.mx) {
                            Ok(data) => data,
                            Err(ProviderError::UnsupportedRecordType { .. }) => return None,
                            Err(e) => {
                                log::warn!("[dnspod] Skipping record due to parse error: {e}");
                                return None;
                            }
                        };
                        Some(DnsRecord {
                            id: r.record_id.to_string(),
                            domain_id: domain_id.to_string(),
                            name: r.name,
                            ttl: r.ttl,
                            data,
                            proxied: None,
                            created_at: None,
                            updated_at: r.updated_on.and_then(|s| {
                                chrono::DateTime::parse_from_rfc3339(&s)
                                    .ok()
                                    .map(|dt| dt.with_timezone(&chrono::Utc))
                            }),
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

        let domain_info = self.get_domain_cached(&req.domain_id).await?;

        // Extract value and mx from RecordData
        let (value, mx) = Self::record_data_to_api(&req.data);
        let record_type = record_type_to_string(&req.data.record_type());

        let api_req = CreateRecordRequest {
            domain: domain_info.name,
            sub_domain: req.name.clone(),
            record_type: record_type.to_string(),
            record_line: "默认".to_string(),
            value,
            ttl: req.ttl,
            mx,
        };

        let ctx = ErrorContext {
            record_name: Some(req.name.clone()),
            domain: Some(req.domain_id.clone()),
            ..Default::default()
        };

        let response: CreateRecordResponse = self.request("CreateRecord", &api_req, ctx).await?;

        let now = chrono::Utc::now();
        Ok(DnsRecord {
            id: response.record_id.to_string(),
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

        let domain_info = self.get_domain_cached(&req.domain_id).await?;

        // Extract value and mx from RecordData
        let (value, mx) = Self::record_data_to_api(&req.data);
        let record_type = record_type_to_string(&req.data.record_type());

        let api_req = ModifyRecordRequest {
            domain: domain_info.name,
            record_id: record_id_num,
            sub_domain: req.name.clone(),
            record_type: record_type.to_string(),
            record_line: "默认".to_string(),
            value,
            ttl: req.ttl,
            mx,
        };

        let ctx = ErrorContext {
            record_name: Some(req.name.clone()),
            record_id: Some(record_id.to_string()),
            domain: Some(req.domain_id.clone()),
        };

        let _response: ModifyRecordResponse = self.request("ModifyRecord", &api_req, ctx).await?;

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

        let domain_info = self.get_domain_cached(domain_id).await?;

        let api_req = DeleteRecordRequest {
            domain: domain_info.name,
            record_id: record_id_num,
        };

        let ctx = ErrorContext {
            record_id: Some(record_id.to_string()),
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };

        let _response: DeleteRecordResponse = self.request("DeleteRecord", &api_req, ctx).await?;

        Ok(())
    }
}
