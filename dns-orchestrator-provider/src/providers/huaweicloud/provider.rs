//! Huawei Cloud `DnsProvider` trait implementation

use std::fmt::Write;

use async_trait::async_trait;
use serde::Serialize;

use crate::error::{ProviderError, Result};
use crate::providers::common::{
    full_name_to_relative, normalize_domain_name, parse_record_data_from_string,
    record_data_to_single_string, record_type_to_string, relative_to_full_name,
};
use crate::traits::{DnsProvider, ErrorContext};
use crate::types::{
    CreateDnsRecordRequest, DnsRecord, DomainStatus, FieldType, PaginatedResponse,
    PaginationParams, ProviderCredentialField, ProviderDomain, ProviderFeatures, ProviderLimits,
    ProviderMetadata, ProviderType, RecordData, RecordQueryParams, UpdateDnsRecordRequest,
};

use super::types::{
    CreateRecordSetResponse, ListRecordSetsResponse, ListZonesResponse, ShowPublicZoneResponse,
};
use super::{HuaweicloudProvider, MAX_PAGE_SIZE};

impl HuaweicloudProvider {
    /// Get domain name information (use cache first)
    async fn get_domain_cached(&self, domain_id: &str) -> Result<ProviderDomain> {
        if let Some(domain) = self.domain_cache.get(domain_id) {
            return Ok(domain);
        }
        let domain = self.get_domain(domain_id).await?;
        self.domain_cache.insert(domain_id, &domain);
        Ok(domain)
    }

    /// Convert Huawei Cloud domain name status to internal status
    /// Huawei Cloud status: ACTIVE, `PENDING_CREATE`, `PENDING_UPDATE`, `PENDING_DELETE`,
    /// `PENDING_FREEZE`, FREEZE, ILLEGAL, POLICE, `PENDING_DISABLE`, DISABLE, ERROR
    pub(crate) fn convert_domain_status(status: Option<&str>) -> DomainStatus {
        match status {
            Some("ACTIVE") => DomainStatus::Active,
            // Various PENDING states
            Some(
                "PENDING_CREATE" | "PENDING_UPDATE" | "PENDING_DELETE" | "PENDING_FREEZE"
                | "PENDING_DISABLE",
            ) => DomainStatus::Pending,
            // freeze/pause state
            Some("FREEZE" | "ILLEGAL" | "POLICE" | "DISABLE") => DomainStatus::Paused,
            Some("ERROR") => DomainStatus::Error,
            _ => DomainStatus::Unknown,
        }
    }

    /// Parse the Huawei Cloud record as `RecordData`
    /// Huawei Cloud format: All fields of MX/SRV/CAA are encoded in the records string
    fn parse_record_data(record_type: &str, record: String) -> Result<RecordData> {
        parse_record_data_from_string(record_type, record, "huaweicloud")
    }

    /// Convert `RecordData` to Huawei Cloud API format (records string)
    fn record_data_to_record_string(data: &RecordData) -> String {
        record_data_to_single_string(data)
    }
}

#[async_trait]
impl DnsProvider for HuaweicloudProvider {
    fn id(&self) -> &'static str {
        "huaweicloud"
    }

    fn metadata() -> ProviderMetadata {
        ProviderMetadata {
            id: ProviderType::Huaweicloud,
            name: "Huawei Cloud DNS".to_string(),
            description: "Huawei Cloud DNS resolution service".to_string(),
            required_fields: vec![
                ProviderCredentialField {
                    key: "accessKeyId".to_string(),
                    label: "Access Key ID".to_string(),
                    field_type: FieldType::Text,
                    placeholder: Some("Enter Access Key ID".to_string()),
                    help_text: None,
                },
                ProviderCredentialField {
                    key: "secretAccessKey".to_string(),
                    label: "Secret Access Key".to_string(),
                    field_type: FieldType::Password,
                    placeholder: Some("Enter Secret Access Key".to_string()),
                    help_text: None,
                },
            ],
            features: ProviderFeatures::default(),
            limits: ProviderLimits {
                max_page_size_domains: 500,
                max_page_size_records: 500,
            },
        }
    }

    async fn validate_credentials(&self) -> Result<bool> {
        match self
            .get::<ListZonesResponse>("/v2/zones", "type=public&limit=1", ErrorContext::default())
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
        let params = params.validated(MAX_PAGE_SIZE);
        // Huawei Cloud uses offset/limit paging
        let offset = (params.page - 1) * params.page_size;
        let limit = params.page_size;
        let query = format!("type=public&offset={offset}&limit={limit}");

        let response: ListZonesResponse = self
            .get("/v2/zones", &query, ErrorContext::default())
            .await?;

        let total_count = response.metadata.and_then(|m| m.total_count).unwrap_or(0);

        let domains = response
            .zones
            .unwrap_or_default()
            .into_iter()
            .map(|z| ProviderDomain {
                id: z.id,
                name: normalize_domain_name(&z.name),
                provider: ProviderType::Huaweicloud,
                status: Self::convert_domain_status(z.status.as_deref()),
                record_count: z.record_num,
            })
            .collect();

        Ok(PaginatedResponse::new(
            domains,
            params.page,
            params.page_size,
            total_count,
        ))
    }

    /// Use `ShowPublicZone` API to directly obtain domain name information
    async fn get_domain(&self, domain_id: &str) -> Result<ProviderDomain> {
        let path = format!("/v2/zones/{domain_id}");
        let ctx = ErrorContext {
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };
        let response: ShowPublicZoneResponse = self.get(&path, "", ctx).await?;

        Ok(ProviderDomain {
            id: response.id,
            name: normalize_domain_name(&response.name),
            provider: ProviderType::Huaweicloud,
            status: Self::convert_domain_status(response.status.as_deref()),
            record_count: response.record_num,
        })
    }

    async fn list_records(
        &self,
        domain_id: &str,
        params: &RecordQueryParams,
    ) -> Result<PaginatedResponse<DnsRecord>> {
        let params = params.validated(MAX_PAGE_SIZE);
        // Get domain name information to get the domain name (using cache)
        let domain_info = self.get_domain_cached(domain_id).await?;

        // Huawei Cloud uses offset/limit paging
        let offset = (params.page - 1) * params.page_size;
        let limit = params.page_size;
        let mut query = format!("offset={offset}&limit={limit}");

        // Add search keywords (Huawei Cloud supports name parameter fuzzy matching)
        if let Some(ref keyword) = params.keyword
            && !keyword.is_empty()
        {
            let _ = write!(query, "&name={}", urlencoding::encode(keyword));
        }

        // Add record type filter
        if let Some(ref record_type) = params.record_type {
            let type_str = record_type_to_string(record_type);
            let _ = write!(query, "&type={}", urlencoding::encode(type_str));
        }

        let path = format!("/v2/zones/{domain_id}/recordsets");
        let ctx = ErrorContext {
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };
        let response: ListRecordSetsResponse = self.get(&path, &query, ctx).await?;

        let total_count = response.metadata.and_then(|m| m.total_count).unwrap_or(0);

        let records = response
            .recordsets
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| {
                // Skip SOA and NS root records
                if r.record_type == "SOA" {
                    return None;
                }

                // TODO: Huawei Cloud recordset can contain multiple records (round-robin),
                // The current data model only supports single-value records, so only the first one is taken.
                let records = r.records.as_ref()?;
                if records.len() > 1 {
                    log::debug!(
                        "[huaweicloud] Record '{}' has {} values, only the first is used",
                        r.name,
                        records.len()
                    );
                }
                let value = records.first()?.clone();
                let data = match Self::parse_record_data(&r.record_type, value) {
                    Ok(data) => data,
                    Err(ProviderError::UnsupportedRecordType { .. }) => return None,
                    Err(e) => {
                        log::warn!("[huaweicloud] Skipping record due to parse error: {e}");
                        return None;
                    }
                };

                Some(DnsRecord {
                    id: r.id,
                    domain_id: domain_id.to_string(),
                    name: full_name_to_relative(&r.name, &domain_info.name),
                    ttl: r.ttl.unwrap_or(300),
                    data,
                    proxied: None,
                    created_at: r.created_at.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                    }),
                    updated_at: r.updated_at.and_then(|s| {
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

    async fn create_record(&self, req: &CreateDnsRecordRequest) -> Result<DnsRecord> {
        #[derive(Serialize)]
        struct CreateRecordSetRequest {
            name: String,
            #[serde(rename = "type")]
            record_type: String,
            records: Vec<String>,
            ttl: u32,
        }

        // Get domain name information (using cache)
        let domain_info = self.get_domain_cached(&req.domain_id).await?;

        // Construct a complete record name (Huawei Cloud requires a dot at the end)
        let full_name = format!("{}.", relative_to_full_name(&req.name, &domain_info.name));

        // Construct record value
        let record_value = Self::record_data_to_record_string(&req.data);
        let record_type = record_type_to_string(&req.data.record_type());

        let api_req = CreateRecordSetRequest {
            name: full_name,
            record_type: record_type.to_string(),
            records: vec![record_value],
            ttl: req.ttl,
        };

        let path = format!("/v2/zones/{}/recordsets", req.domain_id);
        let ctx = ErrorContext {
            record_name: Some(req.name.clone()),
            domain: Some(req.domain_id.clone()),
            ..Default::default()
        };
        let response: CreateRecordSetResponse = self.post(&path, &api_req, ctx).await?;

        let now = chrono::Utc::now();
        Ok(DnsRecord {
            id: response.id,
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
        struct UpdateRecordSetRequest {
            name: String,
            #[serde(rename = "type")]
            record_type: String,
            records: Vec<String>,
            ttl: u32,
        }

        // Get domain name information (using cache)
        let domain_info = self.get_domain_cached(&req.domain_id).await?;

        // Construct a complete record name (Huawei Cloud requires a dot at the end)
        let full_name = format!("{}.", relative_to_full_name(&req.name, &domain_info.name));

        // Construct record value
        let record_value = Self::record_data_to_record_string(&req.data);
        let record_type = record_type_to_string(&req.data.record_type());

        let api_req = UpdateRecordSetRequest {
            name: full_name,
            record_type: record_type.to_string(),
            records: vec![record_value],
            ttl: req.ttl,
        };

        let path = format!("/v2/zones/{}/recordsets/{}", req.domain_id, record_id);
        let ctx = ErrorContext {
            record_name: Some(req.name.clone()),
            record_id: Some(record_id.to_string()),
            domain: Some(req.domain_id.clone()),
        };
        let _response: CreateRecordSetResponse = self.put(&path, &api_req, ctx).await?;

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
        let path = format!("/v2/zones/{domain_id}/recordsets/{record_id}");
        let ctx = ErrorContext {
            record_id: Some(record_id.to_string()),
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };
        self.delete(&path, ctx).await
    }
}
