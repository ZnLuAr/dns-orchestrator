//! Cloudflare `DnsProvider` trait implementation

use std::fmt::Write;

use async_trait::async_trait;
use serde::Deserialize;

use crate::error::{ProviderError, Result};
use crate::providers::common::{full_name_to_relative, relative_to_full_name};
use crate::traits::{DnsProvider, ErrorContext, ProviderErrorMapper};
use crate::types::{
    CreateDnsRecordRequest, DnsRecord, DomainStatus, FieldType, PaginatedResponse,
    PaginationParams, ProviderCredentialField, ProviderDomain, ProviderFeatures, ProviderLimits,
    ProviderMetadata, ProviderType, RecordData, RecordQueryParams, UpdateDnsRecordRequest,
};

use super::{
    CloudflareCaaData, CloudflareDnsRecord, CloudflareProvider, CloudflareSrvData, CloudflareZone,
    MAX_PAGE_SIZE_RECORDS, MAX_PAGE_SIZE_ZONES,
};

impl CloudflareProvider {
    /// Get domain name information (use cache first)
    async fn get_domain_cached(&self, domain_id: &str) -> Result<ProviderDomain> {
        if let Some(domain) = self.domain_cache.get(domain_id) {
            return Ok(domain);
        }
        let domain = self.get_domain(domain_id).await?;
        self.domain_cache.insert(domain_id, &domain);
        Ok(domain)
    }

    /// Convert Cloudflare zone to `ProviderDomain`
    /// Cloudflare status: active, pending, initializing, moved
    pub(crate) fn zone_to_domain(zone: CloudflareZone) -> ProviderDomain {
        let status = match zone.status.as_str() {
            "active" => DomainStatus::Active,
            "pending" | "initializing" => DomainStatus::Pending,
            "moved" => DomainStatus::Paused,
            _ => DomainStatus::Unknown,
        };

        ProviderDomain {
            id: zone.id,
            name: zone.name,
            provider: ProviderType::Cloudflare,
            status,
            record_count: None,
        }
    }

    /// Convert Cloudflare records to `DnsRecord`
    pub(crate) fn cf_record_to_dns_record(
        &self,
        cf_record: CloudflareDnsRecord,
        zone_id: &str,
        zone_name: &str,
    ) -> Result<DnsRecord> {
        let CloudflareDnsRecord {
            id,
            record_type,
            name,
            content,
            ttl,
            priority,
            proxied,
            created_on,
            modified_on,
            data,
        } = cf_record;

        let record_data = self.parse_record_data(&record_type, content, priority, data)?;

        Ok(DnsRecord {
            id,
            domain_id: zone_id.to_string(),
            name: full_name_to_relative(&name, zone_name),
            ttl,
            data: record_data,
            proxied,
            created_at: created_on.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            }),
            updated_at: modified_on.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            }),
        })
    }

    /// Parse Cloudflare record as `RecordData`
    fn parse_record_data(
        &self,
        record_type: &str,
        content: String,
        priority: Option<u16>,
        data: Option<serde_json::Value>,
    ) -> Result<RecordData> {
        match record_type {
            "A" => Ok(RecordData::A { address: content }),
            "AAAA" => Ok(RecordData::AAAA { address: content }),
            "CNAME" => Ok(RecordData::CNAME { target: content }),
            "MX" => Ok(RecordData::MX {
                priority: priority
                    .ok_or_else(|| self.parse_error("MX record missing priority field"))?,
                exchange: content,
            }),
            "TXT" => Ok(RecordData::TXT { text: content }),
            "NS" => Ok(RecordData::NS {
                nameserver: content,
            }),
            "SRV" => {
                // SRV records use the data field
                if let Some(data) = data {
                    let srv: CloudflareSrvData = serde_json::from_value(data)
                        .map_err(|e| self.parse_error(format!("Failed to parse SRV data: {e}")))?;
                    Ok(RecordData::SRV {
                        priority: srv.priority,
                        weight: srv.weight,
                        port: srv.port,
                        target: srv.target,
                    })
                } else {
                    // Fallback: Try to parse from content
                    let parts: Vec<&str> = content.split_whitespace().collect();
                    if parts.len() >= 3 {
                        Ok(RecordData::SRV {
                            priority: priority.ok_or_else(|| {
                                self.parse_error("SRV record missing priority field")
                            })?,
                            weight: parts[0].parse().map_err(|_| {
                                self.parse_error(format!("Invalid SRV weight: '{}'", parts[0]))
                            })?,
                            port: parts[1].parse().map_err(|_| {
                                self.parse_error(format!("Invalid SRV port: '{}'", parts[1]))
                            })?,
                            target: parts[2].to_string(),
                        })
                    } else {
                        Err(self.parse_error(format!(
                            "Invalid SRV record format: expected 'weight port target', got '{content}'"
                        )))
                    }
                }
            }
            "CAA" => {
                // CAA records use the data field
                if let Some(data) = data {
                    let caa: CloudflareCaaData = serde_json::from_value(data)
                        .map_err(|e| self.parse_error(format!("Failed to parse CAA data: {e}")))?;
                    Ok(RecordData::CAA {
                        flags: caa.flags,
                        tag: caa.tag,
                        value: caa.value,
                    })
                } else {
                    // Fallback: Try to parse "flags tag value" from content
                    let parts: Vec<&str> = content.splitn(3, ' ').collect();
                    if parts.len() >= 3 {
                        Ok(RecordData::CAA {
                            flags: parts[0].parse().map_err(|_| {
                                self.parse_error(format!("Invalid CAA flags: '{}'", parts[0]))
                            })?,
                            tag: parts[1].to_string(),
                            value: parts[2].trim_matches('"').to_string(),
                        })
                    } else {
                        Err(self.parse_error(format!(
                            "Invalid CAA record format: expected 'flags tag value', got '{content}'"
                        )))
                    }
                }
            }
            _ => Err(ProviderError::UnsupportedRecordType {
                provider: self.provider_name().to_string(),
                record_type: record_type.to_string(),
            }),
        }
    }

    /// Convert `RecordData` to Cloudflare API request body
    fn build_create_body(
        full_name: &str,
        ttl: u32,
        data: &RecordData,
        proxied: Option<bool>,
    ) -> serde_json::Value {
        match data {
            RecordData::A { address } => serde_json::json!({
                "type": "A",
                "name": full_name,
                "content": address,
                "ttl": ttl,
                "proxied": proxied,
            }),
            RecordData::AAAA { address } => serde_json::json!({
                "type": "AAAA",
                "name": full_name,
                "content": address,
                "ttl": ttl,
                "proxied": proxied,
            }),
            RecordData::CNAME { target } => serde_json::json!({
                "type": "CNAME",
                "name": full_name,
                "content": target,
                "ttl": ttl,
                "proxied": proxied,
            }),
            RecordData::MX { priority, exchange } => serde_json::json!({
                "type": "MX",
                "name": full_name,
                "content": exchange,
                "ttl": ttl,
                "priority": priority,
            }),
            RecordData::TXT { text } => serde_json::json!({
                "type": "TXT",
                "name": full_name,
                "content": text,
                "ttl": ttl,
            }),
            RecordData::NS { nameserver } => serde_json::json!({
                "type": "NS",
                "name": full_name,
                "content": nameserver,
                "ttl": ttl,
            }),
            RecordData::SRV {
                priority,
                weight,
                port,
                target,
            } => serde_json::json!({
                "type": "SRV",
                "name": full_name,
                "ttl": ttl,
                "data": {
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": target,
                }
            }),
            RecordData::CAA { flags, tag, value } => serde_json::json!({
                "type": "CAA",
                "name": full_name,
                "ttl": ttl,
                "data": {
                    "flags": flags,
                    "tag": tag,
                    "value": value,
                }
            }),
        }
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    fn id(&self) -> &'static str {
        "cloudflare"
    }

    fn metadata() -> ProviderMetadata {
        ProviderMetadata {
            id: ProviderType::Cloudflare,
            name: "Cloudflare".to_string(),
            description: "Global CDN and DNS service provider".to_string(),
            required_fields: vec![ProviderCredentialField {
                key: "apiToken".to_string(),
                label: "API Token".to_string(),
                field_type: FieldType::Password,
                placeholder: Some("Enter Cloudflare API Token".to_string()),
                help_text: Some(
                    "Create at Cloudflare Dashboard -> My Profile -> API Tokens".to_string(),
                ),
            }],
            features: ProviderFeatures { proxy: true },
            limits: ProviderLimits {
                max_page_size_domains: 50,
                max_page_size_records: 5000,
            },
        }
    }

    async fn validate_credentials(&self) -> Result<bool> {
        #[derive(Deserialize)]
        struct VerifyResponse {
            status: String,
        }

        match self
            .get::<VerifyResponse>("/user/tokens/verify", ErrorContext::default())
            .await
        {
            Ok(resp) => Ok(resp.status == "active"),
            Err(
                ProviderError::InvalidCredentials { .. } | ProviderError::PermissionDenied { .. },
            ) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn list_domains(
        &self,
        params: &PaginationParams,
    ) -> Result<PaginatedResponse<ProviderDomain>> {
        let params = params.validated(MAX_PAGE_SIZE_ZONES);
        let (zones, total_count): (Vec<CloudflareZone>, u32) = self
            .get_paginated("/zones", &params, ErrorContext::default())
            .await?;
        let domains = zones.into_iter().map(Self::zone_to_domain).collect();
        Ok(PaginatedResponse::new(
            domains,
            params.page,
            params.page_size,
            total_count,
        ))
    }

    async fn get_domain(&self, domain_id: &str) -> Result<ProviderDomain> {
        let ctx = ErrorContext {
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };
        let zone: CloudflareZone = self.get(&format!("/zones/{domain_id}"), ctx).await?;
        Ok(Self::zone_to_domain(zone))
    }

    async fn list_records(
        &self,
        domain_id: &str,
        params: &RecordQueryParams,
    ) -> Result<PaginatedResponse<DnsRecord>> {
        let params = params.validated(MAX_PAGE_SIZE_RECORDS);
        let ctx = ErrorContext {
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };

        // Get zone information first to get domain name (use cache)
        let domain_info = self.get_domain_cached(domain_id).await?;
        let zone_name = domain_info.name;

        // Build query URL, including search parameters
        let mut url = format!(
            "/zones/{}/dns_records?page={}&per_page={}",
            domain_id,
            params.page,
            params.page_size.min(MAX_PAGE_SIZE_RECORDS)
        );

        // Add search keywords (only search record names)
        if let Some(ref keyword) = params.keyword
            && !keyword.is_empty()
        {
            let _ = write!(url, "&name.contains={}", urlencoding::encode(keyword));
        }

        // Add record type filter
        if let Some(ref record_type) = params.record_type {
            let type_str = crate::providers::common::record_type_to_string(record_type);
            let _ = write!(url, "&type={}", urlencoding::encode(type_str));
        }

        let (cf_records, total_count) = self.get_records(&url, ctx).await?;

        let records: Vec<DnsRecord> = cf_records
            .into_iter()
            .filter_map(
                |r| match self.cf_record_to_dns_record(r, domain_id, &zone_name) {
                    Ok(record) => Some(record),
                    Err(ProviderError::UnsupportedRecordType { .. }) => None,
                    Err(e) => {
                        log::warn!("[cloudflare] Skipping record due to parse error: {e}");
                        None
                    }
                },
            )
            .collect();

        Ok(PaginatedResponse::new(
            records,
            params.page,
            params.page_size,
            total_count,
        ))
    }

    async fn create_record(&self, req: &CreateDnsRecordRequest) -> Result<DnsRecord> {
        let ctx = ErrorContext {
            record_name: Some(req.name.clone()),
            domain: Some(req.domain_id.clone()),
            ..Default::default()
        };

        // Get zone information (using cache)
        let domain_info = self.get_domain_cached(&req.domain_id).await?;
        let zone_name = domain_info.name;

        let full_name = relative_to_full_name(&req.name, &zone_name);
        let body = Self::build_create_body(&full_name, req.ttl, &req.data, req.proxied);

        let cf_record: CloudflareDnsRecord = self
            .post_json(&format!("/zones/{}/dns_records", req.domain_id), body, ctx)
            .await?;

        self.cf_record_to_dns_record(cf_record, &req.domain_id, &zone_name)
    }

    async fn update_record(
        &self,
        record_id: &str,
        req: &UpdateDnsRecordRequest,
    ) -> Result<DnsRecord> {
        let ctx = ErrorContext {
            record_name: Some(req.name.clone()),
            record_id: Some(record_id.to_string()),
            domain: Some(req.domain_id.clone()),
        };

        // Get zone information (using cache)
        let domain_info = self.get_domain_cached(&req.domain_id).await?;
        let zone_name = domain_info.name;

        let full_name = relative_to_full_name(&req.name, &zone_name);
        let body = Self::build_create_body(&full_name, req.ttl, &req.data, req.proxied);

        let cf_record: CloudflareDnsRecord = self
            .patch_json(
                &format!("/zones/{}/dns_records/{}", req.domain_id, record_id),
                body,
                ctx,
            )
            .await?;

        self.cf_record_to_dns_record(cf_record, &req.domain_id, &zone_name)
    }

    async fn delete_record(&self, record_id: &str, domain_id: &str) -> Result<()> {
        let ctx = ErrorContext {
            record_id: Some(record_id.to_string()),
            domain: Some(domain_id.to_string()),
            ..Default::default()
        };
        self.delete(&format!("/zones/{domain_id}/dns_records/{record_id}"), ctx)
            .await
    }
}
