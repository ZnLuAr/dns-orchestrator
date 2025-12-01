use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::DnsProvider;
use crate::error::{DnsError, Result};
use crate::types::{
    CreateDnsRecordRequest, DnsRecord, DnsRecordType, Domain, DomainStatus, UpdateDnsRecordRequest,
};

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare API 通用响应
#[derive(Debug, Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    result: Option<T>,
    errors: Option<Vec<CloudflareError>>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: i32,
    message: String,
}

/// Cloudflare Zone 结构
#[derive(Debug, Deserialize)]
struct CloudflareZone {
    id: String,
    name: String,
    status: String,
}

/// Cloudflare DNS Record 结构
#[derive(Debug, Deserialize, Serialize)]
struct CloudflareDnsRecord {
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_on: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_on: Option<String>,
}

/// Cloudflare DNS Provider
pub struct CloudflareProvider {
    client: Client,
    api_token: String,
    account_id: String,
}

impl CloudflareProvider {
    pub fn new(credentials: HashMap<String, String>) -> Self {
        let api_token = credentials
            .get("apiToken")
            .cloned()
            .unwrap_or_default();

        let account_id = uuid::Uuid::new_v4().to_string();

        Self {
            client: Client::new(),
            api_token,
            account_id,
        }
    }

    pub fn with_account_id(credentials: HashMap<String, String>, account_id: String) -> Self {
        let api_token = credentials
            .get("apiToken")
            .cloned()
            .unwrap_or_default();

        Self {
            client: Client::new(),
            api_token,
            account_id,
        }
    }

    /// 执行 GET 请求
    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", CF_API_BASE, path);
        log::debug!("GET {}", url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| DnsError::ApiError(format!("请求失败: {}", e)))?;

        let status = response.status();
        log::debug!("Response Status: {}", status);

        let response_text = response
            .text()
            .await
            .map_err(|e| DnsError::ApiError(format!("读取响应失败: {}", e)))?;

        log::debug!("Response Body: {}", response_text);

        let cf_response: CloudflareResponse<T> = serde_json::from_str(&response_text)
            .map_err(|e| {
                log::error!("JSON 解析失败: {}", e);
                log::error!("原始响应: {}", response_text);
                DnsError::ApiError(format!("解析响应失败: {}", e))
            })?;

        if !cf_response.success {
            let error_msg = cf_response
                .errors
                .and_then(|errors| errors.first().map(|e| e.message.clone()))
                .unwrap_or_else(|| "未知错误".to_string());
            log::error!("API 错误: {}", error_msg);
            return Err(DnsError::ApiError(error_msg));
        }

        cf_response
            .result
            .ok_or_else(|| DnsError::ApiError("响应中缺少 result 字段".to_string()))
    }

    /// 执行 POST 请求
    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = format!("{}{}", CF_API_BASE, path);
        let body_json = serde_json::to_string_pretty(body)
            .unwrap_or_else(|_| "无法序列化请求体".to_string());
        log::debug!("POST {}", url);
        log::debug!("Request Body: {}", body_json);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(body)
            .send()
            .await
            .map_err(|e| DnsError::ApiError(format!("请求失败: {}", e)))?;

        let status = response.status();
        log::debug!("Response Status: {}", status);

        let response_text = response
            .text()
            .await
            .map_err(|e| DnsError::ApiError(format!("读取响应失败: {}", e)))?;

        log::debug!("Response Body: {}", response_text);

        let cf_response: CloudflareResponse<T> = serde_json::from_str(&response_text)
            .map_err(|e| {
                log::error!("JSON 解析失败: {}", e);
                log::error!("原始响应: {}", response_text);
                DnsError::ApiError(format!("解析响应失败: {}", e))
            })?;

        if !cf_response.success {
            let error_msg = cf_response
                .errors
                .and_then(|errors| errors.first().map(|e| e.message.clone()))
                .unwrap_or_else(|| "未知错误".to_string());
            log::error!("API 错误: {}", error_msg);
            return Err(DnsError::ApiError(error_msg));
        }

        cf_response
            .result
            .ok_or_else(|| DnsError::ApiError("响应中缺少 result 字段".to_string()))
    }

    /// 执行 PATCH 请求
    async fn patch<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = format!("{}{}", CF_API_BASE, path);
        let body_json = serde_json::to_string_pretty(body)
            .unwrap_or_else(|_| "无法序列化请求体".to_string());
        log::debug!("PATCH {}", url);
        log::debug!("Request Body: {}", body_json);

        let response = self
            .client
            .patch(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(body)
            .send()
            .await
            .map_err(|e| DnsError::ApiError(format!("请求失败: {}", e)))?;

        let status = response.status();
        log::debug!("Response Status: {}", status);

        let response_text = response
            .text()
            .await
            .map_err(|e| DnsError::ApiError(format!("读取响应失败: {}", e)))?;

        log::debug!("Response Body: {}", response_text);

        let cf_response: CloudflareResponse<T> = serde_json::from_str(&response_text)
            .map_err(|e| {
                log::error!("JSON 解析失败: {}", e);
                log::error!("原始响应: {}", response_text);
                DnsError::ApiError(format!("解析响应失败: {}", e))
            })?;

        if !cf_response.success {
            let error_msg = cf_response
                .errors
                .and_then(|errors| errors.first().map(|e| e.message.clone()))
                .unwrap_or_else(|| "未知错误".to_string());
            log::error!("API 错误: {}", error_msg);
            return Err(DnsError::ApiError(error_msg));
        }

        cf_response
            .result
            .ok_or_else(|| DnsError::ApiError("响应中缺少 result 字段".to_string()))
    }

    /// 执行 DELETE 请求
    async fn delete(&self, path: &str) -> Result<()> {
        let url = format!("{}{}", CF_API_BASE, path);
        log::debug!("DELETE {}", url);

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| DnsError::ApiError(format!("请求失败: {}", e)))?;

        let status = response.status();
        log::debug!("Response Status: {}", status);

        let response_text = response
            .text()
            .await
            .map_err(|e| DnsError::ApiError(format!("读取响应失败: {}", e)))?;

        log::debug!("Response Body: {}", response_text);

        let cf_response: CloudflareResponse<serde_json::Value> = serde_json::from_str(&response_text)
            .map_err(|e| {
                log::error!("JSON 解析失败: {}", e);
                log::error!("原始响应: {}", response_text);
                DnsError::ApiError(format!("解析响应失败: {}", e))
            })?;

        if !cf_response.success {
            let error_msg = cf_response
                .errors
                .and_then(|errors| errors.first().map(|e| e.message.clone()))
                .unwrap_or_else(|| "未知错误".to_string());
            log::error!("API 错误: {}", error_msg);
            return Err(DnsError::ApiError(error_msg));
        }

        Ok(())
    }

    /// 将 Cloudflare zone 转换为 Domain
    fn zone_to_domain(&self, zone: CloudflareZone) -> Domain {
        let status = match zone.status.as_str() {
            "active" => DomainStatus::Active,
            "pending" => DomainStatus::Pending,
            _ => DomainStatus::Error,
        };

        Domain {
            id: zone.id,
            name: zone.name,
            account_id: self.account_id.clone(),
            provider: crate::types::DnsProvider::Cloudflare,
            status,
            record_count: None,
        }
    }

    /// 将完整域名转换为相对名称 (用于显示)
    /// 如: "www.example.com" + "example.com" -> "www"
    /// 如: "example.com" + "example.com" -> "@"
    fn full_name_to_relative(&self, full_name: &str, zone_name: &str) -> String {
        if full_name == zone_name {
            "@".to_string()
        } else if let Some(subdomain) = full_name.strip_suffix(&format!(".{}", zone_name)) {
            subdomain.to_string()
        } else {
            full_name.to_string()
        }
    }

    /// 将相对名称转换为完整域名 (用于 API 调用)
    /// 如: "www" + "example.com" -> "www.example.com"
    /// 如: "@" + "example.com" -> "example.com"
    fn relative_to_full_name(&self, relative_name: &str, zone_name: &str) -> String {
        if relative_name == "@" || relative_name.is_empty() {
            zone_name.to_string()
        } else {
            format!("{}.{}", relative_name, zone_name)
        }
    }

    /// 将 Cloudflare 记录转换为 DnsRecord
    fn cf_record_to_dns_record(&self, cf_record: CloudflareDnsRecord, zone_id: &str, zone_name: &str) -> Result<DnsRecord> {
        let record_type = match cf_record.record_type.as_str() {
            "A" => DnsRecordType::A,
            "AAAA" => DnsRecordType::Aaaa,
            "CNAME" => DnsRecordType::Cname,
            "MX" => DnsRecordType::Mx,
            "TXT" => DnsRecordType::Txt,
            "NS" => DnsRecordType::Ns,
            "SRV" => DnsRecordType::Srv,
            "CAA" => DnsRecordType::Caa,
            _ => return Err(DnsError::ApiError(format!("不支持的记录类型: {}", cf_record.record_type))),
        };

        Ok(DnsRecord {
            id: cf_record.id,
            domain_id: zone_id.to_string(),
            record_type,
            name: self.full_name_to_relative(&cf_record.name, zone_name),
            value: cf_record.content,
            ttl: cf_record.ttl,
            priority: cf_record.priority,
            proxied: cf_record.proxied,
            created_at: cf_record.created_on,
            updated_at: cf_record.modified_on,
        })
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    fn id(&self) -> &'static str {
        "cloudflare"
    }

    async fn validate_credentials(&self) -> Result<bool> {
        #[derive(Deserialize)]
        struct VerifyResponse {
            status: String,
        }

        match self.get::<VerifyResponse>("/user/tokens/verify").await {
            Ok(resp) => Ok(resp.status == "active"),
            Err(_) => Ok(false),
        }
    }

    async fn list_domains(&self) -> Result<Vec<Domain>> {
        let zones: Vec<CloudflareZone> = self.get("/zones").await?;
        Ok(zones.into_iter().map(|z| self.zone_to_domain(z)).collect())
    }

    async fn get_domain(&self, domain_id: &str) -> Result<Domain> {
        let zone: CloudflareZone = self.get(&format!("/zones/{}", domain_id)).await?;
        Ok(self.zone_to_domain(zone))
    }

    async fn list_records(&self, domain_id: &str) -> Result<Vec<DnsRecord>> {
        // 先获取 zone 信息以获取域名
        let zone: CloudflareZone = self.get(&format!("/zones/{}", domain_id)).await?;
        let zone_name = zone.name;

        let cf_records: Vec<CloudflareDnsRecord> =
            self.get(&format!("/zones/{}/dns_records", domain_id)).await?;

        cf_records
            .into_iter()
            .map(|r| self.cf_record_to_dns_record(r, domain_id, &zone_name))
            .collect()
    }

    async fn create_record(&self, req: &CreateDnsRecordRequest) -> Result<DnsRecord> {
        // 先获取 zone 信息
        let zone: CloudflareZone = self.get(&format!("/zones/{}", req.domain_id)).await?;
        let zone_name = zone.name;

        let full_name = self.relative_to_full_name(&req.name, &zone_name);

        #[derive(Serialize)]
        struct CreateRecordBody {
            #[serde(rename = "type")]
            record_type: String,
            name: String,
            content: String,
            ttl: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            priority: Option<u16>,
            #[serde(skip_serializing_if = "Option::is_none")]
            proxied: Option<bool>,
        }

        let body = CreateRecordBody {
            record_type: format!("{:?}", req.record_type).to_uppercase(),
            name: full_name,
            content: req.value.clone(),
            ttl: req.ttl,
            priority: req.priority,
            proxied: req.proxied,
        };

        let cf_record: CloudflareDnsRecord = self
            .post(&format!("/zones/{}/dns_records", req.domain_id), &body)
            .await?;

        self.cf_record_to_dns_record(cf_record, &req.domain_id, &zone_name)
    }

    async fn update_record(&self, record_id: &str, req: &UpdateDnsRecordRequest) -> Result<DnsRecord> {
        // 先获取 zone 信息
        let zone: CloudflareZone = self.get(&format!("/zones/{}", req.domain_id)).await?;
        let zone_name = zone.name;

        let full_name = self.relative_to_full_name(&req.name, &zone_name);

        #[derive(Serialize)]
        struct UpdateRecordBody {
            #[serde(rename = "type")]
            record_type: String,
            name: String,
            content: String,
            ttl: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            priority: Option<u16>,
            #[serde(skip_serializing_if = "Option::is_none")]
            proxied: Option<bool>,
        }

        let body = UpdateRecordBody {
            record_type: format!("{:?}", req.record_type).to_uppercase(),
            name: full_name,
            content: req.value.clone(),
            ttl: req.ttl,
            priority: req.priority,
            proxied: req.proxied,
        };

        let cf_record: CloudflareDnsRecord = self
            .patch(&format!("/zones/{}/dns_records/{}", req.domain_id, record_id), &body)
            .await?;

        self.cf_record_to_dns_record(cf_record, &req.domain_id, &zone_name)
    }

    async fn delete_record(&self, record_id: &str, domain_id: &str) -> Result<()> {
        self.delete(&format!("/zones/{}/dns_records/{}", domain_id, record_id)).await
    }
}
