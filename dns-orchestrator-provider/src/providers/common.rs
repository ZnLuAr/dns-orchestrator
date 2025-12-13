//! Provider 公共工具函数

use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;

use crate::error::{ProviderError, Result};
use crate::types::DnsRecordType;

type HmacSha256 = Hmac<Sha256>;

// ============ HTTP Client ============

/// 默认连接超时（秒）
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// 默认请求超时（秒）
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// 创建带超时配置的 HTTP Client
pub fn create_http_client() -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS))
        .build()
        .expect("Failed to create HTTP client")
}

// ============ 记录类型转换 ============

/// 将字符串转换为 `DnsRecordType`
pub fn parse_record_type(record_type: &str, provider: &str) -> Result<DnsRecordType> {
    match record_type.to_uppercase().as_str() {
        "A" => Ok(DnsRecordType::A),
        "AAAA" => Ok(DnsRecordType::Aaaa),
        "CNAME" => Ok(DnsRecordType::Cname),
        "MX" => Ok(DnsRecordType::Mx),
        "TXT" => Ok(DnsRecordType::Txt),
        "NS" => Ok(DnsRecordType::Ns),
        "SRV" => Ok(DnsRecordType::Srv),
        "CAA" => Ok(DnsRecordType::Caa),
        _ => Err(ProviderError::InvalidParameter {
            provider: provider.to_string(),
            param: "record_type".to_string(),
            detail: format!("不支持的记录类型: {record_type}"),
        }),
    }
}

/// 将 `DnsRecordType` 转换为大写字符串
pub fn record_type_to_string(record_type: &DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "A",
        DnsRecordType::Aaaa => "AAAA",
        DnsRecordType::Cname => "CNAME",
        DnsRecordType::Mx => "MX",
        DnsRecordType::Txt => "TXT",
        DnsRecordType::Ns => "NS",
        DnsRecordType::Srv => "SRV",
        DnsRecordType::Caa => "CAA",
    }
}

// ============ HMAC-SHA256 ============

/// HMAC-SHA256 计算（供 aliyun/dnspod/huaweicloud 使用）
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// ============ 域名名称处理 ============

/// 去掉域名末尾的点
pub fn normalize_domain_name(name: &str) -> String {
    name.trim_end_matches('.').to_string()
}

/// 将完整域名转换为相对名称
/// 如: "www.example.com" + "example.com" -> "www"
/// 如: "example.com" + "example.com" -> "@"
pub fn full_name_to_relative(full_name: &str, zone_name: &str) -> String {
    let full = normalize_domain_name(full_name);
    let zone = normalize_domain_name(zone_name);

    if full == zone {
        "@".to_string()
    } else if let Some(subdomain) = full.strip_suffix(&format!(".{zone}")) {
        subdomain.to_string()
    } else {
        full
    }
}

/// 将相对名称转换为完整域名
/// 如: "www" + "example.com" -> "www.example.com"
/// 如: "@" + "example.com" -> "example.com"
pub fn relative_to_full_name(relative_name: &str, zone_name: &str) -> String {
    let zone = normalize_domain_name(zone_name);

    if relative_name == "@" || relative_name.is_empty() {
        zone
    } else {
        format!("{relative_name}.{zone}")
    }
}
