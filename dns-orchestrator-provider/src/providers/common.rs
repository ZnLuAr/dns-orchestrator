//! Provider 公共工具函数

use std::sync::OnceLock;
use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;

use crate::error::{ProviderError, Result};
use crate::types::{DnsRecordType, RecordData};

type HmacSha256 = Hmac<Sha256>;

// ============ HTTP Client ============

/// 默认连接超时（秒）
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// 默认请求超时（秒）
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// 全局共享的 HTTP Client
static SHARED_HTTP_CLIENT: OnceLock<Client> = OnceLock::new();

/// 获取共享的 HTTP Client（懒初始化，线程安全）
pub fn create_http_client() -> Client {
    SHARED_HTTP_CLIENT
        .get_or_init(|| {
            // Client::builder() only fails if TLS backend cannot initialize,
            // which is a fatal configuration error — silently falling back
            // to a default client with no timeouts would be worse.
            #[allow(clippy::expect_used)]
            Client::builder()
                .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
                .timeout(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS))
                .build()
                .expect("Failed to create HTTP client: TLS backend unavailable")
        })
        .clone()
}

// ============ 记录类型转换 ============

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
    // HMAC-SHA256 accepts keys of any size, so new_from_slice never fails
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any size");
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

// ============ 共享记录解析函数 ============

/// 从字符串解析 SRV 记录数据
///
/// 格式: `"priority weight port target"`
/// Aliyun、DNSPod、Huaweicloud 均使用此格式。
pub fn parse_srv_from_string(value: &str, provider: &str) -> Result<RecordData> {
    let parts: Vec<&str> = value.splitn(4, ' ').collect();
    if parts.len() == 4 {
        Ok(RecordData::SRV {
            priority: parts[0].parse().map_err(|_| ProviderError::ParseError {
                provider: provider.to_string(),
                detail: format!("Invalid SRV priority: '{}'", parts[0]),
            })?,
            weight: parts[1].parse().map_err(|_| ProviderError::ParseError {
                provider: provider.to_string(),
                detail: format!("Invalid SRV weight: '{}'", parts[1]),
            })?,
            port: parts[2].parse().map_err(|_| ProviderError::ParseError {
                provider: provider.to_string(),
                detail: format!("Invalid SRV port: '{}'", parts[2]),
            })?,
            target: parts[3].to_string(),
        })
    } else {
        Err(ProviderError::ParseError {
            provider: provider.to_string(),
            detail: format!(
                "Invalid SRV record format: expected 'priority weight port target', got '{value}'"
            ),
        })
    }
}

/// 从字符串解析 CAA 记录数据
///
/// 格式: `"flags tag value"`（value 可带引号）
/// Aliyun、DNSPod、Huaweicloud 均使用此格式。
pub fn parse_caa_from_string(value: &str, provider: &str) -> Result<RecordData> {
    let parts: Vec<&str> = value.splitn(3, ' ').collect();
    if parts.len() >= 3 {
        Ok(RecordData::CAA {
            flags: parts[0].parse().map_err(|_| ProviderError::ParseError {
                provider: provider.to_string(),
                detail: format!("Invalid CAA flags: '{}'", parts[0]),
            })?,
            tag: parts[1].to_string(),
            value: parts[2].trim_matches('"').to_string(),
        })
    } else {
        Err(ProviderError::ParseError {
            provider: provider.to_string(),
            detail: format!("Invalid CAA record format: expected 'flags tag value', got '{value}'"),
        })
    }
}

/// 从字符串解析 MX 记录数据（华为云格式）
///
/// 格式: `"priority exchange"`
/// 华为云将 priority 和 exchange 都编码在同一个字符串中。
pub fn parse_mx_from_string(value: &str, provider: &str) -> Result<RecordData> {
    let parts: Vec<&str> = value.splitn(2, ' ').collect();
    if parts.len() == 2 {
        Ok(RecordData::MX {
            priority: parts[0].parse().map_err(|_| ProviderError::ParseError {
                provider: provider.to_string(),
                detail: format!("Invalid MX priority: '{}'", parts[0]),
            })?,
            exchange: parts[1].to_string(),
        })
    } else {
        Err(ProviderError::ParseError {
            provider: provider.to_string(),
            detail: format!(
                "Invalid MX record format: expected 'priority exchange', got '{value}'"
            ),
        })
    }
}

/// 从 type/value/priority 解析记录数据（Aliyun/DNSPod 格式）
///
/// MX 使用独立的 priority 参数，SRV/CAA 从 value 字符串解析。
pub fn parse_record_data_with_priority(
    record_type: &str,
    value: &str,
    priority: Option<u16>,
    provider: &str,
) -> Result<RecordData> {
    match record_type {
        "A" => Ok(RecordData::A {
            address: value.to_string(),
        }),
        "AAAA" => Ok(RecordData::AAAA {
            address: value.to_string(),
        }),
        "CNAME" => Ok(RecordData::CNAME {
            target: value.to_string(),
        }),
        "MX" => Ok(RecordData::MX {
            priority: priority.ok_or_else(|| ProviderError::ParseError {
                provider: provider.to_string(),
                detail: "MX record missing priority field".to_string(),
            })?,
            exchange: value.to_string(),
        }),
        "TXT" => Ok(RecordData::TXT {
            text: value.to_string(),
        }),
        "NS" => Ok(RecordData::NS {
            nameserver: value.to_string(),
        }),
        "SRV" => parse_srv_from_string(value, provider),
        "CAA" => parse_caa_from_string(value, provider),
        _ => Err(ProviderError::UnsupportedRecordType {
            provider: provider.to_string(),
            record_type: record_type.to_string(),
        }),
    }
}

/// 从 type/record 字符串解析记录数据（华为云格式）
///
/// MX priority 从 record 字符串解析（`"priority exchange"` 格式），
/// SRV/CAA 同样从字符串解析。
pub fn parse_record_data_from_string(
    record_type: &str,
    record: &str,
    provider: &str,
) -> Result<RecordData> {
    match record_type {
        "A" => Ok(RecordData::A {
            address: record.to_string(),
        }),
        "AAAA" => Ok(RecordData::AAAA {
            address: record.to_string(),
        }),
        "CNAME" => Ok(RecordData::CNAME {
            target: record.to_string(),
        }),
        "MX" => parse_mx_from_string(record, provider),
        "TXT" => Ok(RecordData::TXT {
            text: record.to_string(),
        }),
        "NS" => Ok(RecordData::NS {
            nameserver: record.to_string(),
        }),
        "SRV" => parse_srv_from_string(record, provider),
        "CAA" => parse_caa_from_string(record, provider),
        _ => Err(ProviderError::UnsupportedRecordType {
            provider: provider.to_string(),
            record_type: record_type.to_string(),
        }),
    }
}

/// 将 `RecordData` 转换为 (value, priority) 格式
///
/// Aliyun 和 `DNSPod` 使用此格式：主值在 value 字段，MX priority 在独立字段。
pub fn record_data_to_value_priority(data: &RecordData) -> (String, Option<u16>) {
    match data {
        RecordData::A { address } | RecordData::AAAA { address } => (address.clone(), None),
        RecordData::CNAME { target } => (target.clone(), None),
        RecordData::MX { priority, exchange } => (exchange.clone(), Some(*priority)),
        RecordData::TXT { text } => (text.clone(), None),
        RecordData::NS { nameserver } => (nameserver.clone(), None),
        RecordData::SRV {
            priority,
            weight,
            port,
            target,
        } => (format!("{priority} {weight} {port} {target}"), None),
        RecordData::CAA { flags, tag, value } => (format!("{flags} {tag} \"{value}\""), None),
    }
}

/// 将 `RecordData` 转换为单个字符串
///
/// 华为云格式：所有字段都编码在一个 records 字符串中。
pub fn record_data_to_single_string(data: &RecordData) -> String {
    match data {
        RecordData::A { address } | RecordData::AAAA { address } => address.clone(),
        RecordData::CNAME { target } => target.clone(),
        RecordData::MX { priority, exchange } => format!("{priority} {exchange}"),
        RecordData::TXT { text } => text.clone(),
        RecordData::NS { nameserver } => nameserver.clone(),
        RecordData::SRV {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        RecordData::CAA { flags, tag, value } => format!("{flags} {tag} \"{value}\""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============ SRV 解析测试 ============

    #[test]
    fn parse_srv_valid() {
        let result = parse_srv_from_string("10 20 443 example.com", "test").unwrap();
        assert_eq!(
            result,
            RecordData::SRV {
                priority: 10,
                weight: 20,
                port: 443,
                target: "example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_srv_zero_values() {
        let result = parse_srv_from_string("0 0 0 .", "test").unwrap();
        assert_eq!(
            result,
            RecordData::SRV {
                priority: 0,
                weight: 0,
                port: 0,
                target: ".".to_string(),
            }
        );
    }

    #[test]
    fn parse_srv_max_values() {
        let result = parse_srv_from_string("65535 65535 65535 target.example.com", "test").unwrap();
        assert_eq!(
            result,
            RecordData::SRV {
                priority: 65535,
                weight: 65535,
                port: 65535,
                target: "target.example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_srv_target_with_spaces() {
        // splitn(4, ' ') 意味着第 4 部分包含剩余内容
        let result = parse_srv_from_string("10 20 80 target with spaces", "test").unwrap();
        assert_eq!(
            result,
            RecordData::SRV {
                priority: 10,
                weight: 20,
                port: 80,
                target: "target with spaces".to_string(),
            }
        );
    }

    #[test]
    fn parse_srv_too_few_parts() {
        let err = parse_srv_from_string("10 20", "aliyun").unwrap_err();
        assert!(matches!(err, ProviderError::ParseError { provider, .. } if provider == "aliyun"));
    }

    #[test]
    fn parse_srv_invalid_priority() {
        let err = parse_srv_from_string("abc 20 443 target", "test").unwrap_err();
        assert!(
            matches!(err, ProviderError::ParseError { detail, .. } if detail.contains("priority"))
        );
    }

    #[test]
    fn parse_srv_invalid_weight() {
        let err = parse_srv_from_string("10 abc 443 target", "test").unwrap_err();
        assert!(
            matches!(err, ProviderError::ParseError { detail, .. } if detail.contains("weight"))
        );
    }

    #[test]
    fn parse_srv_invalid_port() {
        let err = parse_srv_from_string("10 20 abc target", "test").unwrap_err();
        assert!(matches!(err, ProviderError::ParseError { detail, .. } if detail.contains("port")));
    }

    #[test]
    fn parse_srv_overflow_port() {
        let err = parse_srv_from_string("10 20 99999 target", "test").unwrap_err();
        assert!(matches!(err, ProviderError::ParseError { detail, .. } if detail.contains("port")));
    }

    // ============ CAA 解析测试 ============

    #[test]
    fn parse_caa_valid_quoted() {
        let result = parse_caa_from_string(r#"0 issue "letsencrypt.org""#, "test").unwrap();
        assert_eq!(
            result,
            RecordData::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string(),
            }
        );
    }

    #[test]
    fn parse_caa_valid_unquoted() {
        let result = parse_caa_from_string("0 issue letsencrypt.org", "test").unwrap();
        assert_eq!(
            result,
            RecordData::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string(),
            }
        );
    }

    #[test]
    fn parse_caa_critical_flag() {
        let result = parse_caa_from_string(r#"128 issuewild "*.example.com""#, "test").unwrap();
        assert_eq!(
            result,
            RecordData::CAA {
                flags: 128,
                tag: "issuewild".to_string(),
                value: "*.example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_caa_iodef_with_url() {
        let result =
            parse_caa_from_string(r#"0 iodef "mailto:admin@example.com""#, "test").unwrap();
        assert_eq!(
            result,
            RecordData::CAA {
                flags: 0,
                tag: "iodef".to_string(),
                value: "mailto:admin@example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_caa_too_few_parts() {
        let err = parse_caa_from_string("0 issue", "dnspod").unwrap_err();
        assert!(matches!(err, ProviderError::ParseError { provider, .. } if provider == "dnspod"));
    }

    #[test]
    fn parse_caa_invalid_flags() {
        let err = parse_caa_from_string("abc issue letsencrypt.org", "test").unwrap_err();
        assert!(
            matches!(err, ProviderError::ParseError { detail, .. } if detail.contains("flags"))
        );
    }

    // ============ MX 解析测试 ============

    #[test]
    fn parse_mx_valid() {
        let result = parse_mx_from_string("10 mail.example.com", "huaweicloud").unwrap();
        assert_eq!(
            result,
            RecordData::MX {
                priority: 10,
                exchange: "mail.example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_mx_zero_priority() {
        let result = parse_mx_from_string("0 mx.example.com", "test").unwrap();
        assert_eq!(
            result,
            RecordData::MX {
                priority: 0,
                exchange: "mx.example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_mx_missing_exchange() {
        let err = parse_mx_from_string("10", "test").unwrap_err();
        assert!(matches!(err, ProviderError::ParseError { .. }));
    }

    #[test]
    fn parse_mx_invalid_priority() {
        let err = parse_mx_from_string("abc mail.example.com", "test").unwrap_err();
        assert!(
            matches!(err, ProviderError::ParseError { detail, .. } if detail.contains("priority"))
        );
    }

    // ============ record_data_to_value_priority 测试 ============

    #[test]
    fn value_priority_a_record() {
        let data = RecordData::A {
            address: "1.2.3.4".to_string(),
        };
        assert_eq!(
            record_data_to_value_priority(&data),
            ("1.2.3.4".to_string(), None)
        );
    }

    #[test]
    fn value_priority_mx_record() {
        let data = RecordData::MX {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        };
        assert_eq!(
            record_data_to_value_priority(&data),
            ("mail.example.com".to_string(), Some(10))
        );
    }

    #[test]
    fn value_priority_srv_record() {
        let data = RecordData::SRV {
            priority: 10,
            weight: 20,
            port: 443,
            target: "srv.example.com".to_string(),
        };
        let (value, priority) = record_data_to_value_priority(&data);
        assert_eq!(value, "10 20 443 srv.example.com");
        assert_eq!(priority, None);
    }

    #[test]
    fn value_priority_caa_record() {
        let data = RecordData::CAA {
            flags: 0,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
        };
        let (value, priority) = record_data_to_value_priority(&data);
        assert_eq!(value, r#"0 issue "letsencrypt.org""#);
        assert_eq!(priority, None);
    }

    // ============ record_data_to_single_string 测试 ============

    #[test]
    fn single_string_a_record() {
        let data = RecordData::A {
            address: "1.2.3.4".to_string(),
        };
        assert_eq!(record_data_to_single_string(&data), "1.2.3.4");
    }

    #[test]
    fn single_string_mx_record() {
        let data = RecordData::MX {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        };
        assert_eq!(record_data_to_single_string(&data), "10 mail.example.com");
    }

    #[test]
    fn single_string_srv_record() {
        let data = RecordData::SRV {
            priority: 10,
            weight: 20,
            port: 443,
            target: "srv.example.com".to_string(),
        };
        assert_eq!(
            record_data_to_single_string(&data),
            "10 20 443 srv.example.com"
        );
    }

    // ============ SRV/CAA 往返测试 ============

    #[test]
    fn srv_roundtrip_value_priority() {
        let original = RecordData::SRV {
            priority: 10,
            weight: 60,
            port: 5060,
            target: "sip.example.com".to_string(),
        };
        let (value, _) = record_data_to_value_priority(&original);
        let parsed = parse_srv_from_string(&value, "test").unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn srv_roundtrip_single_string() {
        let original = RecordData::SRV {
            priority: 10,
            weight: 60,
            port: 5060,
            target: "sip.example.com".to_string(),
        };
        let s = record_data_to_single_string(&original);
        let parsed = parse_srv_from_string(&s, "test").unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn caa_roundtrip() {
        let original = RecordData::CAA {
            flags: 0,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
        };
        let (value, _) = record_data_to_value_priority(&original);
        let parsed = parse_caa_from_string(&value, "test").unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn mx_roundtrip() {
        let original = RecordData::MX {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        };
        let s = record_data_to_single_string(&original);
        let parsed = parse_mx_from_string(&s, "test").unwrap();
        assert_eq!(parsed, original);
    }

    // ============ 域名辅助函数测试 ============

    #[test]
    fn normalize_removes_trailing_dot() {
        assert_eq!(normalize_domain_name("example.com."), "example.com");
    }

    #[test]
    fn normalize_no_trailing_dot() {
        assert_eq!(normalize_domain_name("example.com"), "example.com");
    }

    #[test]
    fn normalize_multiple_trailing_dots() {
        assert_eq!(normalize_domain_name("example.com..."), "example.com");
    }

    #[test]
    fn full_to_relative_subdomain() {
        assert_eq!(
            full_name_to_relative("www.example.com", "example.com"),
            "www"
        );
    }

    #[test]
    fn full_to_relative_apex() {
        assert_eq!(full_name_to_relative("example.com", "example.com"), "@");
    }

    #[test]
    fn full_to_relative_deep_subdomain() {
        assert_eq!(
            full_name_to_relative("a.b.c.example.com", "example.com"),
            "a.b.c"
        );
    }

    #[test]
    fn full_to_relative_with_trailing_dots() {
        assert_eq!(
            full_name_to_relative("www.example.com.", "example.com."),
            "www"
        );
    }

    #[test]
    fn full_to_relative_unrelated_domain() {
        // 不属于该 zone，返回 full name
        assert_eq!(
            full_name_to_relative("www.other.com", "example.com"),
            "www.other.com"
        );
    }

    #[test]
    fn relative_to_full_subdomain() {
        assert_eq!(
            relative_to_full_name("www", "example.com"),
            "www.example.com"
        );
    }

    #[test]
    fn relative_to_full_apex_at() {
        assert_eq!(relative_to_full_name("@", "example.com"), "example.com");
    }

    #[test]
    fn relative_to_full_apex_empty() {
        assert_eq!(relative_to_full_name("", "example.com"), "example.com");
    }

    #[test]
    fn relative_to_full_strips_trailing_dot() {
        assert_eq!(
            relative_to_full_name("www", "example.com."),
            "www.example.com"
        );
    }

    // ============ record_type_to_string 测试 ============

    #[test]
    fn record_type_all_variants() {
        assert_eq!(record_type_to_string(&DnsRecordType::A), "A");
        assert_eq!(record_type_to_string(&DnsRecordType::Aaaa), "AAAA");
        assert_eq!(record_type_to_string(&DnsRecordType::Cname), "CNAME");
        assert_eq!(record_type_to_string(&DnsRecordType::Mx), "MX");
        assert_eq!(record_type_to_string(&DnsRecordType::Txt), "TXT");
        assert_eq!(record_type_to_string(&DnsRecordType::Ns), "NS");
        assert_eq!(record_type_to_string(&DnsRecordType::Srv), "SRV");
        assert_eq!(record_type_to_string(&DnsRecordType::Caa), "CAA");
    }

    // ============ parse_record_data_with_priority 测试 ============

    #[test]
    fn with_priority_all_simple_types() {
        // A
        assert_eq!(
            parse_record_data_with_priority("A", "1.2.3.4", None, "test").unwrap(),
            RecordData::A {
                address: "1.2.3.4".to_string()
            }
        );
        // AAAA
        assert_eq!(
            parse_record_data_with_priority("AAAA", "::1", None, "test").unwrap(),
            RecordData::AAAA {
                address: "::1".to_string()
            }
        );
        // CNAME
        assert_eq!(
            parse_record_data_with_priority("CNAME", "cdn.example.com", None, "test").unwrap(),
            RecordData::CNAME {
                target: "cdn.example.com".to_string()
            }
        );
        // TXT
        assert_eq!(
            parse_record_data_with_priority("TXT", "v=spf1", None, "test").unwrap(),
            RecordData::TXT {
                text: "v=spf1".to_string()
            }
        );
        // NS
        assert_eq!(
            parse_record_data_with_priority("NS", "ns1.example.com", None, "test").unwrap(),
            RecordData::NS {
                nameserver: "ns1.example.com".to_string()
            }
        );
        // MX
        assert_eq!(
            parse_record_data_with_priority("MX", "mail.example.com", Some(10), "test").unwrap(),
            RecordData::MX {
                priority: 10,
                exchange: "mail.example.com".to_string()
            }
        );
        // SRV
        assert_eq!(
            parse_record_data_with_priority("SRV", "10 20 443 srv.example.com", None, "test")
                .unwrap(),
            RecordData::SRV {
                priority: 10,
                weight: 20,
                port: 443,
                target: "srv.example.com".to_string()
            }
        );
        // CAA
        assert_eq!(
            parse_record_data_with_priority("CAA", r#"0 issue "letsencrypt.org""#, None, "test")
                .unwrap(),
            RecordData::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string()
            }
        );
    }

    #[test]
    fn with_priority_mx_missing_priority() {
        let err =
            parse_record_data_with_priority("MX", "mail.example.com", None, "aliyun").unwrap_err();
        assert!(matches!(err, ProviderError::ParseError { provider, detail }
            if provider == "aliyun" && detail.contains("priority")));
    }

    #[test]
    fn with_priority_unsupported_type() {
        let err = parse_record_data_with_priority("LOC", "some data", None, "test").unwrap_err();
        assert!(
            matches!(err, ProviderError::UnsupportedRecordType { record_type, .. } if record_type == "LOC")
        );
    }

    // ============ parse_record_data_from_string 测试 ============

    #[test]
    fn from_string_all_simple_types() {
        // A
        assert_eq!(
            parse_record_data_from_string("A", "1.2.3.4", "test").unwrap(),
            RecordData::A {
                address: "1.2.3.4".to_string()
            }
        );
        // AAAA
        assert_eq!(
            parse_record_data_from_string("AAAA", "::1", "test").unwrap(),
            RecordData::AAAA {
                address: "::1".to_string()
            }
        );
        // CNAME
        assert_eq!(
            parse_record_data_from_string("CNAME", "cdn.example.com", "test").unwrap(),
            RecordData::CNAME {
                target: "cdn.example.com".to_string()
            }
        );
        // TXT
        assert_eq!(
            parse_record_data_from_string("TXT", "v=spf1", "test").unwrap(),
            RecordData::TXT {
                text: "v=spf1".to_string()
            }
        );
        // NS
        assert_eq!(
            parse_record_data_from_string("NS", "ns1.example.com", "test").unwrap(),
            RecordData::NS {
                nameserver: "ns1.example.com".to_string()
            }
        );
        // MX (from string format)
        assert_eq!(
            parse_record_data_from_string("MX", "10 mail.example.com", "test").unwrap(),
            RecordData::MX {
                priority: 10,
                exchange: "mail.example.com".to_string()
            }
        );
        // SRV
        assert_eq!(
            parse_record_data_from_string("SRV", "10 20 443 srv.example.com", "test").unwrap(),
            RecordData::SRV {
                priority: 10,
                weight: 20,
                port: 443,
                target: "srv.example.com".to_string()
            }
        );
        // CAA
        assert_eq!(
            parse_record_data_from_string("CAA", r#"0 issue "letsencrypt.org""#, "test").unwrap(),
            RecordData::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string()
            }
        );
    }

    #[test]
    fn from_string_mx_invalid_format() {
        let err = parse_record_data_from_string("MX", "just-exchange", "huaweicloud").unwrap_err();
        assert!(
            matches!(err, ProviderError::ParseError { provider, .. } if provider == "huaweicloud")
        );
    }

    #[test]
    fn from_string_unsupported_type() {
        let err = parse_record_data_from_string("PTR", "some data", "test").unwrap_err();
        assert!(
            matches!(err, ProviderError::UnsupportedRecordType { record_type, .. } if record_type == "PTR")
        );
    }
}
