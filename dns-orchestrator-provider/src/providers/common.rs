//! Provider public utility functions

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;

use crate::error::{ProviderError, Result};
use crate::types::{DnsRecordType, ProviderDomain, RecordData};

type HmacSha256 = Hmac<Sha256>;

// ============ HTTP Client ============

/// Default connection timeout (seconds)
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Default request timeout (seconds)
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Globally shared HTTP Client
static SHARED_HTTP_CLIENT: OnceLock<Client> = OnceLock::new();

/// Get a shared HTTP Client (lazy initialization, thread-safe)
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

// ============ Domain Cache ============

/// Domain name information caching to reduce repeated API calls
///
/// Use `std::sync::Mutex` instead of `tokio::sync` because the critical section is extremely short and has no asynchronous operations.
/// TTL is 5 minutes.
pub struct DomainCache {
    cache: Mutex<HashMap<String, (ProviderDomain, Instant)>>,
    ttl: Duration,
}

impl Default for DomainCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainCache {
    /// Creates a cache with the default 5-minute TTL.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Get cached domain name information (if not expired)
    pub fn get(&self, domain_id: &str) -> Option<ProviderDomain> {
        let cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((domain, inserted_at)) = cache.get(domain_id)
            && inserted_at.elapsed() < self.ttl
        {
            return Some(domain.clone());
        }
        None
    }

    /// Insert domain name information into cache
    pub fn insert(&self, domain_id: &str, domain: &ProviderDomain) {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.insert(domain_id.to_string(), (domain.clone(), Instant::now()));
    }
}

// ============ Record type conversion ============

/// Convert `DnsRecordType` to uppercase string
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

/// HMAC-SHA256 calculation (for use by aliyun/dnspod/huaweicloud)
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC-SHA256 accepts keys of any size, so new_from_slice never fails
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// ============ Domain name processing ============

/// Remove the dot at the end of the domain name
pub fn normalize_domain_name(name: &str) -> String {
    name.trim_end_matches('.').to_string()
}

/// Convert full domain name to relative name
/// For example: "www.example.com" + "example.com" -> "www"
/// For example: "example.com" + "example.com" -> "@"
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

/// Convert relative name to full domain name
/// For example: "www" + "example.com" -> "www.example.com"
/// For example: "@" + "example.com" -> "example.com"
pub fn relative_to_full_name(relative_name: &str, zone_name: &str) -> String {
    let zone = normalize_domain_name(zone_name);

    if relative_name == "@" || relative_name.is_empty() {
        zone
    } else {
        format!("{relative_name}.{zone}")
    }
}

// ============ Shared record parsing function ============

/// Parse SRV record data from string
///
/// Format: `"priority weight port target"`
/// Aliyun, DNSPod, and Huaweicloud all use this format.
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

/// Parse CAA record data from string
///
/// Format: `"flags tag value"` (value can be quoted)
/// Aliyun, DNSPod, and Huaweicloud all use this format.
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

/// Parse MX record data from string (Huawei Cloud format)
///
/// Format: `"priority exchange"`
/// Huawei Cloud encodes both priority and exchange in the same string.
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

/// Parse record data from type/value/priority (Aliyun/DNSPod format)
///
/// MX uses a separate priority parameter, SRV/CAA parses from the value string.
pub fn parse_record_data_with_priority(
    record_type: &str,
    value: String,
    priority: Option<u16>,
    provider: &str,
) -> Result<RecordData> {
    match record_type {
        "A" => Ok(RecordData::A { address: value }),
        "AAAA" => Ok(RecordData::AAAA { address: value }),
        "CNAME" => Ok(RecordData::CNAME { target: value }),
        "MX" => Ok(RecordData::MX {
            priority: priority.ok_or_else(|| ProviderError::ParseError {
                provider: provider.to_string(),
                detail: "MX record missing priority field".to_string(),
            })?,
            exchange: value,
        }),
        "TXT" => Ok(RecordData::TXT { text: value }),
        "NS" => Ok(RecordData::NS { nameserver: value }),
        "SRV" => parse_srv_from_string(&value, provider),
        "CAA" => parse_caa_from_string(&value, provider),
        _ => Err(ProviderError::UnsupportedRecordType {
            provider: provider.to_string(),
            record_type: record_type.to_string(),
        }),
    }
}

/// Parse record data from type/record string (Huawei Cloud format)
///
/// MX priority parsed from record string (`"priority exchange"` format),
/// SRV/CAA is also parsed from strings.
pub fn parse_record_data_from_string(
    record_type: &str,
    record: String,
    provider: &str,
) -> Result<RecordData> {
    match record_type {
        "A" => Ok(RecordData::A { address: record }),
        "AAAA" => Ok(RecordData::AAAA { address: record }),
        "CNAME" => Ok(RecordData::CNAME { target: record }),
        "MX" => parse_mx_from_string(&record, provider),
        "TXT" => Ok(RecordData::TXT { text: record }),
        "NS" => Ok(RecordData::NS { nameserver: record }),
        "SRV" => parse_srv_from_string(&record, provider),
        "CAA" => parse_caa_from_string(&record, provider),
        _ => Err(ProviderError::UnsupportedRecordType {
            provider: provider.to_string(),
            record_type: record_type.to_string(),
        }),
    }
}

/// Convert `RecordData` to (value, priority) format
///
/// Aliyun and `DNSPod` use this format: primary value in the value field and MX priority in the independent field.
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

/// Convert `RecordData` to a single string
///
/// Huawei Cloud format: All fields are encoded in a records string.
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

    macro_rules! assert_ok_eq {
        ($res:expr, $expected:expr $(,)?) => {{
            let res = $res;
            let expected = $expected;
            assert!(
                matches!(&res, Ok(v) if v == &expected),
                "unexpected result: {res:?}"
            );
        }};
    }

    macro_rules! assert_err_matches {
        ($res:expr, $pat:pat_param $(if $guard:expr)? $(,)?) => {{
            let res = $res;
            assert!(
                matches!(&res, Err($pat) $(if $guard)?),
                "unexpected result: {res:?}"
            );
        }};
    }

    // ============ SRV parsing test ============

    #[test]
    fn parse_srv_valid() {
        assert_ok_eq!(
            parse_srv_from_string("10 20 443 example.com", "test"),
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
        assert_ok_eq!(
            parse_srv_from_string("0 0 0 .", "test"),
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
        assert_ok_eq!(
            parse_srv_from_string("65535 65535 65535 target.example.com", "test"),
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
        // splitn(4, ' ') means that part 4 contains the remaining content
        assert_ok_eq!(
            parse_srv_from_string("10 20 80 target with spaces", "test"),
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
        assert_err_matches!(
            parse_srv_from_string("10 20", "aliyun"),
            ProviderError::ParseError { provider, .. } if provider == "aliyun"
        );
    }

    #[test]
    fn parse_srv_invalid_priority() {
        assert_err_matches!(
            parse_srv_from_string("abc 20 443 target", "test"),
            ProviderError::ParseError { detail, .. } if detail.contains("priority")
        );
    }

    #[test]
    fn parse_srv_invalid_weight() {
        assert_err_matches!(
            parse_srv_from_string("10 abc 443 target", "test"),
            ProviderError::ParseError { detail, .. } if detail.contains("weight")
        );
    }

    #[test]
    fn parse_srv_invalid_port() {
        assert_err_matches!(
            parse_srv_from_string("10 20 abc target", "test"),
            ProviderError::ParseError { detail, .. } if detail.contains("port")
        );
    }

    #[test]
    fn parse_srv_overflow_port() {
        assert_err_matches!(
            parse_srv_from_string("10 20 99999 target", "test"),
            ProviderError::ParseError { detail, .. } if detail.contains("port")
        );
    }

    // ============ CAA Parsing Test ============

    #[test]
    fn parse_caa_valid_quoted() {
        assert_ok_eq!(
            parse_caa_from_string(r#"0 issue "letsencrypt.org""#, "test"),
            RecordData::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string(),
            }
        );
    }

    #[test]
    fn parse_caa_valid_unquoted() {
        assert_ok_eq!(
            parse_caa_from_string("0 issue letsencrypt.org", "test"),
            RecordData::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string(),
            }
        );
    }

    #[test]
    fn parse_caa_critical_flag() {
        assert_ok_eq!(
            parse_caa_from_string(r#"128 issuewild "*.example.com""#, "test"),
            RecordData::CAA {
                flags: 128,
                tag: "issuewild".to_string(),
                value: "*.example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_caa_iodef_with_url() {
        assert_ok_eq!(
            parse_caa_from_string(r#"0 iodef "mailto:admin@example.com""#, "test"),
            RecordData::CAA {
                flags: 0,
                tag: "iodef".to_string(),
                value: "mailto:admin@example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_caa_too_few_parts() {
        assert_err_matches!(
            parse_caa_from_string("0 issue", "dnspod"),
            ProviderError::ParseError { provider, .. } if provider == "dnspod"
        );
    }

    #[test]
    fn parse_caa_invalid_flags() {
        assert_err_matches!(
            parse_caa_from_string("abc issue letsencrypt.org", "test"),
            ProviderError::ParseError { detail, .. } if detail.contains("flags")
        );
    }

    // ============ MX parsing test ============

    #[test]
    fn parse_mx_valid() {
        assert_ok_eq!(
            parse_mx_from_string("10 mail.example.com", "huaweicloud"),
            RecordData::MX {
                priority: 10,
                exchange: "mail.example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_mx_zero_priority() {
        assert_ok_eq!(
            parse_mx_from_string("0 mx.example.com", "test"),
            RecordData::MX {
                priority: 0,
                exchange: "mx.example.com".to_string(),
            }
        );
    }

    #[test]
    fn parse_mx_missing_exchange() {
        assert_err_matches!(
            parse_mx_from_string("10", "test"),
            ProviderError::ParseError { .. }
        );
    }

    #[test]
    fn parse_mx_invalid_priority() {
        assert_err_matches!(
            parse_mx_from_string("abc mail.example.com", "test"),
            ProviderError::ParseError { detail, .. } if detail.contains("priority")
        );
    }

    // ============ record_data_to_value_priority test ============

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

    // ============ record_data_to_single_string test ============

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

    // ============ SRV/CAA Round Trip Test ============

    #[test]
    fn srv_roundtrip_value_priority() {
        let original = RecordData::SRV {
            priority: 10,
            weight: 60,
            port: 5060,
            target: "sip.example.com".to_string(),
        };
        let (value, _) = record_data_to_value_priority(&original);
        assert_ok_eq!(parse_srv_from_string(&value, "test"), original);
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
        assert_ok_eq!(parse_srv_from_string(&s, "test"), original);
    }

    #[test]
    fn caa_roundtrip() {
        let original = RecordData::CAA {
            flags: 0,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
        };
        let (value, _) = record_data_to_value_priority(&original);
        assert_ok_eq!(parse_caa_from_string(&value, "test"), original);
    }

    #[test]
    fn mx_roundtrip() {
        let original = RecordData::MX {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        };
        let s = record_data_to_single_string(&original);
        assert_ok_eq!(parse_mx_from_string(&s, "test"), original);
    }

    // ============ Domain name auxiliary function test ============

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
        // Does not belong to the zone, returns full name
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

    // ============ record_type_to_string test ============

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

    // ============ parse_record_data_with_priority test ============

    #[test]
    fn with_priority_all_simple_types() {
        // A
        assert_ok_eq!(
            parse_record_data_with_priority("A", "1.2.3.4".to_string(), None, "test"),
            RecordData::A {
                address: "1.2.3.4".to_string()
            }
        );
        // AAAA
        assert_ok_eq!(
            parse_record_data_with_priority("AAAA", "::1".to_string(), None, "test"),
            RecordData::AAAA {
                address: "::1".to_string()
            }
        );
        // CNAME
        assert_ok_eq!(
            parse_record_data_with_priority("CNAME", "cdn.example.com".to_string(), None, "test"),
            RecordData::CNAME {
                target: "cdn.example.com".to_string()
            }
        );
        // TXT
        assert_ok_eq!(
            parse_record_data_with_priority("TXT", "v=spf1".to_string(), None, "test"),
            RecordData::TXT {
                text: "v=spf1".to_string()
            }
        );
        // NS
        assert_ok_eq!(
            parse_record_data_with_priority("NS", "ns1.example.com".to_string(), None, "test"),
            RecordData::NS {
                nameserver: "ns1.example.com".to_string()
            }
        );
        // MX
        assert_ok_eq!(
            parse_record_data_with_priority("MX", "mail.example.com".to_string(), Some(10), "test"),
            RecordData::MX {
                priority: 10,
                exchange: "mail.example.com".to_string()
            }
        );
        // SRV
        assert_ok_eq!(
            parse_record_data_with_priority(
                "SRV",
                "10 20 443 srv.example.com".to_string(),
                None,
                "test"
            ),
            RecordData::SRV {
                priority: 10,
                weight: 20,
                port: 443,
                target: "srv.example.com".to_string()
            }
        );
        // CAA
        assert_ok_eq!(
            parse_record_data_with_priority(
                "CAA",
                r#"0 issue "letsencrypt.org""#.to_string(),
                None,
                "test"
            ),
            RecordData::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string()
            }
        );
    }

    #[test]
    fn with_priority_mx_missing_priority() {
        assert_err_matches!(
            parse_record_data_with_priority("MX", "mail.example.com".to_string(), None, "aliyun"),
            ProviderError::ParseError { provider, detail }
                if provider == "aliyun" && detail.contains("priority")
        );
    }

    #[test]
    fn with_priority_unsupported_type() {
        assert_err_matches!(
            parse_record_data_with_priority("LOC", "some data".to_string(), None, "test"),
            ProviderError::UnsupportedRecordType { record_type, .. } if record_type == "LOC"
        );
    }

    // ============ parse_record_data_from_string test ============

    #[test]
    fn from_string_all_simple_types() {
        // A
        assert_ok_eq!(
            parse_record_data_from_string("A", "1.2.3.4".to_string(), "test"),
            RecordData::A {
                address: "1.2.3.4".to_string()
            }
        );
        // AAAA
        assert_ok_eq!(
            parse_record_data_from_string("AAAA", "::1".to_string(), "test"),
            RecordData::AAAA {
                address: "::1".to_string()
            }
        );
        // CNAME
        assert_ok_eq!(
            parse_record_data_from_string("CNAME", "cdn.example.com".to_string(), "test"),
            RecordData::CNAME {
                target: "cdn.example.com".to_string()
            }
        );
        // TXT
        assert_ok_eq!(
            parse_record_data_from_string("TXT", "v=spf1".to_string(), "test"),
            RecordData::TXT {
                text: "v=spf1".to_string()
            }
        );
        // NS
        assert_ok_eq!(
            parse_record_data_from_string("NS", "ns1.example.com".to_string(), "test"),
            RecordData::NS {
                nameserver: "ns1.example.com".to_string()
            }
        );
        // MX (from string format)
        assert_ok_eq!(
            parse_record_data_from_string("MX", "10 mail.example.com".to_string(), "test"),
            RecordData::MX {
                priority: 10,
                exchange: "mail.example.com".to_string()
            }
        );
        // SRV
        assert_ok_eq!(
            parse_record_data_from_string("SRV", "10 20 443 srv.example.com".to_string(), "test"),
            RecordData::SRV {
                priority: 10,
                weight: 20,
                port: 443,
                target: "srv.example.com".to_string()
            }
        );
        // CAA
        assert_ok_eq!(
            parse_record_data_from_string(
                "CAA",
                r#"0 issue "letsencrypt.org""#.to_string(),
                "test"
            ),
            RecordData::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string()
            }
        );
    }

    #[test]
    fn from_string_mx_invalid_format() {
        assert_err_matches!(
            parse_record_data_from_string("MX", "just-exchange".to_string(), "huaweicloud"),
            ProviderError::ParseError { provider, .. } if provider == "huaweicloud"
        );
    }

    #[test]
    fn from_string_unsupported_type() {
        assert_err_matches!(
            parse_record_data_from_string("PTR", "some data".to_string(), "test"),
            ProviderError::UnsupportedRecordType { record_type, .. } if record_type == "PTR"
        );
    }
}
