//! 阿里云 API 类型定义和辅助函数

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write;

use crate::error::{ProviderError, Result};

// ============ RFC3986 URL 编码 ============

/// RFC3986 URL 编码
pub fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            _ => {
                for byte in c.to_string().as_bytes() {
                    let _ = write!(result, "%{byte:02X}");
                }
            }
        }
    }
    result
}

/// 将 `serde_json::Value` 展平为 key-value 对 (处理嵌套对象)
pub fn flatten_value(
    prefix: &str,
    value: &serde_json::Value,
    result: &mut BTreeMap<String, String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let new_key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_value(&new_key, v, result);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let new_key = format!("{}.{}", prefix, i + 1);
                flatten_value(&new_key, v, result);
            }
        }
        serde_json::Value::String(s) => {
            result.insert(prefix.to_string(), s.clone());
        }
        serde_json::Value::Number(n) => {
            result.insert(prefix.to_string(), n.to_string());
        }
        serde_json::Value::Bool(b) => {
            result.insert(prefix.to_string(), b.to_string());
        }
        serde_json::Value::Null => {}
    }
}

/// 将结构体序列化为排序后的 query string
pub fn serialize_to_query_string<T: Serialize>(params: &T) -> Result<String> {
    let value = serde_json::to_value(params).map_err(|e| ProviderError::SerializationError {
        provider: "aliyun".to_string(),
        detail: e.to_string(),
    })?;

    let mut flat_map = BTreeMap::new();
    flatten_value("", &value, &mut flat_map);

    let query_string = flat_map
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    Ok(query_string)
}

// ============ 域名相关结构 ============

#[derive(Debug, Deserialize)]
pub struct DescribeDomainsResponse {
    #[serde(rename = "Domains")]
    pub domains: Option<DomainsWrapper>,
    #[serde(rename = "TotalCount")]
    pub total_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct DomainsWrapper {
    #[serde(rename = "Domain")]
    pub domain: Option<Vec<AliyunDomain>>,
}

#[derive(Debug, Deserialize)]
pub struct AliyunDomain {
    #[serde(rename = "DomainName")]
    pub domain_name: String,
    #[serde(rename = "DomainStatus")]
    pub domain_status: Option<String>,
    #[serde(rename = "RecordCount")]
    pub record_count: Option<u32>,
}

/// `ErrorRequireCheck`: `DescribeDomainInfo` API 响应结构，需验证字段映射是否正确
#[derive(Debug, Deserialize)]
pub struct DescribeDomainInfoResponse {
    #[serde(rename = "DomainName")]
    pub domain_name: String,
    #[serde(rename = "DomainStatus")]
    pub domain_status: Option<String>,
    #[serde(rename = "RecordCount")]
    pub record_count: Option<u32>,
}

// ============ 记录相关结构 ============

#[derive(Debug, Deserialize)]
pub struct DescribeDomainRecordsResponse {
    #[serde(rename = "DomainRecords")]
    pub domain_records: Option<DomainRecordsWrapper>,
    #[serde(rename = "TotalCount")]
    pub total_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct DomainRecordsWrapper {
    #[serde(rename = "Record")]
    pub record: Option<Vec<AliyunRecord>>,
}

#[derive(Debug, Deserialize)]
pub struct AliyunRecord {
    #[serde(rename = "RecordId")]
    pub record_id: String,
    #[serde(rename = "RR")]
    pub rr: String,
    #[serde(rename = "Type")]
    pub record_type: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    #[serde(rename = "Priority")]
    pub priority: Option<u16>,
    #[serde(rename = "CreateTimestamp")]
    pub create_timestamp: Option<i64>,
    #[serde(rename = "UpdateTimestamp")]
    pub update_timestamp: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AddDomainRecordResponse {
    #[serde(rename = "RecordId")]
    pub record_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDomainRecordResponse {}

#[derive(Debug, Deserialize)]
pub struct DeleteDomainRecordResponse {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    // ---- url_encode ----

    #[test]
    fn url_encode_alphanumeric() {
        assert_eq!(url_encode("abc123"), "abc123");
    }

    #[test]
    fn url_encode_unreserved() {
        assert_eq!(url_encode("-._~"), "-._~");
    }

    #[test]
    fn url_encode_space() {
        assert_eq!(url_encode("hello world"), "hello%20world");
    }

    #[test]
    fn url_encode_chinese() {
        assert_eq!(url_encode("你好"), "%E4%BD%A0%E5%A5%BD");
    }

    #[test]
    fn url_encode_empty() {
        assert_eq!(url_encode(""), "");
    }

    #[test]
    fn url_encode_special_chars() {
        assert_eq!(url_encode("/?"), "%2F%3F");
        assert_eq!(url_encode("&="), "%26%3D");
    }

    // ---- flatten_value ----

    #[test]
    fn flatten_simple_object() {
        let val = json!({"a": "1", "b": "2"});
        let mut map = BTreeMap::new();
        flatten_value("", &val, &mut map);
        assert_eq!(map.get("a").map(String::as_str), Some("1"));
        assert_eq!(map.get("b").map(String::as_str), Some("2"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn flatten_nested_object() {
        let val = json!({"a": {"b": "1"}});
        let mut map = BTreeMap::new();
        flatten_value("", &val, &mut map);
        assert_eq!(map.get("a.b").map(String::as_str), Some("1"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn flatten_array() {
        let val = json!({"a": [10, 20]});
        let mut map = BTreeMap::new();
        flatten_value("", &val, &mut map);
        assert_eq!(map.get("a.1").map(String::as_str), Some("10"));
        assert_eq!(map.get("a.2").map(String::as_str), Some("20"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn flatten_bool_and_number() {
        let val = json!({"flag": true, "count": 42});
        let mut map = BTreeMap::new();
        flatten_value("", &val, &mut map);
        assert_eq!(map.get("flag").map(String::as_str), Some("true"));
        assert_eq!(map.get("count").map(String::as_str), Some("42"));
    }

    #[test]
    fn flatten_null_skipped() {
        let val = json!({"a": null});
        let mut map = BTreeMap::new();
        flatten_value("", &val, &mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn flatten_empty_object() {
        let val = json!({});
        let mut map = BTreeMap::new();
        flatten_value("", &val, &mut map);
        assert!(map.is_empty());
    }

    // ---- serialize_to_query_string ----

    #[test]
    fn query_string_simple() {
        let val = json!({"b": "2", "a": "1"});
        let mut flat_map = BTreeMap::new();
        flatten_value("", &val, &mut flat_map);
        let qs = flat_map
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        // BTreeMap sorts keys, so "a" comes before "b"
        assert_eq!(qs, "a=1&b=2");
    }

    #[test]
    fn query_string_encodes_values() {
        let val = json!({"key": "hello world", "path": "/foo"});
        let mut flat_map = BTreeMap::new();
        flatten_value("", &val, &mut flat_map);
        let qs = flat_map
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        assert_eq!(qs, "key=hello%20world&path=%2Ffoo");
    }
}
