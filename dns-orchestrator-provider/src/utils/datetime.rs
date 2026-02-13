//! 日期时间序列化/反序列化工具
//!
//! 提供自定义 Serde 序列化/反序列化支持：
//! - 序列化: `DateTime`<Utc> -> RFC3339 字符串
//! - 反序列化: RFC3339 字符串 或 Unix 时间戳 -> `DateTime`<Utc>

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serializer};

/// 序列化 Option<`DateTime`<Utc>> 为 Option<RFC3339 字符串>
pub fn serialize<S>(dt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(dt) => serializer.serialize_some(&dt.to_rfc3339()),
        None => serializer.serialize_none(),
    }
}

/// 反序列化：支持 RFC3339 字符串或 Unix 时间戳（秒/毫秒自动识别）
pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OptionalTimestamp {
        String(String),
        I64(i64),
        U64(u64),
    }

    match Option::<OptionalTimestamp>::deserialize(deserializer)? {
        Some(OptionalTimestamp::String(s)) => DateTime::parse_from_rfc3339(&s)
            .map(|dt| Some(dt.with_timezone(&Utc)))
            .map_err(|e| Error::custom(format!("Invalid RFC3339 timestamp: {e}"))),
        Some(OptionalTimestamp::I64(ts)) => parse_unix_timestamp(ts)
            .map(Some)
            .ok_or_else(|| Error::custom("Invalid Unix timestamp")),
        Some(OptionalTimestamp::U64(ts)) => parse_unix_timestamp(ts.cast_signed())
            .map(Some)
            .ok_or_else(|| Error::custom("Invalid Unix timestamp")),
        None => Ok(None),
    }
}

/// 解析 Unix 时间戳（自动判断秒/毫秒）
fn parse_unix_timestamp(ts: i64) -> Option<DateTime<Utc>> {
    // 如果时间戳 > 10^11，认为是毫秒（阿里云使用毫秒时间戳）
    if ts > 100_000_000_000 {
        DateTime::from_timestamp_millis(ts)
    } else {
        // 否则认为是秒
        DateTime::from_timestamp(ts, 0)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Wrapper {
        #[serde(with = "super")]
        ts: Option<DateTime<Utc>>,
    }

    #[test]
    fn serialize_some_datetime() {
        let dt = Utc.with_ymd_and_hms(2024, 1, 15, 12, 30, 0).unwrap();
        let w = Wrapper { ts: Some(dt) };
        let json = serde_json::to_string(&w).unwrap();
        // RFC3339 string should be in the output
        assert!(json.contains("2024-01-15T12:30:00+00:00"));
    }

    #[test]
    fn serialize_none() {
        let w = Wrapper { ts: None };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("null"));
    }

    #[test]
    fn deserialize_rfc3339() {
        let json = r#"{"ts":"2024-01-15T12:30:00+00:00"}"#;
        let w: Wrapper = serde_json::from_str(json).unwrap();
        let expected = Utc.with_ymd_and_hms(2024, 1, 15, 12, 30, 0).unwrap();
        assert_eq!(w.ts, Some(expected));
    }

    #[test]
    fn deserialize_unix_seconds() {
        // 1700000000 = 2023-11-14T22:13:20Z
        let json = r#"{"ts":1700000000}"#;
        let w: Wrapper = serde_json::from_str(json).unwrap();
        let expected = Utc.with_ymd_and_hms(2023, 11, 14, 22, 13, 20).unwrap();
        assert_eq!(w.ts, Some(expected));
    }

    #[test]
    fn deserialize_unix_millis() {
        // 1700000000000 ms = same as 1700000000 seconds
        let json = r#"{"ts":1700000000000}"#;
        let w: Wrapper = serde_json::from_str(json).unwrap();
        let expected = Utc.with_ymd_and_hms(2023, 11, 14, 22, 13, 20).unwrap();
        assert_eq!(w.ts, Some(expected));
    }

    #[test]
    fn deserialize_null() {
        let json = r#"{"ts":null}"#;
        let w: Wrapper = serde_json::from_str(json).unwrap();
        assert_eq!(w.ts, None);
    }

    #[test]
    fn deserialize_invalid_rfc3339() {
        let json = r#"{"ts":"not-a-date"}"#;
        let result = serde_json::from_str::<Wrapper>(json);
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_some() {
        let dt = Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();
        let original = Wrapper { ts: Some(dt) };
        let json = serde_json::to_string(&original).unwrap();
        let restored: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn roundtrip_none() {
        let original = Wrapper { ts: None };
        let json = serde_json::to_string(&original).unwrap();
        let restored: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn boundary_seconds_vs_millis() {
        // 100_000_000_000 is exactly the boundary -- treated as seconds (not > threshold)
        let json_seconds = r#"{"ts":100000000000}"#;
        let w_sec: Wrapper = serde_json::from_str(json_seconds).unwrap();
        let expected_sec = DateTime::from_timestamp(100_000_000_000, 0).unwrap();
        assert_eq!(w_sec.ts, Some(expected_sec));

        // 100_000_000_001 is > threshold -- treated as millis
        let json_millis = r#"{"ts":100000000001}"#;
        let w_ms: Wrapper = serde_json::from_str(json_millis).unwrap();
        let expected_ms = DateTime::from_timestamp_millis(100_000_000_001).unwrap();
        assert_eq!(w_ms.ts, Some(expected_ms));
    }
}
