//! Date/time serialization and deserialization utilities.
//!
//! Provides custom Serde support for `Option<DateTime<Utc>>`:
//! - Serialize: `DateTime<Utc>` -> RFC 3339 string
//! - Deserialize: RFC 3339 string or Unix timestamp (seconds/milliseconds) -> `DateTime<Utc>`

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize `Option<DateTime<Utc>>` as an optional RFC 3339 string.
pub fn serialize<S>(dt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(dt) => serializer.serialize_some(&dt.to_rfc3339()),
        None => serializer.serialize_none(),
    }
}

/// Deserialize `Option<DateTime<Utc>>` from an RFC 3339 string or Unix timestamp (seconds/milliseconds).
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

/// Parse Unix timestamp (automatically determine seconds/milliseconds)
fn parse_unix_timestamp(ts: i64) -> Option<DateTime<Utc>> {
    // If the timestamp > 10^11, it is considered to be milliseconds (Alibaba Cloud uses millisecond timestamps)
    if ts > 100_000_000_000 {
        DateTime::from_timestamp_millis(ts)
    } else {
        // Otherwise it is considered to be seconds
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
        let dt_opt = Utc.with_ymd_and_hms(2024, 1, 15, 12, 30, 0).single();
        assert!(
            dt_opt.is_some(),
            "invalid datetime for serialize_some_datetime"
        );
        let Some(dt) = dt_opt else {
            return;
        };
        let w = Wrapper { ts: Some(dt) };
        let json_res = serde_json::to_string(&w);
        assert!(
            json_res.is_ok(),
            "serde_json::to_string failed: {json_res:?}"
        );
        let Ok(json) = json_res else {
            return;
        };
        // RFC3339 string should be in the output
        assert!(json.contains("2024-01-15T12:30:00+00:00"));
    }

    #[test]
    fn serialize_none() {
        let w = Wrapper { ts: None };
        let json_res = serde_json::to_string(&w);
        assert!(
            json_res.is_ok(),
            "serde_json::to_string failed: {json_res:?}"
        );
        let Ok(json) = json_res else {
            return;
        };
        assert!(json.contains("null"));
    }

    #[test]
    fn deserialize_rfc3339() {
        let json = r#"{"ts":"2024-01-15T12:30:00+00:00"}"#;
        let w_res: serde_json::Result<Wrapper> = serde_json::from_str(json);
        assert!(w_res.is_ok(), "serde_json::from_str failed: {w_res:?}");
        let Ok(w) = w_res else {
            return;
        };

        let expected_opt = Utc.with_ymd_and_hms(2024, 1, 15, 12, 30, 0).single();
        assert!(
            expected_opt.is_some(),
            "invalid expected datetime for deserialize_rfc3339"
        );
        let Some(expected) = expected_opt else {
            return;
        };
        assert_eq!(w.ts, Some(expected));
    }

    #[test]
    fn deserialize_unix_seconds() {
        // 1700000000 = 2023-11-14T22:13:20Z
        let json = r#"{"ts":1700000000}"#;
        let w_res: serde_json::Result<Wrapper> = serde_json::from_str(json);
        assert!(w_res.is_ok(), "serde_json::from_str failed: {w_res:?}");
        let Ok(w) = w_res else {
            return;
        };

        let expected_opt = Utc.with_ymd_and_hms(2023, 11, 14, 22, 13, 20).single();
        assert!(
            expected_opt.is_some(),
            "invalid expected datetime for deserialize_unix_seconds"
        );
        let Some(expected) = expected_opt else {
            return;
        };
        assert_eq!(w.ts, Some(expected));
    }

    #[test]
    fn deserialize_unix_millis() {
        // 1700000000000 ms = same as 1700000000 seconds
        let json = r#"{"ts":1700000000000}"#;
        let w_res: serde_json::Result<Wrapper> = serde_json::from_str(json);
        assert!(w_res.is_ok(), "serde_json::from_str failed: {w_res:?}");
        let Ok(w) = w_res else {
            return;
        };

        let expected_opt = Utc.with_ymd_and_hms(2023, 11, 14, 22, 13, 20).single();
        assert!(
            expected_opt.is_some(),
            "invalid expected datetime for deserialize_unix_millis"
        );
        let Some(expected) = expected_opt else {
            return;
        };
        assert_eq!(w.ts, Some(expected));
    }

    #[test]
    fn deserialize_null() {
        let json = r#"{"ts":null}"#;
        let w_res: serde_json::Result<Wrapper> = serde_json::from_str(json);
        assert!(w_res.is_ok(), "serde_json::from_str failed: {w_res:?}");
        let Ok(w) = w_res else {
            return;
        };
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
        let dt_opt = Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).single();
        assert!(dt_opt.is_some(), "invalid datetime for roundtrip_some");
        let Some(dt) = dt_opt else {
            return;
        };
        let original = Wrapper { ts: Some(dt) };
        let json_res = serde_json::to_string(&original);
        assert!(
            json_res.is_ok(),
            "serde_json::to_string failed: {json_res:?}"
        );
        let Ok(json) = json_res else {
            return;
        };

        let restored_res: serde_json::Result<Wrapper> = serde_json::from_str(&json);
        assert!(
            restored_res.is_ok(),
            "serde_json::from_str failed: {restored_res:?}"
        );
        let Ok(restored) = restored_res else {
            return;
        };
        assert_eq!(original, restored);
    }

    #[test]
    fn roundtrip_none() {
        let original = Wrapper { ts: None };
        let json_res = serde_json::to_string(&original);
        assert!(
            json_res.is_ok(),
            "serde_json::to_string failed: {json_res:?}"
        );
        let Ok(json) = json_res else {
            return;
        };

        let restored_res: serde_json::Result<Wrapper> = serde_json::from_str(&json);
        assert!(
            restored_res.is_ok(),
            "serde_json::from_str failed: {restored_res:?}"
        );
        let Ok(restored) = restored_res else {
            return;
        };
        assert_eq!(original, restored);
    }

    #[test]
    fn boundary_seconds_vs_millis() {
        // 100_000_000_000 is exactly the boundary -- treated as seconds (not > threshold)
        let json_seconds = r#"{"ts":100000000000}"#;
        let w_sec_res: serde_json::Result<Wrapper> = serde_json::from_str(json_seconds);
        assert!(
            w_sec_res.is_ok(),
            "serde_json::from_str failed: {w_sec_res:?}"
        );
        let Ok(w_sec) = w_sec_res else {
            return;
        };

        let expected_sec_opt = DateTime::from_timestamp(100_000_000_000, 0);
        assert!(
            expected_sec_opt.is_some(),
            "DateTime::from_timestamp returned None for seconds boundary"
        );
        let Some(expected_sec) = expected_sec_opt else {
            return;
        };
        assert_eq!(w_sec.ts, Some(expected_sec));

        // 100_000_000_001 is > threshold -- treated as millis
        let json_millis = r#"{"ts":100000000001}"#;
        let w_ms_res: serde_json::Result<Wrapper> = serde_json::from_str(json_millis);
        assert!(
            w_ms_res.is_ok(),
            "serde_json::from_str failed: {w_ms_res:?}"
        );
        let Ok(w_ms) = w_ms_res else {
            return;
        };

        let expected_ms_opt = DateTime::from_timestamp_millis(100_000_000_001);
        assert!(
            expected_ms_opt.is_some(),
            "DateTime::from_timestamp_millis returned None for millis boundary"
        );
        let Some(expected_ms) = expected_ms_opt else {
            return;
        };
        assert_eq!(w_ms.ts, Some(expected_ms));
    }
}
