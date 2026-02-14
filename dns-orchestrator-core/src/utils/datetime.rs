//! Datetime serialization/deserialization tool
//!
//! Provides custom Serde serialization/deserialization support:
//! - Serialization: `DateTime`<Utc> -> RFC3339 string
//! - Deserialization: RFC3339 string or Unix timestamp -> `DateTime`<Utc>

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize `DateTime`<Utc> to RFC3339 string
pub fn serialize<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&dt.to_rfc3339())
}

/// Deserialization: supports RFC3339 string or Unix timestamp (seconds/milliseconds automatic recognition)
pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TimestampOrString {
        String(String),
        I64(i64),
        U64(u64),
    }

    match TimestampOrString::deserialize(deserializer)? {
        TimestampOrString::String(s) => {
            // Try parsing RFC3339
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| Error::custom(format!("Invalid RFC3339 timestamp: {e}")))
        }
        TimestampOrString::I64(ts) => {
            // Unix timestamp (automatically determine seconds/milliseconds)
            parse_unix_timestamp(ts).ok_or_else(|| Error::custom("Invalid Unix timestamp"))
        }
        TimestampOrString::U64(ts) => {
            // u64 -> i64: Unix timestamps in practice are well within i64 range
            #[allow(clippy::cast_possible_wrap)]
            parse_unix_timestamp(ts as i64).ok_or_else(|| Error::custom("Invalid Unix timestamp"))
        }
    }
}

/// Option version: serialization and deserialization Option<`DateTime`<Utc>>
pub mod option {
    use super::{parse_unix_timestamp, DateTime, Deserialize, Deserializer, Serializer, Utc};

    pub fn serialize<S>(dt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dt {
            Some(dt) => serializer.serialize_some(&dt.to_rfc3339()),
            None => serializer.serialize_none(),
        }
    }

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
            Some(OptionalTimestamp::U64(ts)) => {
                // u64 -> i64: Unix timestamps in practice are well within i64 range
                #[allow(clippy::cast_possible_wrap)]
                parse_unix_timestamp(ts as i64)
                    .map(Some)
                    .ok_or_else(|| Error::custom("Invalid Unix timestamp"))
            }
            None => Ok(None),
        }
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
