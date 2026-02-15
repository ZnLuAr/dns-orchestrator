//! `DNSPod` TC3-HMAC-SHA256 signature

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::providers::common::hmac_sha256;

use super::{DNSPOD_API_HOST, DNSPOD_SERVICE, DnspodProvider};

impl DnspodProvider {
    /// Generate TC3-HMAC-SHA256 signature
    pub(crate) fn sign(&self, action: &str, payload: &str, timestamp: i64) -> String {
        let date = DateTime::from_timestamp(timestamp, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%d")
            .to_string();

        // 1. Splicing specification request string
        let http_request_method = "POST";
        let canonical_uri = "/";
        let canonical_query_string = "";
        let canonical_headers = format!(
            "content-type:application/json; charset=utf-8\nhost:{}\nx-tc-action:{}\n",
            DNSPOD_API_HOST,
            action.to_lowercase()
        );
        let signed_headers = "content-type;host;x-tc-action";
        let hashed_payload = hex::encode(Sha256::digest(payload.as_bytes()));
        let canonical_request = format!(
            "{http_request_method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{hashed_payload}"
        );

        // 2. Pin the string to be signed
        let algorithm = "TC3-HMAC-SHA256";
        let credential_scope = format!("{date}/{DNSPOD_SERVICE}/tc3_request");
        let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign =
            format!("{algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}");

        // 3. Calculate signature
        let secret_date = hmac_sha256(
            format!("TC3{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let secret_service = hmac_sha256(&secret_date, DNSPOD_SERVICE.as_bytes());
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
        let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

        // 4. Splicing Authorization
        format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm, self.secret_id, credential_scope, signed_headers, signature
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::DnspodProvider;

    fn provider() -> DnspodProvider {
        DnspodProvider::new("test_secret_id".to_string(), "test_secret_key".to_string())
    }

    fn extract_credential(auth: &str) -> Option<&str> {
        auth.split("Credential=")
            .nth(1)
            .and_then(|s| s.split(',').next())
    }

    fn extract_signed_headers(auth: &str) -> Option<&str> {
        auth.split("SignedHeaders=")
            .nth(1)
            .and_then(|s| s.split(',').next())
    }

    fn extract_signature(auth: &str) -> Option<&str> {
        auth.split("Signature=").nth(1)
    }

    // ---- Output format ----

    #[test]
    fn sign_output_format() {
        let result = provider().sign("DescribeRecordList", "{}", 1_705_305_600);

        assert!(
            result.starts_with("TC3-HMAC-SHA256 "),
            "should start with 'TC3-HMAC-SHA256 ', got: {result}"
        );
        assert!(
            result.contains("Credential="),
            "should contain 'Credential=', got: {result}"
        );
        assert!(
            result.contains("SignedHeaders="),
            "should contain 'SignedHeaders=', got: {result}"
        );
        assert!(
            result.contains("Signature="),
            "should contain 'Signature=', got: {result}"
        );
    }

    // ---- Credential contains secret_id and date path ----

    #[test]
    fn sign_credential_contains_secret_id_and_date() {
        // timestamp 1705305600 = 2024-01-15 08:00:00 UTC
        let result = provider().sign("DescribeRecordList", "{}", 1_705_305_600);

        let credential_opt = extract_credential(&result);
        assert!(
            credential_opt.is_some(),
            "failed to extract Credential: {result}"
        );
        let Some(credential) = credential_opt else {
            return;
        };

        assert!(
            credential.starts_with("test_secret_id/"),
            "Credential should start with secret_id, got: {credential}"
        );
        assert!(
            credential.contains("2024-01-15/dnspod/tc3_request"),
            "Credential should contain date path '2024-01-15/dnspod/tc3_request', got: {credential}"
        );
    }

    // ---- SignedHeaders Correct ----

    #[test]
    fn sign_signed_headers_correct() {
        let result = provider().sign("DescribeRecordList", "{}", 1_705_305_600);

        let signed_headers_opt = extract_signed_headers(&result);
        assert!(
            signed_headers_opt.is_some(),
            "failed to extract SignedHeaders: {result}"
        );
        let Some(signed_headers) = signed_headers_opt else {
            return;
        };

        assert_eq!(
            signed_headers, "content-type;host;x-tc-action",
            "SignedHeaders should be 'content-type;host;x-tc-action'"
        );
    }

    // ----Certainty ----

    #[test]
    fn sign_deterministic() {
        let p = provider();
        let a = p.sign(
            "DescribeRecordList",
            r#"{"Domain":"example.com"}"#,
            1_705_305_600,
        );
        let b = p.sign(
            "DescribeRecordList",
            r#"{"Domain":"example.com"}"#,
            1_705_305_600,
        );
        assert_eq!(a, b, "same inputs should produce identical output");
    }

    // ---- Different actions generate different signatures ----

    #[test]
    fn sign_different_action_changes_signature() {
        let p = provider();
        let a = p.sign("DescribeRecordList", "{}", 1_705_305_600);
        let b = p.sign("CreateRecord", "{}", 1_705_305_600);

        let sig_describe_record_list_opt = extract_signature(&a);
        assert!(
            sig_describe_record_list_opt.is_some(),
            "failed to extract Signature: {a}"
        );
        let Some(sig_describe_record_list) = sig_describe_record_list_opt else {
            return;
        };

        let sig_create_record_opt = extract_signature(&b);
        assert!(
            sig_create_record_opt.is_some(),
            "failed to extract Signature: {b}"
        );
        let Some(sig_create_record) = sig_create_record_opt else {
            return;
        };

        assert_ne!(
            sig_describe_record_list, sig_create_record,
            "different actions should produce different signatures"
        );
    }

    // ---- Different payloads generate different signatures ----

    #[test]
    fn sign_different_payload_changes_signature() {
        let p = provider();
        let a = p.sign("DescribeRecordList", r#"{"Domain":"a.com"}"#, 1_705_305_600);
        let b = p.sign("DescribeRecordList", r#"{"Domain":"b.com"}"#, 1_705_305_600);

        let sig_first_payload_opt = extract_signature(&a);
        assert!(
            sig_first_payload_opt.is_some(),
            "failed to extract Signature: {a}"
        );
        let Some(sig_first_payload) = sig_first_payload_opt else {
            return;
        };

        let sig_second_payload_opt = extract_signature(&b);
        assert!(
            sig_second_payload_opt.is_some(),
            "failed to extract Signature: {b}"
        );
        let Some(sig_second_payload) = sig_second_payload_opt else {
            return;
        };

        assert_ne!(
            sig_first_payload, sig_second_payload,
            "different payloads should produce different signatures"
        );
    }

    // ---- Different secret_key generates different signatures ----

    #[test]
    fn sign_different_secret_changes_signature() {
        let p1 = DnspodProvider::new("test_id".to_string(), "key_alpha".to_string());
        let p2 = DnspodProvider::new("test_id".to_string(), "key_beta".to_string());

        let a = p1.sign("DescribeRecordList", "{}", 1_705_305_600);
        let b = p2.sign("DescribeRecordList", "{}", 1_705_305_600);

        let sig_key_alpha_opt = extract_signature(&a);
        assert!(
            sig_key_alpha_opt.is_some(),
            "failed to extract Signature: {a}"
        );
        let Some(sig_key_alpha) = sig_key_alpha_opt else {
            return;
        };

        let sig_key_beta_opt = extract_signature(&b);
        assert!(
            sig_key_beta_opt.is_some(),
            "failed to extract Signature: {b}"
        );
        let Some(sig_key_beta) = sig_key_beta_opt else {
            return;
        };

        assert_ne!(
            sig_key_alpha, sig_key_beta,
            "different secret keys should produce different signatures"
        );
    }

    // ---- Date is derived from timestamp ----

    #[test]
    fn sign_date_derived_from_timestamp() {
        let p = provider();

        // Two timestamps on the same day (2024-01-15 UTC)
        let ts_morning = 1_705_305_600; // 2024-01-15 08:00:00 UTC
        let ts_evening = 1_705_348_800; // 2024-01-15 20:00:00 UTC

        let result_morning = p.sign("DescribeRecordList", "{}", ts_morning);
        let result_evening = p.sign("DescribeRecordList", "{}", ts_evening);

        // Extract date part from Credential
        let extract_date = |s: &str| -> Option<String> {
            let credential = extract_credential(s)?;
            // Format: secret_id/YYYY-MM-DD/dnspod/tc3_request
            credential
                .split('/')
                .nth(1)
                .map(std::string::ToString::to_string)
        };

        let date_morning_opt = extract_date(&result_morning);
        assert!(
            date_morning_opt.is_some(),
            "failed to extract date from Credential: {result_morning}"
        );
        let Some(date_morning) = date_morning_opt else {
            return;
        };

        let date_evening_opt = extract_date(&result_evening);
        assert!(
            date_evening_opt.is_some(),
            "failed to extract date from Credential: {result_evening}"
        );
        let Some(date_evening) = date_evening_opt else {
            return;
        };

        assert_eq!(
            date_morning, date_evening,
            "timestamps from same day should produce same date"
        );
        assert_eq!(date_morning, "2024-01-15");

        // Timestamps on different days (2024-01-16 UTC)
        let ts_next_day = 1_705_392_000; // 2024-01-16 08:00:00 UTC
        let result_next_day = p.sign("DescribeRecordList", "{}", ts_next_day);
        let date_next_day_opt = extract_date(&result_next_day);
        assert!(
            date_next_day_opt.is_some(),
            "failed to extract date from Credential: {result_next_day}"
        );
        let Some(date_next_day) = date_next_day_opt else {
            return;
        };

        assert_ne!(
            date_morning, date_next_day,
            "timestamps from different days should produce different dates"
        );
        assert_eq!(date_next_day, "2024-01-16");
    }
}
