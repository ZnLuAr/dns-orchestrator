//! Huawei Cloud SDK-HMAC-SHA256 signature

use std::fmt::Write;

use sha2::{Digest, Sha256};

use crate::providers::common::hmac_sha256;
use crate::utils::log_sanitizer::truncate_for_log;

use super::HuaweicloudProvider;

impl HuaweicloudProvider {
    /// Generate Huawei Cloud SDK signature
    /// Reference: <https://support.huaweicloud.com/devg-apisign/api-sign-algorithm-005.html>
    pub(crate) fn sign(
        &self,
        method: &str,
        uri: &str,
        query: &str,
        headers: &[(String, String)],
        payload: &str,
        timestamp: &str,
    ) -> String {
        // 1. URI normalization: make sure it ends with "/"
        let canonical_uri = if uri.ends_with('/') {
            uri.to_string()
        } else {
            format!("{uri}/")
        };

        // 2. Query String sorting (in ascending order by parameter name)
        let canonical_query = if query.is_empty() {
            String::new()
        } else {
            let mut params: Vec<&str> = query.split('&').collect();
            params.sort_unstable();
            params.join("&")
        };

        // 3. Construct the standard request header
        let mut sorted_headers: Vec<_> = headers.iter().collect();
        sorted_headers.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

        let canonical_headers: String =
            sorted_headers
                .iter()
                .fold(String::new(), |mut acc, (k, v)| {
                    let _ = writeln!(acc, "{}:{}", k.to_lowercase(), v.trim());
                    acc
                });

        let signed_headers: String = sorted_headers
            .iter()
            .map(|(k, _)| k.to_lowercase())
            .collect::<Vec<_>>()
            .join(";");

        // 4. Calculate payload hash
        let hashed_payload = hex::encode(Sha256::digest(payload.as_bytes()));

        // 5. Construct a specification request
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{hashed_payload}"
        );

        log::debug!("CanonicalRequest:\n{}", truncate_for_log(&canonical_request));

        // 6. Construct the string to be signed (3-line format)
        let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = format!("SDK-HMAC-SHA256\n{timestamp}\n{hashed_canonical_request}");

        log::debug!("StringToSign:\n{string_to_sign}");

        // 7. Calculate signature (use SK directly)
        let signature = hex::encode(hmac_sha256(
            self.secret_access_key.as_bytes(),
            string_to_sign.as_bytes(),
        ));

        // 8. Construct the Authorization header (correct format: Access=xxx)
        format!(
            "SDK-HMAC-SHA256 Access={}, SignedHeaders={}, Signature={}",
            self.access_key_id, signed_headers, signature
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::HuaweicloudProvider;

    /// Create a test provider
    fn provider() -> HuaweicloudProvider {
        HuaweicloudProvider::new("test-ak".to_string(), "test-sk".to_string())
    }

    /// Create a provider for the specified key
    fn provider_with_keys(ak: &str, sk: &str) -> HuaweicloudProvider {
        HuaweicloudProvider::new(ak.to_string(), sk.to_string())
    }

    /// Default test parameters
    fn default_headers() -> Vec<(String, String)> {
        vec![
            ("Host".to_string(), "dns.myhuaweicloud.com".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ]
    }

    /// Extract the value of an Access field from the signature result
    fn extract_access(auth: &str) -> Option<&str> {
        auth.split("Access=")
            .nth(1)
            .and_then(|s| s.split(',').next())
    }

    /// Extract the value of the `SignedHeaders` field from the signature result
    fn extract_signed_headers(auth: &str) -> Option<&str> {
        auth.split("SignedHeaders=")
            .nth(1)
            .and_then(|s| s.split(',').next())
    }

    /// Extract the value of the Signature field from the signature result
    fn extract_signature(auth: &str) -> Option<&str> {
        auth.split("Signature=").nth(1)
    }

    // ============ Output format verification ============

    #[test]
    fn sign_output_format() {
        let p = provider();
        let result = p.sign(
            "GET",
            "/v2/zones",
            "",
            &default_headers(),
            "",
            "20240101T000000Z",
        );

        assert!(
            result.starts_with("SDK-HMAC-SHA256 "),
            "output should start with 'SDK-HMAC-SHA256 '"
        );
        assert!(
            result.contains("Access="),
            "output should contain 'Access='"
        );
        assert!(
            result.contains("SignedHeaders="),
            "output should contain 'SignedHeaders='"
        );
        assert!(
            result.contains("Signature="),
            "output should contain 'Signature='"
        );
    }

    // ============ Access field validation ============

    #[test]
    fn sign_access_matches_key_id() {
        let p = provider_with_keys("MY-ACCESS-KEY-ID", "some-secret");
        let result = p.sign(
            "GET",
            "/v2/zones",
            "",
            &default_headers(),
            "",
            "20240101T000000Z",
        );

        let access_opt = extract_access(&result);
        assert!(access_opt.is_some(), "Access field not found: {result}");
        let Some(access) = access_opt else {
            return;
        };
        assert_eq!(access, "MY-ACCESS-KEY-ID");
    }

    // ============ Deterministic Verification ============

    #[test]
    fn sign_deterministic() {
        let p = provider();
        let headers = default_headers();
        let result1 = p.sign(
            "GET",
            "/v2/zones",
            "a=1",
            &headers,
            "body",
            "20240101T000000Z",
        );
        let result2 = p.sign(
            "GET",
            "/v2/zones",
            "a=1",
            &headers,
            "body",
            "20240101T000000Z",
        );

        assert_eq!(result1, result2, "same inputs should produce same output");
    }

    // ============ URI canonicalization verification ============

    #[test]
    fn sign_uri_normalization_trailing_slash() {
        let p = provider();
        let headers = default_headers();

        let without_slash = p.sign("GET", "/v2/zones", "", &headers, "", "20240101T000000Z");
        let with_slash = p.sign("GET", "/v2/zones/", "", &headers, "", "20240101T000000Z");

        let sig_without_opt = extract_signature(&without_slash);
        assert!(
            sig_without_opt.is_some(),
            "Signature field not found: {without_slash}"
        );
        let Some(sig_without) = sig_without_opt else {
            return;
        };

        let sig_with_opt = extract_signature(&with_slash);
        assert!(
            sig_with_opt.is_some(),
            "Signature field not found: {with_slash}"
        );
        let Some(sig_with) = sig_with_opt else {
            return;
        };
        assert_eq!(
            sig_without, sig_with,
            "URI with and without trailing slash should produce same signature"
        );
    }

    // ============ Query String Sorting Verification ============

    #[test]
    fn sign_query_string_sorting() {
        let p = provider();
        let headers = default_headers();

        let unsorted = p.sign(
            "GET",
            "/v2/zones",
            "b=2&a=1",
            &headers,
            "",
            "20240101T000000Z",
        );
        let sorted = p.sign(
            "GET",
            "/v2/zones",
            "a=1&b=2",
            &headers,
            "",
            "20240101T000000Z",
        );

        let sig_unsorted_opt = extract_signature(&unsorted);
        assert!(
            sig_unsorted_opt.is_some(),
            "Signature field not found: {unsorted}"
        );
        let Some(sig_unsorted) = sig_unsorted_opt else {
            return;
        };

        let sig_sorted_opt = extract_signature(&sorted);
        assert!(
            sig_sorted_opt.is_some(),
            "Signature field not found: {sorted}"
        );
        let Some(sig_sorted) = sig_sorted_opt else {
            return;
        };
        assert_eq!(
            sig_unsorted, sig_sorted,
            "'b=2&a=1' and 'a=1&b=2' should produce same signature"
        );
    }

    // ============ Headers sorting verification ============

    #[test]
    fn sign_headers_sorted_by_key() {
        let p = provider();
        let headers = vec![
            ("X-Header".to_string(), "1".to_string()),
            ("A-Header".to_string(), "2".to_string()),
        ];

        let result = p.sign("GET", "/v2/zones", "", &headers, "", "20240101T000000Z");

        let signed_headers_opt = extract_signed_headers(&result);
        assert!(
            signed_headers_opt.is_some(),
            "SignedHeaders field not found: {result}"
        );
        let Some(signed_headers) = signed_headers_opt else {
            return;
        };
        assert_eq!(
            signed_headers, "a-header;x-header",
            "SignedHeaders should be lowercase and sorted alphabetically"
        );
    }

    // ============ Empty Query String Validation ============

    #[test]
    fn sign_empty_query() {
        let p = provider();
        let result = p.sign(
            "GET",
            "/v2/zones",
            "",
            &default_headers(),
            "payload",
            "20240101T000000Z",
        );

        let signature_opt = extract_signature(&result);
        assert!(
            signature_opt.is_some(),
            "Signature field not found: {result}"
        );
        let Some(signature) = signature_opt else {
            return;
        };
        assert!(
            result.starts_with("SDK-HMAC-SHA256 "),
            "empty query should still produce valid signature"
        );
        assert!(!signature.is_empty(), "signature should not be empty");
    }

    // ============ Empty Payload Verification ============

    #[test]
    fn sign_empty_payload() {
        let p = provider();
        let result = p.sign(
            "GET",
            "/v2/zones",
            "a=1",
            &default_headers(),
            "",
            "20240101T000000Z",
        );

        let signature_opt = extract_signature(&result);
        assert!(
            signature_opt.is_some(),
            "Signature field not found: {result}"
        );
        let Some(signature) = signature_opt else {
            return;
        };
        assert!(
            result.starts_with("SDK-HMAC-SHA256 "),
            "empty payload should still produce valid signature"
        );
        assert!(!signature.is_empty(), "signature should not be empty");
    }

    // ============ Different HTTP Methods produce different signatures ============

    #[test]
    fn sign_different_method_changes_signature() {
        let p = provider();
        let headers = default_headers();

        let get_sig = p.sign("GET", "/v2/zones", "", &headers, "", "20240101T000000Z");
        let post_sig = p.sign("POST", "/v2/zones", "", &headers, "", "20240101T000000Z");

        let get_signature_opt = extract_signature(&get_sig);
        assert!(
            get_signature_opt.is_some(),
            "Signature field not found: {get_sig}"
        );
        let Some(get_signature) = get_signature_opt else {
            return;
        };

        let post_signature_opt = extract_signature(&post_sig);
        assert!(
            post_signature_opt.is_some(),
            "Signature field not found: {post_sig}"
        );
        let Some(post_signature) = post_signature_opt else {
            return;
        };
        assert_ne!(
            get_signature, post_signature,
            "GET and POST should produce different signatures"
        );
    }

    // ============ Different Secrets generate different signatures ============

    #[test]
    fn sign_different_secret_changes_signature() {
        let p1 = provider_with_keys("same-ak", "secret-one");
        let p2 = provider_with_keys("same-ak", "secret-two");
        let headers = default_headers();

        let sig1 = p1.sign("GET", "/v2/zones", "", &headers, "", "20240101T000000Z");
        let sig2 = p2.sign("GET", "/v2/zones", "", &headers, "", "20240101T000000Z");

        let signature_1_opt = extract_signature(&sig1);
        assert!(
            signature_1_opt.is_some(),
            "Signature field not found: {sig1}"
        );
        let Some(signature_1) = signature_1_opt else {
            return;
        };

        let signature_2_opt = extract_signature(&sig2);
        assert!(
            signature_2_opt.is_some(),
            "Signature field not found: {sig2}"
        );
        let Some(signature_2) = signature_2_opt else {
            return;
        };
        assert_ne!(
            signature_1, signature_2,
            "different secrets should produce different signatures"
        );
    }
}
