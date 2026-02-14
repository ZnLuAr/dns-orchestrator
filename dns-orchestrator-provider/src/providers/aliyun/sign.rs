//! Alibaba Cloud ACS3-HMAC-SHA256 signature

use sha2::{Digest, Sha256};

use crate::providers::common::hmac_sha256;
use crate::utils::log_sanitizer::truncate_for_log;

use super::{ALIYUN_DNS_HOST, ALIYUN_DNS_VERSION, AliyunProvider, EMPTY_BODY_SHA256};

impl AliyunProvider {
    /// Generate ACS3-HMAC-SHA256 signature
    /// Reference: <https://www.alibabacloud.com/help/zh/sdk/product-overview/v3-request-structure-and-signature>
    pub(crate) fn sign(
        &self,
        action: &str,
        query_string: &str,
        timestamp: &str,
        nonce: &str,
    ) -> String {
        // 1. Construct a normalized request header (use hash of empty body)
        let canonical_headers = format!(
            "host:{ALIYUN_DNS_HOST}\nx-acs-action:{action}\nx-acs-content-sha256:{EMPTY_BODY_SHA256}\nx-acs-date:{timestamp}\nx-acs-signature-nonce:{nonce}\nx-acs-version:{ALIYUN_DNS_VERSION}\n"
        );

        let signed_headers =
            "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version";

        // 2. Construct a standardized request (RPC style: parameters are in query string)
        let canonical_request = format!(
            "POST\n/\n{query_string}\n{canonical_headers}\n{signed_headers}\n{EMPTY_BODY_SHA256}"
        );

        log::debug!(
            "CanonicalRequest:\n{}",
            truncate_for_log(&canonical_request)
        );

        // 3. Construct the string to be signed
        let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = format!("ACS3-HMAC-SHA256\n{hashed_canonical_request}");

        log::debug!("StringToSign:\n{string_to_sign}");

        // 4. Calculate signature
        let signature = hex::encode(hmac_sha256(
            self.access_key_secret.as_bytes(),
            string_to_sign.as_bytes(),
        ));

        // 5. Construct the Authorization header
        format!(
            "ACS3-HMAC-SHA256 Credential={},SignedHeaders={},Signature={}",
            self.access_key_id, signed_headers, signature
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::AliyunProvider;

    /// Auxiliary function: create `AliyunProvider` for testing
    fn make_provider(key_id: &str, key_secret: &str) -> AliyunProvider {
        AliyunProvider::new(key_id.to_string(), key_secret.to_string())
    }

    /// Helper function: Extract the value of the Signature= part from the signature output
    fn extract_signature(auth: &str) -> Option<&str> {
        auth.split("Signature=").nth(1)
    }

    /// Helper function: Extract the value after `key=` and before the comma from the signature output.
    fn extract_csv_field<'a>(auth: &'a str, key: &str) -> Option<&'a str> {
        auth.split(key).nth(1).and_then(|s| s.split(',').next())
    }

    // ============ Signature format test ============

    #[test]
    fn sign_output_format() {
        let provider = make_provider("test-key-id", "test-key-secret");
        let result = provider.sign("DescribeDomains", "", "2024-01-01T00:00:00Z", "nonce-1");

        assert!(
            result.starts_with("ACS3-HMAC-SHA256 "),
            "output should start with 'ACS3-HMAC-SHA256 ', got: {result}"
        );
        assert!(
            result.contains("Credential="),
            "output should contain 'Credential=', got: {result}"
        );
        assert!(
            result.contains("SignedHeaders="),
            "output should contain 'SignedHeaders=', got: {result}"
        );
        assert!(
            result.contains("Signature="),
            "output should contain 'Signature=', got: {result}"
        );
    }

    #[test]
    fn sign_credential_matches_access_key_id() {
        let key_id = "LTAI5tMyTestKeyId";
        let provider = make_provider(key_id, "some-secret");
        let result = provider.sign("DescribeDomains", "", "2024-01-01T00:00:00Z", "nonce-1");

        let credential_opt = extract_csv_field(&result, "Credential=");
        assert!(
            credential_opt.is_some(),
            "failed to extract Credential value: {result}"
        );
        let Some(credential) = credential_opt else {
            return;
        };

        assert_eq!(credential, key_id, "Credential should equal access_key_id");
    }

    #[test]
    fn sign_signed_headers_complete() {
        let provider = make_provider("key-id", "key-secret");
        let result = provider.sign("DescribeDomains", "", "2024-01-01T00:00:00Z", "nonce-1");

        let signed_headers_opt = extract_csv_field(&result, "SignedHeaders=");
        assert!(
            signed_headers_opt.is_some(),
            "failed to extract SignedHeaders value: {result}"
        );
        let Some(signed_headers) = signed_headers_opt else {
            return;
        };

        let expected_headers = [
            "host",
            "x-acs-action",
            "x-acs-content-sha256",
            "x-acs-date",
            "x-acs-signature-nonce",
            "x-acs-version",
        ];

        for header in &expected_headers {
            assert!(
                signed_headers.contains(header),
                "SignedHeaders should contain '{header}', got: {signed_headers}"
            );
        }

        // Make sure there are exactly 6 headers (separated by semicolons)
        let count = signed_headers.split(';').count();
        assert_eq!(
            count, 6,
            "SignedHeaders should contain exactly 6 headers, got {count}"
        );
    }

    #[test]
    fn sign_deterministic() {
        let provider = make_provider("key-id", "key-secret");
        let result1 = provider.sign(
            "DescribeDomains",
            "DomainName=example.com",
            "2024-01-01T00:00:00Z",
            "nonce-1",
        );
        let result2 = provider.sign(
            "DescribeDomains",
            "DomainName=example.com",
            "2024-01-01T00:00:00Z",
            "nonce-1",
        );

        assert_eq!(
            result1, result2,
            "same inputs should produce identical output"
        );
    }

    #[test]
    fn sign_different_action_changes_signature() {
        let provider = make_provider("key-id", "key-secret");
        let result_a = provider.sign("DescribeDomains", "", "2024-01-01T00:00:00Z", "nonce-1");
        let result_b = provider.sign(
            "DescribeDomainRecords",
            "",
            "2024-01-01T00:00:00Z",
            "nonce-1",
        );

        let sig_describe_domains_opt = extract_signature(&result_a);
        assert!(
            sig_describe_domains_opt.is_some(),
            "missing Signature= in output: {result_a}"
        );
        let Some(sig_describe_domains) = sig_describe_domains_opt else {
            return;
        };

        let sig_describe_domain_records_opt = extract_signature(&result_b);
        assert!(
            sig_describe_domain_records_opt.is_some(),
            "missing Signature= in output: {result_b}"
        );
        let Some(sig_describe_domain_records) = sig_describe_domain_records_opt else {
            return;
        };

        assert_ne!(
            sig_describe_domains, sig_describe_domain_records,
            "different actions should produce different signatures"
        );
    }

    #[test]
    fn sign_different_secret_changes_signature() {
        let provider_a = make_provider("same-key-id", "secret-one");
        let provider_b = make_provider("same-key-id", "secret-two");

        let result_a = provider_a.sign("DescribeDomains", "", "2024-01-01T00:00:00Z", "nonce-1");
        let result_b = provider_b.sign("DescribeDomains", "", "2024-01-01T00:00:00Z", "nonce-1");

        let sig_secret_one_opt = extract_signature(&result_a);
        assert!(
            sig_secret_one_opt.is_some(),
            "missing Signature= in output: {result_a}"
        );
        let Some(sig_secret_one) = sig_secret_one_opt else {
            return;
        };

        let sig_secret_two_opt = extract_signature(&result_b);
        assert!(
            sig_secret_two_opt.is_some(),
            "missing Signature= in output: {result_b}"
        );
        let Some(sig_secret_two) = sig_secret_two_opt else {
            return;
        };

        assert_ne!(
            sig_secret_one, sig_secret_two,
            "different secrets should produce different signatures"
        );
    }

    #[test]
    fn sign_snapshot() {
        let provider = make_provider("LTAI5tTestKeyId", "TestSecretKey123456");
        let result = provider.sign(
            "DescribeDomainRecords",
            "DomainName=example.com",
            "2024-01-15T08:00:00Z",
            "test-nonce-12345",
        );

        // Verify overall format
        assert!(result.starts_with("ACS3-HMAC-SHA256 "));

        // Extract and verify that the Signature is a valid hex string (SHA256 HMAC = 64 hex chars)
        let signature_opt = extract_signature(&result);
        assert!(
            signature_opt.is_some(),
            "missing Signature= in output: {result}"
        );
        let Some(signature) = signature_opt else {
            return;
        };
        assert_eq!(
            signature.len(),
            64,
            "signature should be 64 hex characters (SHA256), got {} chars: {signature}",
            signature.len()
        );
        assert!(
            signature.chars().all(|c| c.is_ascii_hexdigit()),
            "signature should be valid hex, got: {signature}"
        );

        // Regression snapshot: fixed input should always produce the same complete output
        // This value is determined by running the test for the first time and any subsequent changes to the signature logic will be captured
        let expected = "ACS3-HMAC-SHA256 \
             Credential=LTAI5tTestKeyId,\
             SignedHeaders=host;x-acs-action;x-acs-content-sha256;\
             x-acs-date;x-acs-signature-nonce;x-acs-version,\
             Signature=9c4173ede0946854e402679d086862a853ada5d1b83c34216ede75a499d50afd";
        assert_eq!(result, expected, "snapshot regression: full output changed");
    }
}
