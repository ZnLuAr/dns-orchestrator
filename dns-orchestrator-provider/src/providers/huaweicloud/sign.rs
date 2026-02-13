//! 华为云 SDK-HMAC-SHA256 签名

use std::fmt::Write;

use sha2::{Digest, Sha256};

use crate::providers::common::hmac_sha256;

use super::HuaweicloudProvider;

impl HuaweicloudProvider {
    /// 生成华为云 SDK 签名
    /// 参考: <https://support.huaweicloud.com/devg-apisign/api-sign-algorithm-005.html>
    pub(crate) fn sign(
        &self,
        method: &str,
        uri: &str,
        query: &str,
        headers: &[(String, String)],
        payload: &str,
        timestamp: &str,
    ) -> String {
        // 1. URI 规范化：确保以 "/" 结尾
        let canonical_uri = if uri.ends_with('/') {
            uri.to_string()
        } else {
            format!("{uri}/")
        };

        // 2. Query String 排序（按参数名升序）
        let canonical_query = if query.is_empty() {
            String::new()
        } else {
            let mut params: Vec<&str> = query.split('&').collect();
            params.sort_unstable();
            params.join("&")
        };

        // 3. 构造规范请求头
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

        // 4. 计算 payload hash
        let hashed_payload = hex::encode(Sha256::digest(payload.as_bytes()));

        // 5. 构造规范请求
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{hashed_payload}"
        );

        log::debug!("CanonicalRequest:\n{canonical_request}");

        // 6. 构造待签名字符串（3 行格式）
        let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = format!("SDK-HMAC-SHA256\n{timestamp}\n{hashed_canonical_request}");

        log::debug!("StringToSign:\n{string_to_sign}");

        // 7. 计算签名（直接用 SK）
        let signature = hex::encode(hmac_sha256(
            self.secret_access_key.as_bytes(),
            string_to_sign.as_bytes(),
        ));

        // 8. 构造 Authorization 头（正确格式：Access=xxx）
        format!(
            "SDK-HMAC-SHA256 Access={}, SignedHeaders={}, Signature={}",
            self.access_key_id, signed_headers, signature
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::HuaweicloudProvider;

    /// 创建测试用 provider
    fn provider() -> HuaweicloudProvider {
        HuaweicloudProvider::new("test-ak".to_string(), "test-sk".to_string())
    }

    /// 创建指定密钥的 provider
    fn provider_with_keys(ak: &str, sk: &str) -> HuaweicloudProvider {
        HuaweicloudProvider::new(ak.to_string(), sk.to_string())
    }

    /// 默认测试参数
    fn default_headers() -> Vec<(String, String)> {
        vec![
            ("Host".to_string(), "dns.myhuaweicloud.com".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ]
    }

    /// 从签名结果中提取 Access 字段的值
    fn extract_access(auth: &str) -> &str {
        auth.split("Access=")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .expect("Access field not found")
    }

    /// 从签名结果中提取 `SignedHeaders` 字段的值
    fn extract_signed_headers(auth: &str) -> &str {
        auth.split("SignedHeaders=")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .expect("SignedHeaders field not found")
    }

    /// 从签名结果中提取 Signature 字段的值
    fn extract_signature(auth: &str) -> &str {
        auth.split("Signature=")
            .nth(1)
            .expect("Signature field not found")
    }

    // ============ 输出格式验证 ============

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

    // ============ Access 字段验证 ============

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

        assert_eq!(extract_access(&result), "MY-ACCESS-KEY-ID");
    }

    // ============ 确定性验证 ============

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

    // ============ URI 规范化验证 ============

    #[test]
    fn sign_uri_normalization_trailing_slash() {
        let p = provider();
        let headers = default_headers();

        let without_slash = p.sign("GET", "/v2/zones", "", &headers, "", "20240101T000000Z");
        let with_slash = p.sign("GET", "/v2/zones/", "", &headers, "", "20240101T000000Z");

        assert_eq!(
            extract_signature(&without_slash),
            extract_signature(&with_slash),
            "URI with and without trailing slash should produce same signature"
        );
    }

    // ============ Query String 排序验证 ============

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

        assert_eq!(
            extract_signature(&unsorted),
            extract_signature(&sorted),
            "'b=2&a=1' and 'a=1&b=2' should produce same signature"
        );
    }

    // ============ Headers 排序验证 ============

    #[test]
    fn sign_headers_sorted_by_key() {
        let p = provider();
        let headers = vec![
            ("X-Header".to_string(), "1".to_string()),
            ("A-Header".to_string(), "2".to_string()),
        ];

        let result = p.sign("GET", "/v2/zones", "", &headers, "", "20240101T000000Z");

        assert_eq!(
            extract_signed_headers(&result),
            "a-header;x-header",
            "SignedHeaders should be lowercase and sorted alphabetically"
        );
    }

    // ============ 空 Query String 验证 ============

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

        assert!(
            result.starts_with("SDK-HMAC-SHA256 "),
            "empty query should still produce valid signature"
        );
        assert!(
            !extract_signature(&result).is_empty(),
            "signature should not be empty"
        );
    }

    // ============ 空 Payload 验证 ============

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

        assert!(
            result.starts_with("SDK-HMAC-SHA256 "),
            "empty payload should still produce valid signature"
        );
        assert!(
            !extract_signature(&result).is_empty(),
            "signature should not be empty"
        );
    }

    // ============ 不同 HTTP Method 产生不同签名 ============

    #[test]
    fn sign_different_method_changes_signature() {
        let p = provider();
        let headers = default_headers();

        let get_sig = p.sign("GET", "/v2/zones", "", &headers, "", "20240101T000000Z");
        let post_sig = p.sign("POST", "/v2/zones", "", &headers, "", "20240101T000000Z");

        assert_ne!(
            extract_signature(&get_sig),
            extract_signature(&post_sig),
            "GET and POST should produce different signatures"
        );
    }

    // ============ 不同 Secret 产生不同签名 ============

    #[test]
    fn sign_different_secret_changes_signature() {
        let p1 = provider_with_keys("same-ak", "secret-one");
        let p2 = provider_with_keys("same-ak", "secret-two");
        let headers = default_headers();

        let sig1 = p1.sign("GET", "/v2/zones", "", &headers, "", "20240101T000000Z");
        let sig2 = p2.sign("GET", "/v2/zones", "", &headers, "", "20240101T000000Z");

        assert_ne!(
            extract_signature(&sig1),
            extract_signature(&sig2),
            "different secrets should produce different signatures"
        );
    }
}
