//! 阿里云 ACS3-HMAC-SHA256 签名

use sha2::{Digest, Sha256};

use crate::providers::common::hmac_sha256;

use super::{ALIYUN_DNS_HOST, ALIYUN_DNS_VERSION, AliyunProvider, EMPTY_BODY_SHA256};

impl AliyunProvider {
    /// 生成 ACS3-HMAC-SHA256 签名
    /// 参考: <https://www.alibabacloud.com/help/zh/sdk/product-overview/v3-request-structure-and-signature>
    pub(crate) fn sign(
        &self,
        action: &str,
        query_string: &str,
        timestamp: &str,
        nonce: &str,
    ) -> String {
        // 1. 构造规范化请求头 (使用空 body 的 hash)
        let canonical_headers = format!(
            "host:{ALIYUN_DNS_HOST}\nx-acs-action:{action}\nx-acs-content-sha256:{EMPTY_BODY_SHA256}\nx-acs-date:{timestamp}\nx-acs-signature-nonce:{nonce}\nx-acs-version:{ALIYUN_DNS_VERSION}\n"
        );

        let signed_headers =
            "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version";

        // 2. 构造规范化请求 (RPC 风格: 参数在 query string 中)
        let canonical_request = format!(
            "POST\n/\n{query_string}\n{canonical_headers}\n{signed_headers}\n{EMPTY_BODY_SHA256}"
        );

        log::debug!("CanonicalRequest:\n{canonical_request}");

        // 3. 构造待签名字符串
        let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = format!("ACS3-HMAC-SHA256\n{hashed_canonical_request}");

        log::debug!("StringToSign:\n{string_to_sign}");

        // 4. 计算签名
        let signature = hex::encode(hmac_sha256(
            self.access_key_secret.as_bytes(),
            string_to_sign.as_bytes(),
        ));

        // 5. 构造 Authorization 头
        format!(
            "ACS3-HMAC-SHA256 Credential={},SignedHeaders={},Signature={}",
            self.access_key_id, signed_headers, signature
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::AliyunProvider;

    /// 辅助函数: 创建测试用 AliyunProvider
    fn make_provider(key_id: &str, key_secret: &str) -> AliyunProvider {
        AliyunProvider::new(key_id.to_string(), key_secret.to_string())
    }

    /// 辅助函数: 从签名输出中提取 Signature= 部分的值
    fn extract_signature(auth: &str) -> &str {
        auth.split("Signature=")
            .nth(1)
            .expect("missing Signature= in output")
    }

    // ============ 签名格式测试 ============

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

        let credential = result
            .split("Credential=")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .expect("failed to extract Credential value");

        assert_eq!(
            credential, key_id,
            "Credential should equal access_key_id"
        );
    }

    #[test]
    fn sign_signed_headers_complete() {
        let provider = make_provider("key-id", "key-secret");
        let result = provider.sign("DescribeDomains", "", "2024-01-01T00:00:00Z", "nonce-1");

        let signed_headers = result
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .expect("failed to extract SignedHeaders value");

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

        // 确认恰好有 6 个 header（用分号分隔）
        let count = signed_headers.split(';').count();
        assert_eq!(count, 6, "SignedHeaders should contain exactly 6 headers, got {count}");
    }

    #[test]
    fn sign_deterministic() {
        let provider = make_provider("key-id", "key-secret");
        let result1 = provider.sign("DescribeDomains", "DomainName=example.com", "2024-01-01T00:00:00Z", "nonce-1");
        let result2 = provider.sign("DescribeDomains", "DomainName=example.com", "2024-01-01T00:00:00Z", "nonce-1");

        assert_eq!(result1, result2, "same inputs should produce identical output");
    }

    #[test]
    fn sign_different_action_changes_signature() {
        let provider = make_provider("key-id", "key-secret");
        let result_a = provider.sign("DescribeDomains", "", "2024-01-01T00:00:00Z", "nonce-1");
        let result_b = provider.sign("DescribeDomainRecords", "", "2024-01-01T00:00:00Z", "nonce-1");

        let sig_a = extract_signature(&result_a);
        let sig_b = extract_signature(&result_b);

        assert_ne!(sig_a, sig_b, "different actions should produce different signatures");
    }

    #[test]
    fn sign_different_secret_changes_signature() {
        let provider_a = make_provider("same-key-id", "secret-one");
        let provider_b = make_provider("same-key-id", "secret-two");

        let result_a = provider_a.sign("DescribeDomains", "", "2024-01-01T00:00:00Z", "nonce-1");
        let result_b = provider_b.sign("DescribeDomains", "", "2024-01-01T00:00:00Z", "nonce-1");

        let sig_a = extract_signature(&result_a);
        let sig_b = extract_signature(&result_b);

        assert_ne!(sig_a, sig_b, "different secrets should produce different signatures");
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

        // 验证整体格式
        assert!(result.starts_with("ACS3-HMAC-SHA256 "));

        // 提取并验证 Signature 是有效的 hex 字符串 (SHA256 HMAC = 64 hex chars)
        let signature = extract_signature(&result);
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

        // 回归快照: 固定输入应始终产生相同的完整输出
        // 此值通过首次运行测试确定，后续任何签名逻辑变更都会被捕获
        let expected = "ACS3-HMAC-SHA256 \
             Credential=LTAI5tTestKeyId,\
             SignedHeaders=host;x-acs-action;x-acs-content-sha256;\
             x-acs-date;x-acs-signature-nonce;x-acs-version,\
             Signature=9c4173ede0946854e402679d086862a853ada5d1b83c34216ede75a499d50afd";
        assert_eq!(result, expected, "snapshot regression: full output changed");
    }
}
