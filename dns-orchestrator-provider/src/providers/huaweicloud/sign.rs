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

        let canonical_headers: String = sorted_headers
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
