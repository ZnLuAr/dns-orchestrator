//! `DNSPod` TC3-HMAC-SHA256 签名

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::providers::common::hmac_sha256;

use super::{DNSPOD_API_HOST, DNSPOD_SERVICE, DnspodProvider};

impl DnspodProvider {
    /// 生成 TC3-HMAC-SHA256 签名
    pub(crate) fn sign(&self, action: &str, payload: &str, timestamp: i64) -> String {
        let date = DateTime::from_timestamp(timestamp, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%d")
            .to_string();

        // 1. 拼接规范请求串
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

        // 2. 拼接待签名字符串
        let algorithm = "TC3-HMAC-SHA256";
        let credential_scope = format!("{date}/{DNSPOD_SERVICE}/tc3_request");
        let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign =
            format!("{algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}");

        // 3. 计算签名
        let secret_date = hmac_sha256(
            format!("TC3{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let secret_service = hmac_sha256(&secret_date, DNSPOD_SERVICE.as_bytes());
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
        let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

        // 4. 拼接 Authorization
        format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm, self.secret_id, credential_scope, signed_headers, signature
        )
    }
}
