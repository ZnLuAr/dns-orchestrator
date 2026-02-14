//! 阿里云 HTTP 请求方法（重构版：使用通用 HTTP 工具）

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{ProviderError, Result};
use crate::http_client::HttpUtils;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

use super::{
    ALIYUN_DNS_HOST, ALIYUN_DNS_VERSION, AliyunProvider, EMPTY_BODY_SHA256,
    serialize_to_query_string,
};

impl AliyunProvider {
    /// 执行阿里云 API 请求 (RPC 风格: 参数通过 query string 传递)
    pub(crate) async fn request<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        action: &str,
        params: &B,
        ctx: ErrorContext,
    ) -> Result<T> {
        // 1. 序列化参数为 query string
        let query_string = serialize_to_query_string(params)?;

        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = uuid::Uuid::new_v4().to_string();

        // 2. 生成签名 (使用 query string)
        let authorization = self.sign(action, &query_string, &timestamp, &nonce);

        // 3. 构造 URL (参数在 query string 中)
        let url = if query_string.is_empty() {
            format!("https://{ALIYUN_DNS_HOST}/")
        } else {
            format!("https://{ALIYUN_DNS_HOST}/?{query_string}")
        };

        // 4. 发送请求 (body 为空，使用 HttpUtils)
        let request = self
            .client
            .post(&url)
            .header("Host", ALIYUN_DNS_HOST)
            .header("x-acs-action", action)
            .header("x-acs-version", ALIYUN_DNS_VERSION)
            .header("x-acs-date", &timestamp)
            .header("x-acs-signature-nonce", &nonce)
            .header("x-acs-content-sha256", EMPTY_BODY_SHA256)
            .header("Authorization", authorization);

        let (_status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            "POST",
            &format!("{url} (Action: {action})"),
            self.max_retries,
        )
        .await?;

        // 5. 解析为 Value（只做一次字符串解析）
        let value: serde_json::Value = HttpUtils::parse_json(&response_text, self.provider_name())?;

        // 6. 检查错误
        if let (Some(code), Some(message)) = (
            value.get("Code").and_then(|v| v.as_str()),
            value.get("Message").and_then(|v| v.as_str()),
        ) {
            log::error!("API error: {code} - {message}");
            return Err(self.map_error(RawApiError::with_code(code, message), ctx));
        }

        // 7. 转换为目标类型（Value → T，不需要重新 tokenize）
        serde_json::from_value(value).map_err(|e| ProviderError::ParseError {
            provider: self.provider_name().to_string(),
            detail: e.to_string(),
        })
    }
}
