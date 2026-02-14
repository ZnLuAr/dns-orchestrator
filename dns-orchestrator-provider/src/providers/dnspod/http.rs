//! `DNSPod` HTTP 请求方法（重构版：使用通用 HTTP 工具）

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{ProviderError, Result};
use crate::http_client::HttpUtils;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

use super::{DNSPOD_API_HOST, DNSPOD_VERSION, DnspodProvider, TencentError, TencentResponse};

impl DnspodProvider {
    /// 执行腾讯云 API 请求
    pub(crate) async fn request<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        action: &str,
        body: &B,
        ctx: ErrorContext,
    ) -> Result<T> {
        // 1. 序列化请求体
        let payload =
            serde_json::to_string(body).map_err(|e| ProviderError::SerializationError {
                provider: self.provider_name().to_string(),
                detail: e.to_string(),
            })?;

        log::debug!("Request Body: {payload}");

        // 2. 生成签名
        let timestamp = Utc::now().timestamp();
        let authorization = self.sign(action, &payload, timestamp);

        // 3. 发送请求（使用 HttpUtils）
        let url = format!("https://{DNSPOD_API_HOST}");
        let request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Host", DNSPOD_API_HOST)
            .header("X-TC-Action", action)
            .header("X-TC-Version", DNSPOD_VERSION)
            .header("X-TC-Timestamp", timestamp.to_string())
            .header("Authorization", authorization)
            .body(payload);

        let (_status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            "POST",
            &format!("Action: {action}"),
            self.max_retries,
        )
        .await?;

        // 4. 解析外层包装
        let tc_response: TencentResponse =
            HttpUtils::parse_json(&response_text, self.provider_name())?;
        let response_value = tc_response.response;

        // 5. 检查错误
        if let Some(error_value) = response_value.get("Error") {
            let error: TencentError = serde_json::from_value(error_value.clone())
                .map_err(|e| self.parse_error(format!("Failed to parse error: {e}")))?;
            log::error!("API error: {} - {}", error.code, error.message);
            return Err(self.map_error(RawApiError::with_code(&error.code, &error.message), ctx));
        }

        // 6. 反序列化为目标类型
        serde_json::from_value(response_value).map_err(|e| ProviderError::ParseError {
            provider: self.provider_name().to_string(),
            detail: e.to_string(),
        })
    }
}
