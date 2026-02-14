//! `DNSPod` HTTP 请求方法（重构版：使用通用 HTTP 工具）

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{ProviderError, Result};
use crate::http_client::HttpUtils;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

use super::{DNSPOD_API_HOST, DNSPOD_VERSION, DnspodProvider, TencentResponse};

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

        // 4. 解析响应
        let tc_response: TencentResponse<T> =
            HttpUtils::parse_json(&response_text, self.provider_name())?;

        // 5. 处理错误
        if let Some(error) = tc_response.response.error {
            log::error!("API error: {} - {}", error.code, error.message);
            return Err(self.map_error(RawApiError::with_code(&error.code, &error.message), ctx));
        }

        // 6. 提取数据
        tc_response
            .response
            .data
            .ok_or_else(|| self.parse_error("Missing data in response"))
    }
}
