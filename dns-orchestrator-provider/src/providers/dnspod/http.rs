//! `DNSPod` HTTP request method (refactored version: use common HTTP tools)

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{ProviderError, Result};
use crate::http_client::HttpUtils;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};
use crate::utils::log_sanitizer::truncate_for_log;

use super::{DNSPOD_API_HOST, DNSPOD_VERSION, DnspodProvider, TencentError, TencentResponse};

impl DnspodProvider {
    /// Execute Tencent Cloud API request
    pub(crate) async fn request<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        action: &str,
        body: &B,
        ctx: ErrorContext,
    ) -> Result<T> {
        // 1. Serialize request body
        let payload =
            serde_json::to_string(body).map_err(|e| ProviderError::SerializationError {
                provider: self.provider_name().to_string(),
                detail: e.to_string(),
            })?;

        log::debug!("Request Body: {}", truncate_for_log(&payload));

        // 2. Generate signature
        let timestamp = Utc::now().timestamp();
        let authorization = self.sign(action, &payload, timestamp);

        // 3. Send request (using HttpUtils)
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

        // 4. Parse the outer packaging
        let tc_response: TencentResponse =
            HttpUtils::parse_json(&response_text, self.provider_name())?;
        let response_value = tc_response.response;

        // 5. Check for errors
        if let Some(error_value) = response_value.get("Error") {
            let error: TencentError = serde_json::from_value(error_value.clone())
                .map_err(|e| self.parse_error(format!("Failed to parse error: {e}")))?;
            log::error!("API error: {} - {}", error.code, error.message);
            return Err(self.map_error(RawApiError::with_code(&error.code, &error.message), ctx));
        }

        // 6. Deserialize to target type
        serde_json::from_value(response_value).map_err(|e| ProviderError::ParseError {
            provider: self.provider_name().to_string(),
            detail: e.to_string(),
        })
    }
}
