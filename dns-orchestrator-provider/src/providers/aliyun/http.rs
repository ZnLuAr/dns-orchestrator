//! Alibaba Cloud HTTP request method (reconstructed version: using general HTTP tools)

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
    /// Execute Alibaba Cloud API request (RPC style: parameters are passed through query string)
    pub(crate) async fn request<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        action: &str,
        params: &B,
        ctx: ErrorContext,
    ) -> Result<T> {
        // 1. The serialization parameter is query string
        let query_string = serialize_to_query_string(params)?;

        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = uuid::Uuid::new_v4().to_string();

        // 2. Generate signature (using query string)
        let authorization = self.sign(action, &query_string, &timestamp, &nonce);

        // 3. Construct URL (parameters are in query string)
        let url = if query_string.is_empty() {
            format!("https://{ALIYUN_DNS_HOST}/")
        } else {
            format!("https://{ALIYUN_DNS_HOST}/?{query_string}")
        };

        // 4. Send request (body is empty, use HttpUtils)
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

        let (status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            "POST",
            &format!("{url} (Action: {action})"),
            self.max_retries,
        )
        .await?;

        // For HTTP 4xx/5xx errors, try parsing the JSON error body
        if status >= 400 {
            // Try to parse to Value and extract Code/Message
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&response_text)
                && let (Some(code), Some(message)) = (
                    value.get("Code").and_then(|v| v.as_str()),
                    value.get("Message").and_then(|v| v.as_str()),
                )
            {
                log::error!("API error: {code} - {message}");
                return Err(self.map_error(RawApiError::with_code(code, message), ctx));
            }
            // Unable to resolve as structured error, returns generic NetworkError
            return Err(ProviderError::NetworkError {
                provider: self.provider_name().to_string(),
                detail: format!("HTTP {status}: {response_text}"),
            });
        }

        // 5. Parse to Value (only perform string parsing once)
        let value: serde_json::Value = HttpUtils::parse_json(&response_text, self.provider_name())?;

        // 6. Check for errors
        if let (Some(code), Some(message)) = (
            value.get("Code").and_then(|v| v.as_str()),
            value.get("Message").and_then(|v| v.as_str()),
        ) {
            log::error!("API error: {code} - {message}");
            return Err(self.map_error(RawApiError::with_code(code, message), ctx));
        }

        // 7. Convert to target type (Value → T, no need to re-tokenize)
        serde_json::from_value(value).map_err(|e| ProviderError::ParseError {
            provider: self.provider_name().to_string(),
            detail: e.to_string(),
        })
    }
}
