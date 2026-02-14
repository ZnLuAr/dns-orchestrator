//! Huawei Cloud HTTP request method (refactored version: eliminating code duplication)

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{ProviderError, Result};
use crate::http_client::HttpUtils;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};
use crate::utils::log_sanitizer::truncate_for_log;

use super::types::ErrorResponse;
use super::{HUAWEICLOUD_DNS_HOST, HuaweicloudProvider};

impl HuaweicloudProvider {
    // ==================== Helper methods ====================

    /// Unified handling of Huawei Cloud response errors
    fn handle_response_error(
        &self,
        status: u16,
        response_text: &str,
        ctx: ErrorContext,
    ) -> Result<()> {
        if (200..300).contains(&status) {
            return Ok(());
        }

        // Try to parse structured errors
        if let Ok(error) = serde_json::from_str::<ErrorResponse>(response_text) {
            return Err(self.map_error(
                RawApiError::with_code(
                    error.code.unwrap_or_else(|| "UNKNOWN".to_string()),
                    error
                        .message
                        .unwrap_or_else(|| "No error message provided by API".to_string()),
                ),
                ctx,
            ));
        }

        // fallback to generic error
        Err(self.unknown_error(RawApiError::new(format!("HTTP {status}: {response_text}"))))
    }

    /// Execute request with body (POST/PUT)
    async fn request_with_body<T, B>(
        &self,
        method: &str,
        path: &str,
        body: &B,
        ctx: ErrorContext,
    ) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize,
    {
        let payload =
            serde_json::to_string(body).map_err(|e| ProviderError::SerializationError {
                provider: self.provider_name().to_string(),
                detail: e.to_string(),
            })?;

        log::debug!("Request Body: {}", truncate_for_log(&payload));

        let now = Utc::now();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();

        let headers = vec![
            ("Host".to_string(), HUAWEICLOUD_DNS_HOST.to_string()),
            ("X-Sdk-Date".to_string(), timestamp.clone()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let authorization = self.sign(method, path, "", &headers, &payload, &timestamp);
        let url = format!("https://{HUAWEICLOUD_DNS_HOST}{path}");

        // Build the request based on method
        let request_builder = match method {
            "POST" => self.client.post(&url),
            "PUT" => self.client.put(&url),
            _ => unreachable!("request_with_body only supports POST/PUT"),
        };

        let request = request_builder
            .header("Host", HUAWEICLOUD_DNS_HOST)
            .header("X-Sdk-Date", &timestamp)
            .header("Content-Type", "application/json")
            .header("Authorization", authorization)
            .body(payload);

        let (status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            method,
            &url,
            self.max_retries,
        )
        .await?;

        self.handle_response_error(status, &response_text, ctx)?;
        HttpUtils::parse_json(&response_text, self.provider_name())
    }

    // ==================== Public API methods ====================

    /// Perform a GET request
    pub(crate) async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &str,
        ctx: ErrorContext,
    ) -> Result<T> {
        let now = Utc::now();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();

        let headers = vec![
            ("Host".to_string(), HUAWEICLOUD_DNS_HOST.to_string()),
            ("X-Sdk-Date".to_string(), timestamp.clone()),
        ];

        let authorization = self.sign("GET", path, query, &headers, "", &timestamp);

        let url = if query.is_empty() {
            format!("https://{HUAWEICLOUD_DNS_HOST}{path}")
        } else {
            format!("https://{HUAWEICLOUD_DNS_HOST}{path}?{query}")
        };

        let request = self
            .client
            .get(&url)
            .header("Host", HUAWEICLOUD_DNS_HOST)
            .header("X-Sdk-Date", &timestamp)
            .header("Authorization", authorization);

        let (status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            "GET",
            &url,
            self.max_retries,
        )
        .await?;

        self.handle_response_error(status, &response_text, ctx)?;
        HttpUtils::parse_json(&response_text, self.provider_name())
    }

    /// Perform a POST request
    pub(crate) async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
        ctx: ErrorContext,
    ) -> Result<T> {
        self.request_with_body("POST", path, body, ctx).await
    }

    /// Perform PUT request
    pub(crate) async fn put<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
        ctx: ErrorContext,
    ) -> Result<T> {
        self.request_with_body("PUT", path, body, ctx).await
    }

    /// Perform DELETE request
    pub(crate) async fn delete(&self, path: &str, ctx: ErrorContext) -> Result<()> {
        let now = Utc::now();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();

        let headers = vec![
            ("Host".to_string(), HUAWEICLOUD_DNS_HOST.to_string()),
            ("X-Sdk-Date".to_string(), timestamp.clone()),
        ];

        let authorization = self.sign("DELETE", path, "", &headers, "", &timestamp);
        let url = format!("https://{HUAWEICLOUD_DNS_HOST}{path}");

        let request = self
            .client
            .delete(&url)
            .header("Host", HUAWEICLOUD_DNS_HOST)
            .header("X-Sdk-Date", &timestamp)
            .header("Authorization", authorization);

        let (status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            "DELETE",
            &url,
            self.max_retries,
        )
        .await?;

        self.handle_response_error(status, &response_text, ctx)
    }
}
