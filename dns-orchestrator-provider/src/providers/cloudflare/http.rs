//! Cloudflare HTTP request methods (refactored: eliminate code duplication)

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::http_client::HttpUtils;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};
use crate::types::PaginationParams;
use crate::utils::log_sanitizer::truncate_for_log;

use super::{
    CF_API_BASE, CloudflareDnsRecord, CloudflareProvider, CloudflareResponse, MAX_PAGE_SIZE_ZONES,
};

impl CloudflareProvider {
    // ==================== Helper methods ====================

    /// Checks the error field in the Cloudflare response and returns the mapped error on failure
    fn check_cf_errors<T>(
        &self,
        cf_response: &CloudflareResponse<T>,
        ctx: ErrorContext,
    ) -> Result<()> {
        if !cf_response.success {
            let (code, message) = cf_response
                .errors
                .as_ref()
                .and_then(|errors| {
                    errors
                        .first()
                        .map(|e| (e.code.to_string(), e.message.clone()))
                })
                .unwrap_or_else(|| (String::new(), "Unknown error".to_string()));
            log::error!("API error: {message}");
            return Err(self.map_error(RawApiError::with_code(code, message), ctx));
        }
        Ok(())
    }

    /// Unified handling of Cloudflare API responses
    fn handle_cf_response<T: for<'de> Deserialize<'de>>(
        &self,
        response_text: &str,
        ctx: ErrorContext,
    ) -> Result<T> {
        let cf_response: CloudflareResponse<T> =
            HttpUtils::parse_json(response_text, self.provider_name())?;

        self.check_cf_errors(&cf_response, ctx)?;

        cf_response
            .result
            .ok_or_else(|| self.parse_error("Missing 'result' field in response"))
    }

    /// Unified handling of Cloudflare API responses (with pagination information)
    fn handle_cf_response_paginated<T: for<'de> Deserialize<'de>>(
        &self,
        response_text: &str,
        ctx: ErrorContext,
    ) -> Result<(Vec<T>, u32)> {
        let cf_response: CloudflareResponse<Vec<T>> =
            HttpUtils::parse_json(response_text, self.provider_name())?;

        self.check_cf_errors(&cf_response, ctx)?;

        let total_count = cf_response.result_info.map_or(0, |i| i.total_count);
        let items = cf_response.result.unwrap_or_default();

        Ok((items, total_count))
    }

    /// Execute request with body (POST/PATCH)
    async fn request_with_body<T, B>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: &B,
        ctx: ErrorContext,
    ) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
    {
        let url = format!("{CF_API_BASE}{path}");

        if log::log_enabled!(log::Level::Debug) {
            let body_json = serde_json::to_string_pretty(body)
                .unwrap_or_else(|_| "Failed to serialize request body".to_string());
            log::debug!("Request Body: {}", truncate_for_log(&body_json));
        }

        let request = self
            .client
            .request(method.clone(), &url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(body);

        let (_status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            method.as_str(),
            &url,
            self.max_retries,
        )
        .await?;

        self.handle_cf_response(&response_text, ctx)
    }

    // ==================== Public API methods ====================

    /// Perform a GET request
    pub(crate) async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        ctx: ErrorContext,
    ) -> Result<T> {
        let url = format!("{CF_API_BASE}{path}");

        let request = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token));

        let (_status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            "GET",
            &url,
            self.max_retries,
        )
        .await?;

        self.handle_cf_response(&response_text, ctx)
    }

    /// Perform a GET request (with pagination)
    pub(crate) async fn get_paginated<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        params: &PaginationParams,
        ctx: ErrorContext,
    ) -> Result<(Vec<T>, u32)> {
        let url = format!(
            "{}{}?page={}&per_page={}",
            CF_API_BASE,
            path,
            params.page,
            params.page_size.min(MAX_PAGE_SIZE_ZONES)
        );

        let request = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token));

        let (_status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            "GET",
            &url,
            self.max_retries,
        )
        .await?;

        self.handle_cf_response_paginated(&response_text, ctx)
    }

    /// Perform a GET request (with custom URL for `list_records`)
    pub(crate) async fn get_records(
        &self,
        url: &str,
        ctx: ErrorContext,
    ) -> Result<(Vec<CloudflareDnsRecord>, u32)> {
        let full_url = format!("{CF_API_BASE}{url}");

        let request = self
            .client
            .get(&full_url)
            .header("Authorization", format!("Bearer {}", self.api_token));

        let (_status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            "GET",
            &full_url,
            self.max_retries,
        )
        .await?;

        self.handle_cf_response_paginated(&response_text, ctx)
    }

    /// Perform POST request (using JSON Value directly)
    pub(crate) async fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: serde_json::Value,
        ctx: ErrorContext,
    ) -> Result<T> {
        self.request_with_body(reqwest::Method::POST, path, &body, ctx)
            .await
    }

    /// Perform PATCH request (using JSON Value directly)
    pub(crate) async fn patch_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: serde_json::Value,
        ctx: ErrorContext,
    ) -> Result<T> {
        self.request_with_body(reqwest::Method::PATCH, path, &body, ctx)
            .await
    }

    /// Perform DELETE request
    pub(crate) async fn delete(&self, path: &str, ctx: ErrorContext) -> Result<()> {
        let url = format!("{CF_API_BASE}{path}");

        let request = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token));

        let (_status, response_text) = HttpUtils::execute_request_with_retry(
            request,
            self.provider_name(),
            "DELETE",
            &url,
            self.max_retries,
        )
        .await?;

        // The DELETE response only needs to check whether it is successful and does not need to return data.
        let cf_response: CloudflareResponse<serde_json::Value> =
            HttpUtils::parse_json(&response_text, self.provider_name())?;

        self.check_cf_errors(&cf_response, ctx)?;

        Ok(())
    }
}
