//! Cloudflare HTTP 请求方法

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};
use crate::types::PaginationParams;

use super::{
    CF_API_BASE, CloudflareDnsRecord, CloudflareProvider, CloudflareResponse, MAX_PAGE_SIZE_ZONES,
};

impl CloudflareProvider {
    /// 执行 GET 请求
    pub(crate) async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = format!("{CF_API_BASE}{path}");
        log::debug!("GET {url}");

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| self.network_error(e))?;

        let status = response.status();
        log::debug!("Response Status: {status}");

        let response_text = response
            .text()
            .await
            .map_err(|e| self.network_error(format!("读取响应失败: {e}")))?;

        log::debug!("Response Body: {response_text}");

        let cf_response: CloudflareResponse<T> =
            serde_json::from_str(&response_text).map_err(|e| {
                log::error!("JSON 解析失败: {e}");
                log::error!("原始响应: {response_text}");
                self.parse_error(e)
            })?;

        if !cf_response.success {
            let (code, message) = cf_response
                .errors
                .and_then(|errors| {
                    errors
                        .first()
                        .map(|e| (e.code.to_string(), e.message.clone()))
                })
                .unwrap_or_else(|| (String::new(), "Unknown error".to_string()));
            log::error!("API 错误: {message}");
            return Err(self.map_error(
                RawApiError::with_code(code, message),
                ErrorContext::default(),
            ));
        }

        cf_response
            .result
            .ok_or_else(|| self.parse_error("响应中缺少 result 字段"))
    }

    /// 执行 GET 请求 (带分页)
    pub(crate) async fn get_paginated<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        params: &PaginationParams,
    ) -> Result<(Vec<T>, u32)> {
        // Cloudflare zones API 最大 per_page 是 50
        let url = format!(
            "{}{}?page={}&per_page={}",
            CF_API_BASE,
            path,
            params.page,
            params.page_size.min(MAX_PAGE_SIZE_ZONES)
        );
        log::debug!("GET {url}");

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| self.network_error(e))?;

        let status = response.status();
        log::debug!("Response Status: {status}");

        let response_text = response
            .text()
            .await
            .map_err(|e| self.network_error(format!("读取响应失败: {e}")))?;

        log::debug!("Response Body: {response_text}");

        let cf_response: CloudflareResponse<Vec<T>> = serde_json::from_str(&response_text)
            .map_err(|e| {
                log::error!("JSON 解析失败: {e}");
                log::error!("原始响应: {response_text}");
                self.parse_error(e)
            })?;

        if !cf_response.success {
            let (code, message) = cf_response
                .errors
                .and_then(|errors| {
                    errors
                        .first()
                        .map(|e| (e.code.to_string(), e.message.clone()))
                })
                .unwrap_or_else(|| (String::new(), "Unknown error".to_string()));
            log::error!("API 错误: {message}");
            return Err(self.map_error(
                RawApiError::with_code(code, message),
                ErrorContext::default(),
            ));
        }

        let total_count = cf_response.result_info.map_or(0, |i| i.total_count);
        let items = cf_response.result.unwrap_or_default();

        Ok((items, total_count))
    }

    /// 执行 GET 请求 (带自定义 URL，用于 list_records)
    pub(crate) async fn get_records(&self, url: &str) -> Result<(Vec<CloudflareDnsRecord>, u32)> {
        log::debug!("GET {CF_API_BASE}{url}");

        let response = self
            .client
            .get(format!("{CF_API_BASE}{url}"))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| self.network_error(e))?;

        let response_text = response
            .text()
            .await
            .map_err(|e| self.network_error(format!("读取响应失败: {e}")))?;

        let cf_response: CloudflareResponse<Vec<CloudflareDnsRecord>> =
            serde_json::from_str(&response_text).map_err(|e| self.parse_error(e))?;

        if !cf_response.success {
            let (code, message) = cf_response
                .errors
                .and_then(|errors| {
                    errors
                        .first()
                        .map(|e| (e.code.to_string(), e.message.clone()))
                })
                .unwrap_or_else(|| (String::new(), "Unknown error".to_string()));
            return Err(self.map_error(
                RawApiError::with_code(code, message),
                ErrorContext::default(),
            ));
        }

        let total_count = cf_response.result_info.map_or(0, |i| i.total_count);
        let records = cf_response.result.unwrap_or_default();

        Ok((records, total_count))
    }

    /// 执行 POST 请求
    pub(crate) async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = format!("{CF_API_BASE}{path}");
        let body_json =
            serde_json::to_string_pretty(body).unwrap_or_else(|_| "无法序列化请求体".to_string());
        log::debug!("POST {url}");
        log::debug!("Request Body: {body_json}");

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(body)
            .send()
            .await
            .map_err(|e| self.network_error(e))?;

        let status = response.status();
        log::debug!("Response Status: {status}");

        let response_text = response
            .text()
            .await
            .map_err(|e| self.network_error(format!("读取响应失败: {e}")))?;

        log::debug!("Response Body: {response_text}");

        let cf_response: CloudflareResponse<T> =
            serde_json::from_str(&response_text).map_err(|e| {
                log::error!("JSON 解析失败: {e}");
                log::error!("原始响应: {response_text}");
                self.parse_error(e)
            })?;

        if !cf_response.success {
            let (code, message) = cf_response
                .errors
                .and_then(|errors| {
                    errors
                        .first()
                        .map(|e| (e.code.to_string(), e.message.clone()))
                })
                .unwrap_or_else(|| (String::new(), "Unknown error".to_string()));
            log::error!("API 错误: {message}");
            return Err(self.map_error(
                RawApiError::with_code(code, message),
                ErrorContext::default(),
            ));
        }

        cf_response
            .result
            .ok_or_else(|| self.parse_error("响应中缺少 result 字段"))
    }

    /// 执行 PATCH 请求
    pub(crate) async fn patch<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = format!("{CF_API_BASE}{path}");
        let body_json =
            serde_json::to_string_pretty(body).unwrap_or_else(|_| "无法序列化请求体".to_string());
        log::debug!("PATCH {url}");
        log::debug!("Request Body: {body_json}");

        let response = self
            .client
            .patch(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(body)
            .send()
            .await
            .map_err(|e| self.network_error(e))?;

        let status = response.status();
        log::debug!("Response Status: {status}");

        let response_text = response
            .text()
            .await
            .map_err(|e| self.network_error(format!("读取响应失败: {e}")))?;

        log::debug!("Response Body: {response_text}");

        let cf_response: CloudflareResponse<T> =
            serde_json::from_str(&response_text).map_err(|e| {
                log::error!("JSON 解析失败: {e}");
                log::error!("原始响应: {response_text}");
                self.parse_error(e)
            })?;

        if !cf_response.success {
            let (code, message) = cf_response
                .errors
                .and_then(|errors| {
                    errors
                        .first()
                        .map(|e| (e.code.to_string(), e.message.clone()))
                })
                .unwrap_or_else(|| (String::new(), "Unknown error".to_string()));
            log::error!("API 错误: {message}");
            return Err(self.map_error(
                RawApiError::with_code(code, message),
                ErrorContext::default(),
            ));
        }

        cf_response
            .result
            .ok_or_else(|| self.parse_error("响应中缺少 result 字段"))
    }

    /// 执行 DELETE 请求
    pub(crate) async fn delete(&self, path: &str) -> Result<()> {
        let url = format!("{CF_API_BASE}{path}");
        log::debug!("DELETE {url}");

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| self.network_error(e))?;

        let status = response.status();
        log::debug!("Response Status: {status}");

        let response_text = response
            .text()
            .await
            .map_err(|e| self.network_error(format!("读取响应失败: {e}")))?;

        log::debug!("Response Body: {response_text}");

        let cf_response: CloudflareResponse<serde_json::Value> =
            serde_json::from_str(&response_text).map_err(|e| {
                log::error!("JSON 解析失败: {e}");
                log::error!("原始响应: {response_text}");
                self.parse_error(e)
            })?;

        if !cf_response.success {
            let (code, message) = cf_response
                .errors
                .and_then(|errors| {
                    errors
                        .first()
                        .map(|e| (e.code.to_string(), e.message.clone()))
                })
                .unwrap_or_else(|| (String::new(), "Unknown error".to_string()));
            log::error!("API 错误: {message}");
            return Err(self.map_error(
                RawApiError::with_code(code, message),
                ErrorContext::default(),
            ));
        }

        Ok(())
    }
}
