//! 通用 HTTP 客户端工具
//!
//! 提供可复用的 HTTP 请求处理逻辑，减少各 Provider 的重复代码。
//! 各 Provider 保留完全的签名灵活性，自己构造 `RequestBuilder`。
//!
//! # 设计原则
//! - **不强制统一签名逻辑** - 各 provider 的签名算法差异太大
//! - **统一通用的 HTTP 处理流程** - 发送请求、日志记录、读取响应
//! - **灵活的响应解析** - 提供工具函数，但不限制解析方式

use reqwest::RequestBuilder;
use serde::de::DeserializeOwned;
use std::time::Duration;

use crate::error::ProviderError;

/// HTTP 工具函数集
pub struct HttpUtils;

impl HttpUtils {
    /// 执行 HTTP 请求并返回响应文本
    ///
    /// 统一处理：发送请求、日志记录、错误处理
    ///
    /// # Arguments
    /// * `request_builder` - 已配置好的请求构造器（包含 URL、headers、body 等）
    /// * `provider_name` - Provider 名称（用于日志）
    /// * `method_name` - 请求方法名（如 "GET", "POST"，用于日志）
    /// * `url_or_action` - URL 或 Action 名称（用于日志）
    ///
    /// # Returns
    /// * `Ok((status_code, response_text))` - 成功时返回状态码和响应文本
    /// * `Err(ProviderError::NetworkError)` - 网络错误
    pub async fn execute_request(
        request_builder: RequestBuilder,
        provider_name: &str,
        method_name: &str,
        url_or_action: &str,
    ) -> Result<(u16, String), ProviderError> {
        log::debug!("[{provider_name}] {method_name} {url_or_action}");

        // 发送请求
        let response = request_builder.send().await.map_err(|e| {
            if e.is_timeout() {
                ProviderError::Timeout {
                    provider: provider_name.to_string(),
                    detail: e.to_string(),
                }
            } else {
                ProviderError::NetworkError {
                    provider: provider_name.to_string(),
                    detail: e.to_string(),
                }
            }
        })?;

        let status_code = response.status().as_u16();
        log::debug!("[{provider_name}] Response Status: {status_code}");

        // 读取响应体
        let response_text = response
            .text()
            .await
            .map_err(|e| ProviderError::NetworkError {
                provider: provider_name.to_string(),
                detail: format!("读取响应失败: {e}"),
            })?;

        log::debug!("[{provider_name}] Response Body: {response_text}");

        Ok((status_code, response_text))
    }

    /// 解析 JSON 响应
    ///
    /// # Type Parameters
    /// * `T` - 目标类型
    ///
    /// # Arguments
    /// * `response_text` - JSON 文本
    /// * `provider_name` - Provider 名称（用于错误消息）
    ///
    /// # Returns
    /// * `Ok(T)` - 成功解析
    /// * `Err(ProviderError::ParseError)` - 解析失败
    pub fn parse_json<T>(response_text: &str, provider_name: &str) -> Result<T, ProviderError>
    where
        T: DeserializeOwned,
    {
        serde_json::from_str(response_text).map_err(|e| {
            log::error!("[{provider_name}] JSON 解析失败: {e}");
            log::error!("[{provider_name}] 原始响应: {response_text}");
            ProviderError::ParseError {
                provider: provider_name.to_string(),
                detail: e.to_string(),
            }
        })
    }

    /// 执行 HTTP 请求并返回响应文本（带重试）
    ///
    /// 自动重试网络错误，使用指数退避策略。
    ///
    /// # Arguments
    /// * `request_builder` - 已配置好的请求构造器
    /// * `provider_name` - Provider 名称
    /// * `method_name` - 请求方法名
    /// * `url_or_action` - URL 或 Action 名称
    /// * `max_retries` - 最大重试次数（0 表示不重试）
    ///
    /// # Returns
    /// * `Ok((status_code, response_text))` - 成功时返回状态码和响应文本
    /// * `Err(ProviderError)` - 所有重试都失败后返回最后一个错误
    ///
    /// # 重试策略
    /// - 只重试网络错误（`ProviderError::NetworkError`）
    /// - 指数退避：100ms, 200ms, 400ms, 800ms, ... (最大 10 秒)
    /// - 业务错误（认证失败、记录不存在等）不会重试
    pub async fn execute_request_with_retry(
        request_builder: RequestBuilder,
        provider_name: &str,
        method_name: &str,
        url_or_action: &str,
        max_retries: u32,
    ) -> Result<(u16, String), ProviderError> {
        if max_retries == 0 {
            // 不重试，直接执行
            return Self::execute_request(
                request_builder,
                provider_name,
                method_name,
                url_or_action,
            )
            .await;
        }

        let mut last_error = None;

        for attempt in 0..=max_retries {
            // 克隆请求（RequestBuilder 只能使用一次）
            let Some(req) = request_builder.try_clone() else {
                // 无法克隆（通常是 body stream 导致），回退到不重试
                log::warn!("[{provider_name}] 无法克隆请求，禁用重试");
                return Self::execute_request(
                    request_builder,
                    provider_name,
                    method_name,
                    url_or_action,
                )
                .await;
            };

            match Self::execute_request(req, provider_name, method_name, url_or_action).await {
                Ok(resp) => return Ok(resp),
                Err(e) if attempt < max_retries && is_retryable(&e) => {
                    let delay = backoff_delay(attempt);
                    log::warn!(
                        "[{}] 请求失败（尝试 {}/{}），{:.1}秒后重试: {}",
                        provider_name,
                        attempt + 1,
                        max_retries,
                        delay.as_secs_f32(),
                        e
                    );
                    tokio::time::sleep(delay).await;
                    last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_error.unwrap_or_else(|| ProviderError::NetworkError {
            provider: provider_name.to_string(),
            detail: "所有重试均失败，但未捕获到错误".to_string(),
        }))
    }
}

/// 判断错误是否可重试
///
/// 网络错误、超时、限流适合重试，业务错误（如认证失败、记录不存在）不应重试
fn is_retryable(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::NetworkError { .. }
            | ProviderError::Timeout { .. }
            | ProviderError::RateLimited { .. }
    )
}

/// 计算指数退避延迟
///
/// 退避策略：100ms, 200ms, 400ms, 800ms, 1.6s, ...
/// 最大延迟限制为 10 秒
fn backoff_delay(attempt: u32) -> Duration {
    let delay_ms = 100 * 2_u64.pow(attempt);
    let delay_ms = delay_ms.min(10_000); // 最大 10 秒
    Duration::from_millis(delay_ms)
}
