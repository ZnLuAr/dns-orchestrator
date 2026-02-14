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

        // 提取 Retry-After header（在消费 response body 前）
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        // 对 HTTP 429 返回 RateLimited 错误
        if status_code == 429 {
            let body = response.text().await.unwrap_or_default();
            log::warn!("[{provider_name}] Rate limited (HTTP 429), retry_after={retry_after:?}");
            return Err(ProviderError::RateLimited {
                provider: provider_name.to_string(),
                retry_after,
                raw_message: Some(body),
            });
        }

        // 对 502/503/504 返回 NetworkError（可重试）
        if matches!(status_code, 502..=504) {
            let body = response.text().await.unwrap_or_default();
            log::warn!("[{provider_name}] Server error (HTTP {status_code})");
            return Err(ProviderError::NetworkError {
                provider: provider_name.to_string(),
                detail: format!("HTTP {status_code}: {body}"),
            });
        }

        // 读取响应体
        let response_text = response
            .text()
            .await
            .map_err(|e| ProviderError::NetworkError {
                provider: provider_name.to_string(),
                detail: format!("Failed to read response body: {e}"),
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
            log::error!("[{provider_name}] JSON parse failed: {e}");
            log::error!("[{provider_name}] Raw response: {response_text}");
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
                log::warn!("[{provider_name}] Cannot clone request, disabling retry");
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
                    let delay = retry_delay(&e, attempt);
                    log::warn!(
                        "[{}] Request failed (attempt {}/{}), retrying in {:.1}s: {}",
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
            detail: "All retries exhausted with no error captured".to_string(),
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

/// 计算重试延迟
///
/// 当错误是 `RateLimited` 且包含 `retry_after` 时，使用该值（上限 30s）。
/// 否则使用指数退避。
fn retry_delay(error: &ProviderError, attempt: u32) -> Duration {
    if let ProviderError::RateLimited {
        retry_after: Some(secs),
        ..
    } = error
    {
        Duration::from_secs((*secs).min(30))
    } else {
        backoff_delay(attempt)
    }
}

/// 计算指数退避延迟
///
/// 退避策略：100ms, 200ms, 400ms, 800ms, 1.6s, ...
/// 最大延迟限制为 10 秒
fn backoff_delay(attempt: u32) -> Duration {
    let capped_attempt = attempt.min(20); // 防止 2^attempt 溢出
    let delay_ms = 100_u64.saturating_mul(1_u64 << capped_attempt);
    let delay_ms = delay_ms.min(10_000); // 最大 10 秒
    Duration::from_millis(delay_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProviderError;
    use std::time::Duration;

    // ---- is_retryable ----

    #[test]
    fn retryable_network_error() {
        let e = ProviderError::NetworkError {
            provider: "test".into(),
            detail: "err".into(),
        };
        assert!(is_retryable(&e));
    }

    #[test]
    fn retryable_timeout() {
        let e = ProviderError::Timeout {
            provider: "test".into(),
            detail: "err".into(),
        };
        assert!(is_retryable(&e));
    }

    #[test]
    fn retryable_rate_limited() {
        let e = ProviderError::RateLimited {
            provider: "test".into(),
            retry_after: None,
            raw_message: None,
        };
        assert!(is_retryable(&e));
    }

    #[test]
    fn not_retryable_auth_error() {
        let e = ProviderError::InvalidCredentials {
            provider: "test".into(),
            raw_message: None,
        };
        assert!(!is_retryable(&e));
    }

    #[test]
    fn not_retryable_record_not_found() {
        let e = ProviderError::RecordNotFound {
            provider: "test".into(),
            record_id: "1".into(),
            raw_message: None,
        };
        assert!(!is_retryable(&e));
    }

    #[test]
    fn not_retryable_parse_error() {
        let e = ProviderError::ParseError {
            provider: "test".into(),
            detail: "err".into(),
        };
        assert!(!is_retryable(&e));
    }

    #[test]
    fn not_retryable_domain_not_found() {
        let e = ProviderError::DomainNotFound {
            provider: "test".into(),
            domain: "x".into(),
            raw_message: None,
        };
        assert!(!is_retryable(&e));
    }

    // ---- backoff_delay ----

    #[test]
    fn backoff_attempt_0() {
        assert_eq!(backoff_delay(0), Duration::from_millis(100));
    }

    #[test]
    fn backoff_attempt_1() {
        assert_eq!(backoff_delay(1), Duration::from_millis(200));
    }

    #[test]
    fn backoff_attempt_2() {
        assert_eq!(backoff_delay(2), Duration::from_millis(400));
    }

    #[test]
    fn backoff_attempt_3() {
        assert_eq!(backoff_delay(3), Duration::from_millis(800));
    }

    #[test]
    fn backoff_capped_at_10s() {
        // attempt 7: 100 * 2^7 = 12800ms, capped to 10000ms
        assert_eq!(backoff_delay(7), Duration::from_millis(10_000));
    }

    // ---- parse_json ----

    #[test]
    fn parse_json_valid() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Foo {
            x: i32,
        }
        let result: Result<Foo, ProviderError> = HttpUtils::parse_json(r#"{"x":42}"#, "test");
        assert_eq!(result.unwrap(), Foo { x: 42 });
    }

    #[test]
    fn parse_json_invalid() {
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct Foo {
            x: i32,
        }
        let result: Result<Foo, ProviderError> = HttpUtils::parse_json("not json", "test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProviderError::ParseError { .. }));
    }
}
