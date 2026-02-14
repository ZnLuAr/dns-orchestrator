//! Generic HTTP client tools
//!
//! Provide reusable HTTP request processing logic to reduce duplicate code for each Provider.
//! Each Provider retains full signature flexibility and constructs `RequestBuilder` by itself.
//!
//! # design principles
//! - **Does not enforce unified signature logic** - The signature algorithms of each provider are too different
//! - **Unified and universal HTTP processing flow** - sending requests, logging, and reading responses
//! - **Flexible response parsing** - Provides tool functions but does not limit parsing methods

use reqwest::RequestBuilder;
use serde::de::DeserializeOwned;
use std::time::Duration;

use crate::error::ProviderError;
use crate::utils::log_sanitizer::truncate_for_log;

/// HTTP tool function set
pub struct HttpUtils;

impl HttpUtils {
    /// Performs an HTTP request and returns response text
    ///
    /// Unified processing: sending requests, logging, error handling
    ///
    /// # Arguments
    /// * `request_builder` - configured request constructor (including URL, headers, body, etc.)
    /// * `provider_name` - Provider name (for logging)
    /// * `method_name` - request method name (such as "GET", "POST", used for logs)
    /// * `url_or_action` - URL or Action name (for logging)
    ///
    /// # Returns
    /// * `Ok((status_code, response_text))` - returns status code and response text on success
    /// * `Err(ProviderError::NetworkError)` - Network error
    pub async fn execute_request(
        request_builder: RequestBuilder,
        provider_name: &str,
        method_name: &str,
        url_or_action: &str,
    ) -> Result<(u16, String), ProviderError> {
        log::debug!("[{provider_name}] {method_name} {url_or_action}");

        // Send request
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

        // Extract Retry-After header (before consuming response body)
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        // Returns RateLimited error for HTTP 429
        if status_code == 429 {
            let body = response.text().await.unwrap_or_default();
            log::warn!("[{provider_name}] Rate limited (HTTP 429), retry_after={retry_after:?}");
            return Err(ProviderError::RateLimited {
                provider: provider_name.to_string(),
                retry_after,
                raw_message: Some(body),
            });
        }

        // Return NetworkError for 502/503/504 (can be retried)
        if matches!(status_code, 502..=504) {
            let body = response.text().await.unwrap_or_default();
            log::warn!("[{provider_name}] Server error (HTTP {status_code})");
            return Err(ProviderError::NetworkError {
                provider: provider_name.to_string(),
                detail: format!("HTTP {status_code}: {body}"),
            });
        }

        // Read response body
        let response_text = response
            .text()
            .await
            .map_err(|e| ProviderError::NetworkError {
                provider: provider_name.to_string(),
                detail: format!("Failed to read response body: {e}"),
            })?;

        log::debug!(
            "[{provider_name}] Response Body: {}",
            truncate_for_log(&response_text)
        );

        Ok((status_code, response_text))
    }

    /// Parse JSON response
    ///
    /// # Type Parameters
    /// * `T` - target type
    ///
    /// # Arguments
    /// * `response_text` - JSON text
    /// * `provider_name` - Provider name (used for error messages)
    ///
    /// # Returns
    /// * `Ok(T)` - successfully parsed
    /// * `Err(ProviderError::ParseError)` - parsing failed
    pub fn parse_json<T>(response_text: &str, provider_name: &str) -> Result<T, ProviderError>
    where
        T: DeserializeOwned,
    {
        serde_json::from_str(response_text).map_err(|e| {
            log::error!("[{provider_name}] JSON parse failed: {e}");
            log::error!(
                "[{provider_name}] Raw response: {}",
                truncate_for_log(response_text)
            );
            ProviderError::ParseError {
                provider: provider_name.to_string(),
                detail: e.to_string(),
            }
        })
    }

    /// Performs an HTTP request and returns response text (with retries)
    ///
    /// Automatically retry network errors, using an exponential backoff strategy.
    ///
    /// # Arguments
    /// * `request_builder` - configured request constructor
    /// * `provider_name` - Provider name
    /// * `method_name` - request method name
    /// * `url_or_action` - URL or Action name
    /// * `max_retries` - Maximum number of retries (0 means no retries)
    ///
    /// # Returns
    /// * `Ok((status_code, response_text))` - returns status code and response text on success
    /// * `Err(ProviderError)` - the last error returned after all retries have failed
    ///
    /// # Retry strategy
    /// - Only retry network errors (`ProviderError::NetworkError`)
    /// - Exponential backoff: 100ms, 200ms, 400ms, 800ms, ... (maximum 10 seconds)
    /// - Business errors (authentication failure, record does not exist, etc.) will not be retried
    pub async fn execute_request_with_retry(
        request_builder: RequestBuilder,
        provider_name: &str,
        method_name: &str,
        url_or_action: &str,
        max_retries: u32,
    ) -> Result<(u16, String), ProviderError> {
        if max_retries == 0 {
            // Do not retry, execute directly
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
            // Clone the request (RequestBuilder can only be used once)
            let Some(req) = request_builder.try_clone() else {
                // Unable to clone (usually caused by body stream), fallback to not retrying
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

/// Determine whether the error can be retried
///
/// Network errors, timeouts, and current limiting are suitable for retrying, but business errors (such as authentication failure and records that do not exist) should not be retried.
fn is_retryable(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::NetworkError { .. }
            | ProviderError::Timeout { .. }
            | ProviderError::RateLimited { .. }
    )
}

/// Calculate retry delay
///
/// Use this value (capped at 30s) when the error is `RateLimited` and contains `retry_after`.
/// Otherwise exponential backoff is used.
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

/// Calculate exponential backoff delay
///
/// Backoff strategy: 100ms, 200ms, 400ms, 800ms, 1.6s, ...
/// Maximum delay limit is 10 seconds
fn backoff_delay(attempt: u32) -> Duration {
    let capped_attempt = attempt.min(20); // Prevent 2^attempt from overflowing
    let delay_ms = 100_u64.saturating_mul(1_u64 << capped_attempt);
    let delay_ms = delay_ms.min(10_000); // Maximum 10 seconds
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
        assert!(
            matches!(&result, Ok(Foo { x: 42 })),
            "unexpected parse result: {result:?}"
        );
    }

    #[test]
    fn parse_json_invalid() {
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct Foo {
            x: i32,
        }
        let result: Result<Foo, ProviderError> = HttpUtils::parse_json("not json", "test");
        assert!(
            matches!(&result, Err(ProviderError::ParseError { .. })),
            "unexpected parse result: {result:?}"
        );
    }
}
