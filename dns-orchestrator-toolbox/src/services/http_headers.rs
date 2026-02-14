//! HTTP header inspection and security analysis module.

use std::fmt::Write;
use std::sync::LazyLock;
use std::time::Instant;

use log::debug;
use reqwest::{Client, Method};
use tokio::time::timeout;
use url::Url;

use crate::error::{ToolboxError, ToolboxResult};
use crate::types::{
    HttpHeader, HttpHeaderCheckRequest, HttpHeaderCheckResult, HttpMethod, SecurityHeaderAnalysis,
    SecurityHeaderStatus,
};

const REQUEST_TIMEOUT_SECS: u64 = 10;
const OVERALL_TIMEOUT_SECS: u64 = 15;

/// Shared HTTP client with configured timeout and redirect policy.
static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .unwrap_or_default()
});

/// Required security headers.
const REQUIRED_SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
];

/// Recommended (but not required) security headers.
const RECOMMENDED_SECURITY_HEADERS: &[&str] =
    &["referrer-policy", "permissions-policy", "x-xss-protection"];

/// Perform an HTTP header check and security analysis.
pub async fn http_header_check(
    request: &HttpHeaderCheckRequest,
) -> ToolboxResult<HttpHeaderCheckResult> {
    timeout(
        std::time::Duration::from_secs(OVERALL_TIMEOUT_SECS),
        http_header_check_inner(request),
    )
    .await
    .map_err(|_| {
        ToolboxError::NetworkError(format!(
            "HTTP header check timed out ({OVERALL_TIMEOUT_SECS}s)"
        ))
    })?
}

async fn http_header_check_inner(
    request: &HttpHeaderCheckRequest,
) -> ToolboxResult<HttpHeaderCheckResult> {
    debug!("[HTTP] Checking headers for {}", request.url);
    let start = Instant::now();

    // Ensure the URL includes a scheme; default to https://
    let url = if request.url.starts_with("http://") || request.url.starts_with("https://") {
        request.url.clone()
    } else {
        format!("https://{}", request.url)
    };

    debug!("[HTTP] Normalized URL: {url}");

    let client = &*HTTP_CLIENT;

    // Map HttpMethod to reqwest::Method
    let method = match request.method {
        HttpMethod::GET => Method::GET,
        HttpMethod::HEAD => Method::HEAD,
        HttpMethod::POST => Method::POST,
        HttpMethod::PUT => Method::PUT,
        HttpMethod::DELETE => Method::DELETE,
        HttpMethod::PATCH => Method::PATCH,
        HttpMethod::OPTIONS => Method::OPTIONS,
    };

    // Build request
    let mut req_builder = client.request(method.clone(), &url);

    // Add custom request headers
    for header in &request.custom_headers {
        if !header.name.is_empty() && !header.value.is_empty() {
            req_builder = req_builder.header(header.name.as_str(), header.value.as_str());
        }
    }

    // Attach request body and Content-Type
    if let Some(body) = &request.body {
        if let Some(content_type) = &request.content_type {
            req_builder = req_builder.header("Content-Type", content_type);
        }
        req_builder = req_builder.body(body.clone());
    }

    // Send request
    let response = req_builder
        .send()
        .await
        .map_err(|e| ToolboxError::NetworkError(format!("HTTP request failed: {e}")))?;

    let elapsed = start.elapsed();
    let status_code = response.status().as_u16();
    let status_text = response
        .status()
        .canonical_reason()
        .unwrap_or("Unknown")
        .to_string();

    // Extract response headers
    let mut headers: Vec<HttpHeader> = Vec::new();
    for (name, value) in response.headers() {
        headers.push(HttpHeader {
            name: name.to_string(),
            value: value.to_str().unwrap_or("<binary>").to_string(),
        });
    }

    // Read response body as bytes
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| ToolboxError::NetworkError(format!("Failed to read response body: {e}")))?;

    // Content-Length -- compute actual size
    let content_length = Some(body_bytes.len() as u64);

    // Convert body bytes to string (for raw_response)
    let body = String::from_utf8_lossy(&body_bytes).to_string();

    // Security header analysis
    let security_analysis = analyze_security_headers(&headers);

    // Build raw request message
    let mut raw_request = format!("{} {} HTTP/1.1\r\n", method.as_str(), url);

    // Parse Host from URL
    if let Ok(parsed_url) = Url::parse(&url)
        && let Some(host) = parsed_url.host_str()
    {
        let host_header = if let Some(port) = parsed_url.port() {
            format!("{host}:{port}")
        } else {
            host.to_string()
        };
        let _ = write!(raw_request, "Host: {host_header}\r\n");
    }

    // Append custom headers to raw request
    for header in &request.custom_headers {
        if !header.name.is_empty() && !header.value.is_empty() {
            let _ = write!(raw_request, "{}: {}\r\n", header.name, header.value);
        }
    }

    // Append Content-Type and body
    if let Some(body) = &request.body {
        if let Some(content_type) = &request.content_type {
            let _ = write!(raw_request, "Content-Type: {content_type}\r\n");
        }
        let _ = write!(raw_request, "Content-Length: {}\r\n", body.len());
        raw_request.push_str("\r\n");
        raw_request.push_str(body);
    } else {
        raw_request.push_str("\r\n");
    }

    // Build raw response message
    let mut raw_response = format!("HTTP/1.1 {status_code} {status_text}\r\n");
    for header in &headers {
        let _ = write!(raw_response, "{}: {}\r\n", header.name, header.value);
    }
    raw_response.push_str("\r\n");
    raw_response.push_str(&body);

    debug!(
        "[HTTP] Check completed: {} - status={}, headers={}, time={:?}",
        url,
        status_code,
        headers.len(),
        elapsed
    );

    // u128 -> u64: elapsed millis for an HTTP request will never exceed u64::MAX
    #[allow(clippy::cast_possible_truncation)]
    let response_time_ms = elapsed.as_millis() as u64;

    Ok(HttpHeaderCheckResult {
        url,
        status_code,
        status_text,
        response_time_ms,
        headers,
        security_analysis,
        content_length,
        raw_request,
        raw_response,
    })
}

/// Analyse response headers for security best practices.
fn analyze_security_headers(headers: &[HttpHeader]) -> Vec<SecurityHeaderAnalysis> {
    let mut analysis = Vec::new();

    // Check required security headers
    for &header_name in REQUIRED_SECURITY_HEADERS {
        let found = headers
            .iter()
            .find(|h| h.name.to_lowercase() == header_name);

        analysis.push(SecurityHeaderAnalysis {
            name: header_name.to_string(),
            present: found.is_some(),
            value: found.map(|h| h.value.clone()),
            status: if found.is_some() {
                SecurityHeaderStatus::Good
            } else {
                SecurityHeaderStatus::Missing
            },
            recommendation: if found.is_none() {
                Some(get_recommendation(header_name))
            } else {
                None
            },
        });
    }

    // Check recommended security headers
    for &header_name in RECOMMENDED_SECURITY_HEADERS {
        let found = headers
            .iter()
            .find(|h| h.name.to_lowercase() == header_name);

        analysis.push(SecurityHeaderAnalysis {
            name: header_name.to_string(),
            present: found.is_some(),
            value: found.map(|h| h.value.clone()),
            status: if found.is_some() {
                SecurityHeaderStatus::Good
            } else {
                SecurityHeaderStatus::Warning
            },
            recommendation: if found.is_none() {
                Some(get_recommendation(header_name))
            } else {
                None
            },
        });
    }

    analysis
}

/// Return a human-readable recommendation for a missing security header.
fn get_recommendation(header_name: &str) -> String {
    match header_name {
        "strict-transport-security" => "Add HSTS header to enforce HTTPS connections".to_string(),
        "x-frame-options" => "Add to prevent clickjacking attacks".to_string(),
        "x-content-type-options" => "Set to 'nosniff' to prevent MIME type sniffing".to_string(),
        "content-security-policy" => "Add CSP header to prevent XSS attacks".to_string(),
        "referrer-policy" => "Set Referrer-Policy to control referrer information".to_string(),
        "permissions-policy" => "Set Permissions-Policy to restrict browser features".to_string(),
        "x-xss-protection" => "Add to enable browser XSS filter".to_string(),
        _ => "Consider adding this security header".to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    // ==================== get_recommendation tests ====================

    #[test]
    fn test_get_recommendation_known_headers() {
        assert!(get_recommendation("strict-transport-security").contains("HSTS"));
        assert!(get_recommendation("x-frame-options").contains("clickjacking"));
        assert!(get_recommendation("x-content-type-options").contains("nosniff"));
        assert!(get_recommendation("content-security-policy").contains("XSS"));
        assert!(get_recommendation("referrer-policy").contains("Referrer"));
        assert!(get_recommendation("permissions-policy").contains("Permissions"));
        assert!(get_recommendation("x-xss-protection").contains("XSS"));
    }

    #[test]
    fn test_get_recommendation_unknown_header() {
        let rec = get_recommendation("custom-header");
        assert!(rec.contains("Consider"));
    }

    // ==================== analyze_security_headers tests ====================

    #[test]
    fn test_analyze_security_headers_all_present() {
        let headers = vec![
            HttpHeader {
                name: "strict-transport-security".to_string(),
                value: "max-age=31536000".to_string(),
            },
            HttpHeader {
                name: "x-frame-options".to_string(),
                value: "DENY".to_string(),
            },
            HttpHeader {
                name: "x-content-type-options".to_string(),
                value: "nosniff".to_string(),
            },
            HttpHeader {
                name: "content-security-policy".to_string(),
                value: "default-src 'self'".to_string(),
            },
            HttpHeader {
                name: "referrer-policy".to_string(),
                value: "strict-origin".to_string(),
            },
            HttpHeader {
                name: "permissions-policy".to_string(),
                value: "geolocation=()".to_string(),
            },
            HttpHeader {
                name: "x-xss-protection".to_string(),
                value: "1; mode=block".to_string(),
            },
        ];

        let analysis = analyze_security_headers(&headers);

        // All should be present and "good"
        for item in &analysis {
            assert!(item.present, "Header {} should be present", item.name);
            assert_eq!(
                item.status,
                SecurityHeaderStatus::Good,
                "Header {} should be good",
                item.name
            );
            assert!(
                item.recommendation.is_none(),
                "Header {} should have no recommendation",
                item.name
            );
            assert!(item.value.is_some());
        }
    }

    #[test]
    fn test_analyze_security_headers_none_present() {
        let headers: Vec<HttpHeader> = vec![
            HttpHeader {
                name: "content-type".to_string(),
                value: "text/html".to_string(),
            },
            HttpHeader {
                name: "server".to_string(),
                value: "nginx".to_string(),
            },
        ];

        let analysis = analyze_security_headers(&headers);

        // Total: 4 required + 3 recommended = 7
        assert_eq!(analysis.len(), 7);

        // Required headers should be "missing"
        let required_names: Vec<&str> = REQUIRED_SECURITY_HEADERS.to_vec();
        for item in analysis
            .iter()
            .filter(|a| required_names.contains(&a.name.as_str()))
        {
            assert!(!item.present);
            assert_eq!(item.status, SecurityHeaderStatus::Missing);
            assert!(item.recommendation.is_some());
            assert!(item.value.is_none());
        }

        // Recommended headers should be "warning"
        let recommended_names: Vec<&str> = RECOMMENDED_SECURITY_HEADERS.to_vec();
        for item in analysis
            .iter()
            .filter(|a| recommended_names.contains(&a.name.as_str()))
        {
            assert!(!item.present);
            assert_eq!(item.status, SecurityHeaderStatus::Warning);
            assert!(item.recommendation.is_some());
        }
    }

    #[test]
    fn test_analyze_security_headers_partial() {
        let headers = vec![
            HttpHeader {
                name: "strict-transport-security".to_string(),
                value: "max-age=31536000".to_string(),
            },
            HttpHeader {
                name: "x-content-type-options".to_string(),
                value: "nosniff".to_string(),
            },
        ];

        let analysis = analyze_security_headers(&headers);

        let hsts = analysis
            .iter()
            .find(|a| a.name == "strict-transport-security")
            .unwrap();
        assert!(hsts.present);
        assert_eq!(hsts.status, SecurityHeaderStatus::Good);
        assert_eq!(hsts.value.as_deref(), Some("max-age=31536000"));

        let xfo = analysis
            .iter()
            .find(|a| a.name == "x-frame-options")
            .unwrap();
        assert!(!xfo.present);
        assert_eq!(xfo.status, SecurityHeaderStatus::Missing);
    }

    #[test]
    fn test_analyze_security_headers_case_insensitive() {
        let headers = vec![HttpHeader {
            name: "Strict-Transport-Security".to_string(),
            value: "max-age=31536000".to_string(),
        }];

        let analysis = analyze_security_headers(&headers);
        let hsts = analysis
            .iter()
            .find(|a| a.name == "strict-transport-security")
            .unwrap();
        assert!(hsts.present);
        assert_eq!(hsts.status, SecurityHeaderStatus::Good);
    }

    #[test]
    fn test_analyze_security_headers_count() {
        let analysis = analyze_security_headers(&[]);
        // 4 required + 3 recommended = 7
        assert_eq!(analysis.len(), 7);
    }

    // ==================== integration tests ====================
    // NOTE: These tests depend on external networks; failures may be due to network issues, not code bugs

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_http_header_check_real() {
        let request = HttpHeaderCheckRequest {
            url: "https://httpbin.org/get".to_string(),
            method: HttpMethod::GET,
            custom_headers: vec![],
            body: None,
            content_type: None,
        };
        let result = http_header_check(&request).await;
        let check =
            result.unwrap_or_else(|e| panic!("HTTP header check failed (network issue?): {e}"));
        assert_eq!(check.status_code, 200);
        assert!(!check.headers.is_empty());
        assert!(!check.security_analysis.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_http_header_check_head_method_real() {
        let request = HttpHeaderCheckRequest {
            url: "https://httpbin.org/get".to_string(),
            method: HttpMethod::HEAD,
            custom_headers: vec![],
            body: None,
            content_type: None,
        };
        let result = http_header_check(&request).await;
        result.unwrap_or_else(|e| panic!("HEAD request failed (network issue?): {e}"));
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_http_header_check_auto_https_prefix() {
        let request = HttpHeaderCheckRequest {
            url: "httpbin.org/get".to_string(),
            method: HttpMethod::GET,
            custom_headers: vec![],
            body: None,
            content_type: None,
        };
        let result = http_header_check(&request).await;
        let check = result
            .unwrap_or_else(|e| panic!("Auto HTTPS prefix test failed (network issue?): {e}"));
        assert!(
            check.url.starts_with("https://"),
            "URL should have been prefixed with https://, got: {}",
            check.url
        );
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_http_header_check_custom_headers_real() {
        let request = HttpHeaderCheckRequest {
            url: "https://httpbin.org/get".to_string(),
            method: HttpMethod::GET,
            custom_headers: vec![HttpHeader {
                name: "X-Custom-Header".to_string(),
                value: "test-value".to_string(),
            }],
            body: None,
            content_type: None,
        };
        let result = http_header_check(&request).await;
        let check =
            result.unwrap_or_else(|e| panic!("Custom headers test failed (network issue?): {e}"));
        assert!(
            check.raw_request.contains("X-Custom-Header: test-value"),
            "raw_request should contain custom header, got:\n{}",
            check.raw_request
        );
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_http_header_check_with_body_real() {
        let request = HttpHeaderCheckRequest {
            url: "https://httpbin.org/post".to_string(),
            method: HttpMethod::POST,
            custom_headers: vec![],
            body: Some("{\"key\": \"value\"}".to_string()),
            content_type: Some("application/json".to_string()),
        };
        let result = http_header_check(&request).await;
        result.unwrap_or_else(|e| panic!("POST with body test failed (network issue?): {e}"));
    }

    #[tokio::test]
    async fn test_http_header_check_invalid_url() {
        let request = HttpHeaderCheckRequest {
            url: "not a valid url at all !!!".to_string(),
            method: HttpMethod::GET,
            custom_headers: vec![],
            body: None,
            content_type: None,
        };
        let result = http_header_check(&request).await;
        assert!(result.is_err());
    }
}
