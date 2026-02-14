//! Cloudflare error mapping

use crate::error::ProviderError;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

use super::CloudflareProvider;

/// Cloudflare error code mapping
/// Reference: <https://api.cloudflare.com/#getting-started-responses>
impl ProviderErrorMapper for CloudflareProvider {
    fn provider_name(&self) -> &'static str {
        "cloudflare"
    }

    fn map_error(&self, raw: RawApiError, context: ErrorContext) -> ProviderError {
        match raw.code.as_deref() {
            // Authentication error
            // 6003: Invalid request headers
            // 6103: Invalid format for X-Auth-Key header
            // 6111: Invalid format for Authorization header
            // 9109: Unauthorized to access requested resource / Max auth failures reached
            // 10000: Authentication error
            Some("6003" | "6103" | "6111" | "9109" | "10000") => {
                ProviderError::InvalidCredentials {
                    provider: self.provider_name().to_string(),
                    raw_message: Some(raw.message),
                }
            }

            // Invalid parameter
            // 1004: DNS Validation Error
            // 9000: Invalid or missing name
            // 9005: Content for A record is invalid. Must be a valid IPv4 address
            // 9006: Content for AAAA record is invalid. Must be a valid IPv6 address
            // 9009: Content for MX record must be a hostname
            // 9021: Invalid TTL. Must be between 120 and 2147483647 seconds or 1 for automatic
            // 9041: This DNS record cannot be proxied
            Some(code @ ("1004" | "9000" | "9005" | "9006" | "9009" | "9021" | "9041")) => {
                let param = match code {
                    "9000" => "name",
                    "9005" | "9006" | "9009" => "value",
                    "9021" => "ttl",
                    "9041" => "proxied",
                    // "1004" is a general validation error.
                    _ => "general",
                };
                ProviderError::InvalidParameter {
                    provider: self.provider_name().to_string(),
                    param: param.to_string(),
                    detail: raw.message,
                }
            }

            // record already exists
            // 81053: An A AAAA or CNAME record already exists with that host
            // 81054: A CNAME record with that host already exists
            // 81055: An A record with that host already exists
            // 81056: NS records with that host already exist
            // 81057: The record already exists
            // 81058: A record with those settings already exists
            Some("81053" | "81054" | "81055" | "81056" | "81057" | "81058") => {
                ProviderError::RecordExists {
                    provider: self.provider_name().to_string(),
                    record_name: context
                        .record_name
                        .unwrap_or_else(|| "<unknown>".to_string()),
                    raw_message: Some(raw.message),
                }
            }

            // Record does not exist
            // 81044: Record does not exist
            Some("81044") => ProviderError::RecordNotFound {
                provider: self.provider_name().to_string(),
                record_id: context.record_id.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // Quota exceeded
            // 81045: The record quota has been exceeded
            Some("81045") => ProviderError::QuotaExceeded {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // Zone/domain name does not exist
            // 7000: No route for that URI
            // 7003: Could not route to /path. perhaps your object identifier is invalid?
            Some("7000" | "7003") => ProviderError::DomainNotFound {
                provider: self.provider_name().to_string(),
                domain: context.domain.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // Other error fallback
            _ => self.unknown_error(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

    fn provider() -> CloudflareProvider {
        CloudflareProvider::new(String::new())
    }

    fn ctx() -> ErrorContext {
        ErrorContext::default()
    }

    fn ctx_with_record() -> ErrorContext {
        ErrorContext {
            record_name: Some("www".to_string()),
            record_id: Some("rec-123".to_string()),
            domain: Some("example.com".to_string()),
        }
    }

    // ---- Auth errors ----

    #[test]
    fn auth_error_6003() {
        let p = provider();
        let err = p.map_error(RawApiError::with_code("6003", "bad header"), ctx());
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    #[test]
    fn auth_error_6103() {
        let p = provider();
        let err = p.map_error(RawApiError::with_code("6103", "invalid X-Auth-Key"), ctx());
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    #[test]
    fn auth_error_6111() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("6111", "invalid Authorization header"),
            ctx(),
        );
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    #[test]
    fn auth_error_9109() {
        let p = provider();
        let err = p.map_error(RawApiError::with_code("9109", "unauthorized"), ctx());
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    #[test]
    fn auth_error_10000() {
        let p = provider();
        let err = p.map_error(RawApiError::with_code("10000", "auth error"), ctx());
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    // ---- Invalid parameter errors ----

    #[test]
    fn invalid_param_1004_general() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("1004", "DNS validation error"),
            ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { param, .. } if param == "general"
        ));
    }

    #[test]
    fn invalid_param_9000_name() {
        let p = provider();
        let err = p.map_error(RawApiError::with_code("9000", "invalid name"), ctx());
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { param, .. } if param == "name"
        ));
    }

    #[test]
    fn invalid_param_9005_value() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("9005", "invalid A record content"),
            ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { param, .. } if param == "value"
        ));
    }

    #[test]
    fn invalid_param_9006_value() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("9006", "invalid AAAA record content"),
            ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { param, .. } if param == "value"
        ));
    }

    #[test]
    fn invalid_param_9009_value() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("9009", "MX content must be hostname"),
            ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { param, .. } if param == "value"
        ));
    }

    #[test]
    fn invalid_param_9021_ttl() {
        let p = provider();
        let err = p.map_error(RawApiError::with_code("9021", "invalid TTL"), ctx());
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { param, .. } if param == "ttl"
        ));
    }

    #[test]
    fn invalid_param_9041_proxied() {
        let p = provider();
        let err = p.map_error(RawApiError::with_code("9041", "cannot be proxied"), ctx());
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { param, .. } if param == "proxied"
        ));
    }

    // ---- Record exists ----

    #[test]
    fn record_exists_81057() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("81057", "record already exists"),
            ctx_with_record(),
        );
        assert!(matches!(
            err,
            ProviderError::RecordExists { record_name, .. } if record_name == "www"
        ));
    }

    #[test]
    fn record_exists_81053() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("81053", "A/AAAA/CNAME already exists"),
            ctx_with_record(),
        );
        assert!(matches!(err, ProviderError::RecordExists { .. }));
    }

    // ---- Record not found ----

    #[test]
    fn record_not_found_81044() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("81044", "record does not exist"),
            ctx_with_record(),
        );
        assert!(matches!(
            err,
            ProviderError::RecordNotFound { record_id, .. } if record_id == "rec-123"
        ));
    }

    // ---- Quota exceeded ----

    #[test]
    fn quota_exceeded_81045() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("81045", "record quota exceeded"),
            ctx(),
        );
        assert!(matches!(err, ProviderError::QuotaExceeded { .. }));
    }

    // ---- Domain not found ----

    #[test]
    fn domain_not_found_7000() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("7000", "no route"),
            ctx_with_record(),
        );
        assert!(matches!(
            err,
            ProviderError::DomainNotFound { domain, .. } if domain == "example.com"
        ));
    }

    #[test]
    fn domain_not_found_7003() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("7003", "could not route"),
            ctx_with_record(),
        );
        assert!(matches!(err, ProviderError::DomainNotFound { .. }));
    }

    // ---- Fallback: unknown code ----

    #[test]
    fn fallback_unknown_code() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("99999", "something unexpected"),
            ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::Unknown { raw_code, raw_message, .. }
                if raw_code.as_deref() == Some("99999") && raw_message == "something unexpected"
        ));
    }

    // ---- Fallback: no code (None) ----

    #[test]
    fn fallback_no_code() {
        let p = provider();
        let err = p.map_error(RawApiError::new("no code at all"), ctx());
        assert!(matches!(
            err,
            ProviderError::Unknown { raw_code: None, raw_message, .. }
                if raw_message == "no code at all"
        ));
    }

    // ---- Context defaults ----

    #[test]
    fn record_exists_default_context() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("81057", "record already exists"),
            ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::RecordExists { record_name, .. } if record_name == "<unknown>"
        ));
    }

    #[test]
    fn record_not_found_default_context() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("81044", "record does not exist"),
            ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::RecordNotFound { record_id, .. } if record_id == "<unknown>"
        ));
    }

    #[test]
    fn domain_not_found_default_context() {
        let p = provider();
        let err = p.map_error(RawApiError::with_code("7000", "no route"), ctx());
        assert!(matches!(
            err,
            ProviderError::DomainNotFound { domain, .. } if domain == "<unknown>"
        ));
    }

    // ---- Provider name ----

    #[test]
    fn provider_name_is_cloudflare() {
        let p = provider();
        assert_eq!(p.provider_name(), "cloudflare");
    }

    #[test]
    fn error_contains_provider_name() {
        let p = provider();
        let err = p.map_error(RawApiError::with_code("6003", "bad header"), ctx());
        assert!(matches!(
            err,
            ProviderError::InvalidCredentials { provider, .. } if provider == "cloudflare"
        ));
    }
}
