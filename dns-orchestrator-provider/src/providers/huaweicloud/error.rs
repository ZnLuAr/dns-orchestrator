//! Huawei cloud error mapping
//!
//! Reference: <https://support.huaweicloud.com/api-dns/ErrorCode.html>
//!
//! ## Error code classification (29 core error codes in total)
//!
//! - **Authentication Error (7)**: APIGW.0301, APIGW.0101, APIGW.0303, APIGW.0305, DNS.0005, DNS.0013, DNS.0040
//! - **Permission Denied (4)**: APIGW.0302, APIGW.0306, DNS.0030, DNS.1802
//! - **Quota exceeded (8)**: DNS.0403, DNS.0404, DNS.0405, DNS.0408, DNS.0409, APIGW.0308, DNS.0021, DNS.2002
//! - **Record Operations (4)**: DNS.0312, DNS.0335, DNS.0016 (`RecordExists`), DNS.0313, DNS.0004 (`RecordNotFound`)
//! - **Domain Name Operation (6)**: DNS.0302, DNS.0301, DNS.1206 (`DomainNotFound`), DNS.0213, DNS.0214, DNS.0209 (`DomainLocked`)
//! - **Parameter errors (various)**: DNS.0303(ttl), DNS.0307(type), DNS.0308(value), DNS.0304(name), etc.
//! - **Network Error (5)**: APIGW.0201, DNS.0012, DNS.0015, DNS.0022, DNS.0036
//!
//! ## Unmapped special functions (fallback to Unknown)
//!
//! - Health Check (DNS.11xx): Project not in use
//! - VPC association (DNS.07xx): Project uses Public Zone
//! - PTR record (DNS.05xx): reverse resolution, not used by the project
//! - DNSSEC (DNS.23xx): advanced features
//! - Enterprise Project (DNS.19xx): Enterprise Features

use crate::error::ProviderError;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

use super::HuaweicloudProvider;

/// Huawei Cloud error code mapping implementation
impl ProviderErrorMapper for HuaweicloudProvider {
    fn provider_name(&self) -> &'static str {
        "huaweicloud"
    }

    fn map_error(&self, raw: RawApiError, context: ErrorContext) -> ProviderError {
        match raw.code.as_deref() {
            // ============ Authentication error ============
            Some(
                "APIGW.0301" // IAM authentication information error
                | "APIGW.0101" // API does not exist/is not published (wrong authentication path)
                | "APIGW.0303" // APP authentication information error
                | "APIGW.0305" // Generic authentication error
                | "DNS.0005"   // Permission authentication failed
                | "DNS.0013"   // No permission to operate API
                | "DNS.0040",  // The account has not been authenticated by real name
            ) => ProviderError::InvalidCredentials {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ Permission/Operation Denied ============
            Some(
                "APIGW.0302" // IAM users are not allowed access (black/white list restrictions)
                | "APIGW.0306" // API access denied
                | "DNS.0030"   // Operation of this resource is not allowed
                | "DNS.1802",  // Policy does not allow operation
            ) => ProviderError::PermissionDenied {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ Quota limit (resources run out, no retry) ============
            Some(
                "DNS.0403"     // Insufficient Record Set quota
                | "DNS.0404"   // Insufficient Zone quota
                | "DNS.0405"   // Insufficient PTR quota
                | "DNS.0408"   // Insufficient custom line quota
                | "DNS.0409"   // Insufficient line grouping quota
                | "DNS.0021"   // Unable to acquire lock (concurrency violation)
                | "DNS.2002",  // Insufficient tenant quota
            ) => ProviderError::QuotaExceeded {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ Frequency limiting (can be retried) ============
            Some("APIGW.0308") => ProviderError::RateLimited { // Flow control threshold reached (429)
                provider: self.provider_name().to_string(),
                retry_after: None,
                raw_message: Some(raw.message),
            },

            // ============ Record already exists ============
            Some(
                "DNS.0312"     // Recordset name already exists
                | "DNS.0335"   // Duplicate recordset exists
                | "DNS.0016",  // The record already exists or conflicts
            ) => ProviderError::RecordExists {
                provider: self.provider_name().to_string(),
                record_name: context.record_name.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ Record does not exist ============
            Some("DNS.0313" | "DNS.0004") => ProviderError::RecordNotFound {
                provider: self.provider_name().to_string(),
                record_id: context.record_id.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ The domain name does not exist ============
            Some(
                "DNS.0302"     // Zone does not exist
                | "DNS.0101"   // Zone does not exist (old error codes remain for compatibility)
                | "DNS.1206",  // Invalid domain name
            ) => ProviderError::DomainNotFound {
                provider: self.provider_name().to_string(),
                domain: context.domain.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ Domain name is locked/disabled ============
            Some(
                "DNS.0213"     // Domain name has been suspended
                | "DNS.0214"   // The domain name is in an abnormal state
                | "DNS.0209"   // The domain name is not in normal status
                | "DNS.2003"   // Police freeze
                | "DNS.2005"   // Police freeze
                | "DNS.2006",  // Domain name freezing
            ) => ProviderError::DomainLocked {
                provider: self.provider_name().to_string(),
                domain: context.domain.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ Invalid parameter - TTL ============
            Some("DNS.0303" | "DNS.0319") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "ttl".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - record type ============
            Some("DNS.0307") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "type".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - record value ============
            Some("DNS.0308") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "value".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - record name ============
            Some("DNS.0304" | "DNS.0202") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "name".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - subdomain level ============
            Some("DNS.0321") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "subdomain".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - weight ============
            Some("DNS.0323") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "weight".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - line ============
            Some(
                "DNS.0806"     // Line not supported
                | "DNS.1601"   // Invalid line ID
                | "DNS.1602"   // Invalid line name
                | "DNS.1604",  // Line does not exist
            ) => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "line".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - line grouping ============
            Some(
                "DNS.1702"     // Line group contains invalid lines
                | "DNS.1704"   // Line group name already exists
                | "DNS.1706"   // Line group contains duplicate lines
                | "DNS.1707",  // Line grouping does not exist
            ) => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "line_group".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - Record ID ============
            Some("DNS.0309") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "record_id".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - description ============
            Some("DNS.0206" | "DNS.0305") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "description".to_string(),
                detail: raw.message,
            },

            // ============ Network/Backend Service Error ============
            Some(
                "APIGW.0201"   // Request malformed/backend unavailable/timed out
                | "DNS.0012"   // VPC service exception
                | "DNS.0015"   // IAM service exception
                | "DNS.0022"   // Cloud Eye service abnormality
                | "DNS.0036",  // Neutron service exception
            ) => ProviderError::NetworkError {
                provider: self.provider_name().to_string(),
                detail: raw.message,
            },

            // ============ Other errors fallback ============
            _ => self.unknown_error(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

    fn provider() -> HuaweicloudProvider {
        HuaweicloudProvider::new(String::new(), String::new())
    }

    fn default_ctx() -> ErrorContext {
        ErrorContext::default()
    }

    fn ctx_with_record(name: &str, id: &str) -> ErrorContext {
        ErrorContext {
            record_name: Some(name.to_string()),
            record_id: Some(id.to_string()),
            domain: None,
        }
    }

    fn ctx_with_domain(domain: &str) -> ErrorContext {
        ErrorContext {
            record_name: None,
            record_id: None,
            domain: Some(domain.to_string()),
        }
    }

    // ============ 1. Authentication error ============

    #[test]
    fn auth_apigw_0301() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("APIGW.0301", "iam auth failed"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    #[test]
    fn auth_apigw_0101() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("APIGW.0101", "api not found"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    #[test]
    fn auth_dns_0005() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0005", "auth failed"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    #[test]
    fn auth_dns_0040() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0040", "not verified"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    // ============ 2. Permission Denied ============

    #[test]
    fn permission_apigw_0302() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("APIGW.0302", "access denied"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::PermissionDenied { .. }));
    }

    #[test]
    fn permission_dns_0030() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0030", "resource forbidden"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::PermissionDenied { .. }));
    }

    #[test]
    fn permission_dns_1802() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.1802", "policy denied"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::PermissionDenied { .. }));
    }

    // ============ 3. Quota exceeded ============

    #[test]
    fn quota_dns_0403() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0403", "recordset quota"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::QuotaExceeded { .. }));
    }

    #[test]
    fn quota_dns_0404() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0404", "zone quota"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::QuotaExceeded { .. }));
    }

    #[test]
    fn quota_dns_2002() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.2002", "tenant quota"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::QuotaExceeded { .. }));
    }

    // ============ 4. Frequency limiting ============

    #[test]
    fn rate_limited_apigw_0308() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("APIGW.0308", "throttled"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::RateLimited {
                retry_after: None,
                ..
            }
        ));
    }

    // ============ 5. The record already exists ============

    #[test]
    fn record_exists_dns_0312() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0312", "name exists"),
            ctx_with_record("www", ""),
        );
        assert!(matches!(err, ProviderError::RecordExists { .. }));
    }

    #[test]
    fn record_exists_dns_0335() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0335", "duplicate"),
            ctx_with_record("mx", ""),
        );
        assert!(matches!(err, ProviderError::RecordExists { .. }));
    }

    #[test]
    fn record_exists_dns_0016() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0016", "conflict"),
            ctx_with_record("txt", ""),
        );
        assert!(matches!(err, ProviderError::RecordExists { .. }));
    }

    // ============ 6. The record does not exist ============

    #[test]
    fn record_not_found_dns_0313() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0313", "not found"),
            ctx_with_record("", "rec-123"),
        );
        assert!(matches!(err, ProviderError::RecordNotFound { .. }));
    }

    #[test]
    fn record_not_found_dns_0004() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0004", "not found"),
            ctx_with_record("", "rec-456"),
        );
        assert!(matches!(err, ProviderError::RecordNotFound { .. }));
    }

    // ============ 7. The domain name does not exist ============

    #[test]
    fn domain_not_found_dns_0302() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0302", "zone not found"),
            ctx_with_domain("example.com"),
        );
        assert!(matches!(err, ProviderError::DomainNotFound { .. }));
    }

    #[test]
    fn domain_not_found_dns_0101() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0101", "zone not found"),
            ctx_with_domain("example.com"),
        );
        assert!(matches!(err, ProviderError::DomainNotFound { .. }));
    }

    #[test]
    fn domain_not_found_dns_1206() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.1206", "invalid domain"),
            ctx_with_domain("bad.example"),
        );
        assert!(matches!(err, ProviderError::DomainNotFound { .. }));
    }

    // ============ 8. Domain name is locked ============

    #[test]
    fn domain_locked_dns_0213() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0213", "suspended"),
            ctx_with_domain("locked.com"),
        );
        assert!(matches!(err, ProviderError::DomainLocked { .. }));
    }

    #[test]
    fn domain_locked_dns_0214() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0214", "abnormal"),
            ctx_with_domain("locked.com"),
        );
        assert!(matches!(err, ProviderError::DomainLocked { .. }));
    }

    #[test]
    fn domain_locked_dns_0209() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0209", "not normal"),
            ctx_with_domain("locked.com"),
        );
        assert!(matches!(err, ProviderError::DomainLocked { .. }));
    }

    #[test]
    fn domain_locked_dns_2003() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.2003", "frozen"),
            ctx_with_domain("locked.com"),
        );
        assert!(matches!(err, ProviderError::DomainLocked { .. }));
    }

    // ============ 9. Invalid parameter - TTL ============

    #[test]
    fn invalid_param_ttl_dns_0303() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0303", "ttl invalid"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "ttl"
        ));
    }

    #[test]
    fn invalid_param_ttl_dns_0319() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0319", "ttl out of range"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "ttl"
        ));
    }

    // ============ 10. Invalid parameter - type ============

    #[test]
    fn invalid_param_type_dns_0307() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0307", "bad type"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "type"
        ));
    }

    // ============ 11. Invalid parameter - value ============

    #[test]
    fn invalid_param_value_dns_0308() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0308", "bad value"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "value"
        ));
    }

    // ============ 12. Invalid parameter - name ============

    #[test]
    fn invalid_param_name_dns_0304() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0304", "bad name"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "name"
        ));
    }

    // ============ 13. Invalid parameter - subdomain ============

    #[test]
    fn invalid_param_subdomain_dns_0321() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0321", "too deep"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "subdomain"
        ));
    }

    // ============ 14. Invalid parameter - weight ============

    #[test]
    fn invalid_param_weight_dns_0323() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0323", "bad weight"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "weight"
        ));
    }

    // ============ 15. Invalid parameter - line ============

    #[test]
    fn invalid_param_line_dns_0806() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0806", "unsupported line"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "line"
        ));
    }

    // ============ 16. Invalid parameter - line_group ============

    #[test]
    fn invalid_param_line_group_dns_1702() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.1702", "invalid line in group"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "line_group"
        ));
    }

    // ============ 17. Invalid parameter - record_id ============

    #[test]
    fn invalid_param_record_id_dns_0309() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0309", "bad record id"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "record_id"
        ));
    }

    // ============ 18. Invalid parameter - description ============

    #[test]
    fn invalid_param_description_dns_0206() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0206", "description too long"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "description"
        ));
    }

    // ============ 19. Network error ============

    #[test]
    fn network_error_apigw_0201() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("APIGW.0201", "backend unavailable"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::NetworkError { .. }));
    }

    #[test]
    fn network_error_dns_0012() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0012", "vpc error"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::NetworkError { .. }));
    }

    // ============ 20. Fallback - unknown code ============

    #[test]
    fn fallback_unknown_code() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("TOTALLY.UNKNOWN", "mystery error"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::Unknown {
                ref raw_code,
                ref raw_message,
                ..
            } if raw_code.as_deref() == Some("TOTALLY.UNKNOWN")
                && raw_message == "mystery error"
        ));
    }

    // ============ 21. Fallback - no code ============

    #[test]
    fn fallback_no_code() {
        let p = provider();
        let err = p.map_error(RawApiError::new("something broke"), default_ctx());
        assert!(matches!(
            err,
            ProviderError::Unknown {
                ref raw_code,
                ref raw_message,
                ..
            } if raw_code.is_none() && raw_message == "something broke"
        ));
    }

    // ============ Verification provider_name ============

    #[test]
    fn provider_name_is_huaweicloud() {
        let p = provider();
        assert_eq!(p.provider_name(), "huaweicloud");
    }

    // ============ Validation context field delivery ============

    #[test]
    fn record_exists_carries_record_name() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0312", "exists"),
            ctx_with_record("www.example.com", ""),
        );
        assert!(matches!(
            err,
            ProviderError::RecordExists { record_name, .. } if record_name == "www.example.com"
        ));
    }

    #[test]
    fn record_not_found_carries_record_id() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0313", "not found"),
            ctx_with_record("", "rec-abc-123"),
        );
        assert!(matches!(
            err,
            ProviderError::RecordNotFound { record_id, .. } if record_id == "rec-abc-123"
        ));
    }

    #[test]
    fn domain_not_found_carries_domain() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0302", "zone gone"),
            ctx_with_domain("example.org"),
        );
        assert!(matches!(
            err,
            ProviderError::DomainNotFound { domain, .. } if domain == "example.org"
        ));
    }

    #[test]
    fn domain_locked_carries_domain() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DNS.0213", "suspended"),
            ctx_with_domain("frozen.io"),
        );
        assert!(matches!(
            err,
            ProviderError::DomainLocked { domain, .. } if domain == "frozen.io"
        ));
    }

    #[test]
    fn default_context_yields_unknown_placeholder() {
        let p = provider();
        let err = p.map_error(RawApiError::with_code("DNS.0312", "exists"), default_ctx());
        assert!(matches!(
            err,
            ProviderError::RecordExists { record_name, .. } if record_name == "<unknown>"
        ));
    }
}
