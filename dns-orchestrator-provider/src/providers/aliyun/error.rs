//! 阿里云错误映射

use crate::error::ProviderError;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

use super::AliyunProvider;

/// 阿里云错误码映射
/// 参考: <https://api.aliyun.com/document/Alidns/2015-01-09/errorCode>
impl ProviderErrorMapper for AliyunProvider {
    fn provider_name(&self) -> &'static str {
        "aliyun"
    }

    fn map_error(&self, raw: RawApiError, context: ErrorContext) -> ProviderError {
        match raw.code.as_deref() {
            // ============ 认证错误 ============
            Some("InvalidAccessKeyId.NotFound" | "SignatureDoesNotMatch") => {
                ProviderError::InvalidCredentials {
                    provider: self.provider_name().to_string(),
                    raw_message: Some(raw.message),
                }
            }

            // ============ 记录已存在 ============
            Some("DomainRecordDuplicate" | "DomainRecordConflict") => ProviderError::RecordExists {
                provider: self.provider_name().to_string(),
                record_name: context
                    .record_name
                    .unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ 记录不存在 ============
            Some(
                "DomainRecordNotBelongToUser"
                | "InvalidRecordId.NotFound"
                | "InvalidRR.NoExist"
                | "PdnsRecord.NotExists",
            ) => ProviderError::RecordNotFound {
                provider: self.provider_name().to_string(),
                record_id: context.record_id.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ 域名不存在 ============
            Some("InvalidDomainName.NoExist" | "DomainNotFound" | "PdnsZone.NotExists") => {
                ProviderError::DomainNotFound {
                    provider: self.provider_name().to_string(),
                    domain: context.domain.unwrap_or_else(|| "<unknown>".to_string()),
                    raw_message: Some(raw.message),
                }
            }

            // ============ 配额限制 ============
            Some(
                "QuotaExceeded.ARecord"
                | "QuotaExceeded.Record"
                | "QuotaExceeded.FreeDnsRecord"
                | "QuotaExceeded.SubDomain"
                | "QuotaExceeded.TTL"
                | "QuotaExceeded.AliasRecord"
                | "QuotaExceeded.ALIASRecord"
                | "QuotaExceeded.HTTPSRecord"
                | "QuotaExceeded.SVCBRecord"
                | "LineDnsSlb.QuotaExceeded",
            ) => ProviderError::QuotaExceeded {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ 频率限流（可重试） ============
            Some("Throttling" | "Throttling.User") => ProviderError::RateLimited {
                provider: self.provider_name().to_string(),
                retry_after: None,
                raw_message: Some(raw.message),
            },

            // ============ 域名被锁定/禁用 ============
            Some(
                "DomainRecordLocked"
                | "DomainExpiredDNSForbidden"
                | "Forbidden.DomainExpired"
                | "RecordForbidden.BlackHole"
                | "RecordFobidden.BlackHole",
            ) => ProviderError::DomainLocked {
                provider: self.provider_name().to_string(),
                domain: context.domain.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ 权限/操作被拒绝 ============
            Some(
                "Forbidden"
                | "Forbidden.RiskControl"
                | "OperationDomain.NoPermission"
                | "IllegalUser"
                | "IncorrectDomainUser",
            ) => ProviderError::PermissionDenied {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ 参数无效 - 记录类型 ============
            Some("InvalidRR.TypeEmpty" | "SubDomainInvalid.Type" | "PdnsRecord.InvalidType") => {
                ProviderError::InvalidParameter {
                    provider: self.provider_name().to_string(),
                    param: "type".to_string(),
                    detail: raw.message,
                }
            }

            // ============ 参数无效 - 记录值 ============
            Some(
                "InvalidRR.AValue"
                | "InvalidRR.AAAAValue"
                | "InvalidRR.MXValue"
                | "InvalidRR.NSValue"
                | "PdnsRecord.InvalidRecordValue",
            ) => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "value".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 主机记录 ============
            Some(
                "InvalidRR.RrEmpty" | "InvalidRR.Format" | "Record.Invalid.Rr" | "InvalidRR.Length",
            ) => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "rr".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - TTL ============
            Some("SubDomainInvalid.TTL" | "PdnsRecord.InvalidTtl") => {
                ProviderError::InvalidParameter {
                    provider: self.provider_name().to_string(),
                    param: "ttl".to_string(),
                    detail: raw.message,
                }
            }

            // ============ 参数无效 - 线路 ============
            Some("SubDomainInvalid.Line" | "UnsupportedLine") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "line".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - MX优先级 ============
            Some("SubDomainInvalid.Priority") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "priority".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 域名格式 ============
            Some(
                "InvalidDomainName.Format"
                | "InvalidDomainName.Suffix"
                | "InvalidDomainName.Length"
                | "DomainEmpty"
                | "PdnsZone.InvalidZoneName",
            ) => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "domain".to_string(),
                detail: raw.message,
            },

            // ============ 其他错误 fallback ============
            _ => self.unknown_error(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

    fn provider() -> AliyunProvider {
        AliyunProvider::new(String::new(), String::new())
    }

    fn default_ctx() -> ErrorContext {
        ErrorContext::default()
    }

    // ---- 1. Auth errors ----

    #[test]
    fn map_invalid_access_key_id() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("InvalidAccessKeyId.NotFound", "key not found"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    #[test]
    fn map_signature_does_not_match() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("SignatureDoesNotMatch", "bad signature"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::InvalidCredentials { .. }));
    }

    // ---- 2. Record exists ----

    #[test]
    fn map_domain_record_duplicate() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DomainRecordDuplicate", "duplicate record"),
            ErrorContext {
                record_name: Some("www".to_string()),
                ..Default::default()
            },
        );
        assert!(matches!(err, ProviderError::RecordExists { .. }));
    }

    #[test]
    fn map_domain_record_conflict() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DomainRecordConflict", "conflict"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::RecordExists { .. }));
    }

    // ---- 3. Record not found ----

    #[test]
    fn map_domain_record_not_belong_to_user() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DomainRecordNotBelongToUser", "not yours"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::RecordNotFound { .. }));
    }

    #[test]
    fn map_invalid_record_id_not_found() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("InvalidRecordId.NotFound", "no such record"),
            ErrorContext {
                record_id: Some("12345".to_string()),
                ..Default::default()
            },
        );
        assert!(matches!(err, ProviderError::RecordNotFound { .. }));
    }

    #[test]
    fn map_pdns_record_not_exists() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("PdnsRecord.NotExists", "not exists"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::RecordNotFound { .. }));
    }

    // ---- 4. Domain not found ----

    #[test]
    fn map_invalid_domain_name_no_exist() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("InvalidDomainName.NoExist", "domain not found"),
            ErrorContext {
                domain: Some("example.com".to_string()),
                ..Default::default()
            },
        );
        assert!(matches!(err, ProviderError::DomainNotFound { .. }));
    }

    #[test]
    fn map_domain_not_found() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DomainNotFound", "not found"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::DomainNotFound { .. }));
    }

    #[test]
    fn map_pdns_zone_not_exists() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("PdnsZone.NotExists", "zone missing"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::DomainNotFound { .. }));
    }

    // ---- 5. Quota exceeded ----

    #[test]
    fn map_quota_exceeded_a_record() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("QuotaExceeded.ARecord", "too many A records"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::QuotaExceeded { .. }));
    }

    #[test]
    fn map_quota_exceeded_record() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("QuotaExceeded.Record", "limit reached"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::QuotaExceeded { .. }));
    }

    // ---- 6. Rate limited ----

    #[test]
    fn map_throttling() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("Throttling", "slow down"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::RateLimited { .. }));
    }

    #[test]
    fn map_throttling_user() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("Throttling.User", "user throttled"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::RateLimited { .. }));
    }

    // ---- 7. Domain locked ----

    #[test]
    fn map_domain_record_locked() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("DomainRecordLocked", "record is locked"),
            ErrorContext {
                domain: Some("example.com".to_string()),
                ..Default::default()
            },
        );
        assert!(matches!(err, ProviderError::DomainLocked { .. }));
    }

    // ---- 8. Permission denied ----

    #[test]
    fn map_forbidden() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("Forbidden", "access denied"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::PermissionDenied { .. }));
    }

    #[test]
    fn map_forbidden_risk_control() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("Forbidden.RiskControl", "risk control"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::PermissionDenied { .. }));
    }

    // ---- 9. Invalid parameter: type ----

    #[test]
    fn map_invalid_rr_type_empty() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("InvalidRR.TypeEmpty", "type is empty"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "type"
        ));
    }

    // ---- 10. Invalid parameter: value ----

    #[test]
    fn map_invalid_rr_a_value() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("InvalidRR.AValue", "bad A value"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "value"
        ));
    }

    // ---- 11. Invalid parameter: rr ----

    #[test]
    fn map_invalid_rr_rr_empty() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("InvalidRR.RrEmpty", "rr is empty"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "rr"
        ));
    }

    // ---- 12. Invalid parameter: ttl ----

    #[test]
    fn map_subdomain_invalid_ttl() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("SubDomainInvalid.TTL", "invalid ttl"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "ttl"
        ));
    }

    // ---- 13. Invalid parameter: line ----

    #[test]
    fn map_subdomain_invalid_line() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("SubDomainInvalid.Line", "invalid line"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "line"
        ));
    }

    // ---- 14. Invalid parameter: priority ----

    #[test]
    fn map_subdomain_invalid_priority() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("SubDomainInvalid.Priority", "invalid priority"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "priority"
        ));
    }

    // ---- 15. Invalid parameter: domain ----

    #[test]
    fn map_invalid_domain_name_format() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("InvalidDomainName.Format", "bad domain format"),
            default_ctx(),
        );
        assert!(matches!(
            err,
            ProviderError::InvalidParameter { ref param, .. } if param == "domain"
        ));
    }

    // ---- 16. Fallback: unknown code ----

    #[test]
    fn map_unknown_error_code() {
        let p = provider();
        let err = p.map_error(
            RawApiError::with_code("SomeWeirdCode.NeverSeen", "weird stuff"),
            default_ctx(),
        );
        assert!(matches!(err, ProviderError::Unknown { .. }));
    }

    // ---- 17. Fallback: no code ----

    #[test]
    fn map_no_error_code() {
        let p = provider();
        let err = p.map_error(RawApiError::new("something went wrong"), default_ctx());
        assert!(matches!(err, ProviderError::Unknown { .. }));
    }
}
