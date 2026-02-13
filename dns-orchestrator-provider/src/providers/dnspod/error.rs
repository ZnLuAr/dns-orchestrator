//! `DNSPod` 错误映射

use crate::error::ProviderError;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

use super::DnspodProvider;

/// `DNSPod` 错误码映射
/// 参考: <https://cloud.tencent.com/document/api/1427/56192>
impl ProviderErrorMapper for DnspodProvider {
    fn provider_name(&self) -> &'static str {
        "dnspod"
    }

    fn map_error(&self, raw: RawApiError, context: ErrorContext) -> ProviderError {
        match raw.code.as_deref() {
            // ============ 认证错误 ============
            Some(
                "AuthFailure"
                | "AuthFailure.InvalidAuthorization"
                | "AuthFailure.InvalidSecretId"
                | "AuthFailure.MFAFailure"
                | "AuthFailure.SecretIdNotFound"
                | "AuthFailure.SignatureExpire"
                | "AuthFailure.SignatureFailure"
                | "AuthFailure.TokenFailure"
                | "AuthFailure.UnauthorizedOperation"
                | "InvalidParameter.InvalidSecretId"
                | "InvalidParameter.InvalidSignature"
                | "InvalidParameter.PermissionDenied"
                | "InvalidParameter.LoginTokenIdError"
                | "InvalidParameter.LoginTokenNotExists"
                | "InvalidParameter.LoginTokenValidateFailed",
            ) => ProviderError::InvalidCredentials {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message.clone()),
            },

            // ============ 配额限制（资源用完，不可重试） ============
            Some(
                "LimitExceeded"
                | "LimitExceeded.AAAACountLimit"
                | "LimitExceeded.AtNsRecordLimit"
                | "LimitExceeded.CustomLineLimited"
                | "LimitExceeded.DomainAliasCountExceeded"
                | "LimitExceeded.DomainAliasNumberLimit"
                | "LimitExceeded.FailedLoginLimitExceeded"
                | "LimitExceeded.GroupNumberLimit"
                | "LimitExceeded.HiddenUrlExceeded"
                | "LimitExceeded.NsCountLimit"
                | "LimitExceeded.OffsetExceeded"
                | "LimitExceeded.SrvCountLimit"
                | "LimitExceeded.SubdomainLevelLimit"
                | "LimitExceeded.SubdomainRollLimit"
                | "LimitExceeded.SubdomainWcardLimit"
                | "LimitExceeded.UrlCountLimit"
                | "RequestLimitExceeded.GlobalRegionUinLimitExceeded"
                | "RequestLimitExceeded.IPLimitExceeded"
                | "RequestLimitExceeded.UinLimitExceeded"
                | "RequestLimitExceeded.BatchTaskLimit"
                | "RequestLimitExceeded.CreateDomainLimit",
            ) => ProviderError::QuotaExceeded {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ 频率限流（临时限制，可重试） ============
            Some(
                "RequestLimitExceeded"
                | "RequestLimitExceeded.RequestLimitExceeded"
                | "FailedOperation.FrequencyLimit"
                | "InvalidParameter.OperationIsTooFrequent",
            ) => ProviderError::RateLimited {
                provider: self.provider_name().to_string(),
                retry_after: None,
                raw_message: Some(raw.message),
            },

            // ============ 记录已存在 ============
            Some("InvalidParameter.DomainRecordExist") => ProviderError::RecordExists {
                provider: self.provider_name().to_string(),
                record_name: context.record_name.unwrap_or_default(),
                raw_message: Some(raw.message),
            },

            // ============ 域名不存在 ============
            Some("ResourceNotFound.NoDataOfDomain" | "InvalidParameterValue.DomainNotExists") => {
                ProviderError::DomainNotFound {
                    provider: self.provider_name().to_string(),
                    domain: context.domain.unwrap_or_default(),
                    raw_message: Some(raw.message),
                }
            }

            // ============ 域名被锁定/禁用 ============
            Some(
                "FailedOperation.DomainIsLocked"
                | "FailedOperation.DomainIsSpam"
                | "FailedOperation.AccountIsLocked"
                | "InvalidParameter.UserAlreadyLocked"
                | "InvalidParameter.DomainIsNotlocked"
                | "InvalidParameter.DomainNotAllowedLock",
            ) => ProviderError::DomainLocked {
                provider: self.provider_name().to_string(),
                domain: context.domain.unwrap_or_default(),
                raw_message: Some(raw.message),
            },

            // ============ 权限/操作被拒绝 ============
            Some(
                "OperationDenied"
                | "OperationDenied.AccessDenied"
                | "OperationDenied.DomainOwnerAllowedOnly"
                | "OperationDenied.NoPermissionToOperateDomain"
                | "OperationDenied.NotAdmin"
                | "OperationDenied.NotAgent"
                | "OperationDenied.NotGrantedByOwner"
                | "OperationDenied.NotManagedUser"
                | "OperationDenied.NotOrderOwner"
                | "OperationDenied.NotResourceOwner"
                | "OperationDenied.AgentDenied"
                | "OperationDenied.AgentSubordinateDenied"
                | "UnauthorizedOperation"
                | "FailedOperation.NotDomainOwner"
                | "FailedOperation.NotResourceOwner"
                | "FailedOperation.NotBatchTaskOwner"
                | "InvalidParameter.NoAuthorityToSrcDomain"
                | "InvalidParameter.NoAuthorityToTheGroup",
            ) => ProviderError::PermissionDenied {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ 参数无效 - 线路 ============
            Some("InvalidParameter.RecordLineInvalid" | "InvalidParameter.LineNotExist") => {
                ProviderError::InvalidParameter {
                    provider: self.provider_name().to_string(),
                    param: "line".to_string(),
                    detail: raw.message,
                }
            }

            // ============ 参数无效 - 记录类型 ============
            Some("InvalidParameter.RecordTypeInvalid") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "type".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 记录值 ============
            Some(
                "InvalidParameter.RecordValueInvalid" | "InvalidParameter.RecordValueLengthInvalid",
            ) => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "value".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 子域名 ============
            Some("InvalidParameter.SubdomainInvalid") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "subdomain".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - TTL ============
            Some("LimitExceeded.RecordTtlLimit") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "ttl".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - MX优先级 ============
            Some("InvalidParameter.MxInvalid") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "mx".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 域名 ============
            Some(
                "InvalidParameter.DomainIdInvalid"
                | "InvalidParameter.DomainInvalid"
                | "InvalidParameter.DomainTooLong"
                | "InvalidParameter.DomainTypeInvalid",
            ) => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "domain".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 记录ID ============
            Some("InvalidParameter.RecordIdInvalid") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "record_id".to_string(),
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
    use crate::traits::RawApiError;

    fn provider() -> DnspodProvider {
        DnspodProvider::new(String::new(), String::new())
    }

    fn default_ctx() -> ErrorContext {
        ErrorContext::default()
    }

    fn ctx_with_record_name(name: &str) -> ErrorContext {
        ErrorContext {
            record_name: Some(name.to_string()),
            ..Default::default()
        }
    }

    fn ctx_with_domain(domain: &str) -> ErrorContext {
        ErrorContext {
            domain: Some(domain.to_string()),
            ..Default::default()
        }
    }

    // ---- 认证错误 ----

    #[test]
    fn auth_failure_maps_to_invalid_credentials() {
        let p = provider();
        for code in [
            "AuthFailure",
            "AuthFailure.InvalidSecretId",
            "InvalidParameter.LoginTokenNotExists",
        ] {
            let raw = RawApiError::with_code(code, "auth failed");
            let err = p.map_error(raw, default_ctx());
            assert!(
                matches!(err, ProviderError::InvalidCredentials { .. }),
                "expected InvalidCredentials for code '{code}', got {err:?}"
            );
        }
    }

    // ---- 配额限制 ----

    #[test]
    fn quota_codes_map_to_quota_exceeded() {
        let p = provider();
        for code in [
            "LimitExceeded",
            "LimitExceeded.AAAACountLimit",
            "RequestLimitExceeded.IPLimitExceeded",
        ] {
            let raw = RawApiError::with_code(code, "quota hit");
            let err = p.map_error(raw, default_ctx());
            assert!(
                matches!(err, ProviderError::QuotaExceeded { .. }),
                "expected QuotaExceeded for code '{code}', got {err:?}"
            );
        }
    }

    // ---- 频率限流 ----

    #[test]
    fn rate_limit_codes_map_to_rate_limited() {
        let p = provider();
        for code in [
            "RequestLimitExceeded",
            "FailedOperation.FrequencyLimit",
            "InvalidParameter.OperationIsTooFrequent",
        ] {
            let raw = RawApiError::with_code(code, "slow down");
            let err = p.map_error(raw, default_ctx());
            assert!(
                matches!(
                    err,
                    ProviderError::RateLimited {
                        retry_after: None,
                        ..
                    }
                ),
                "expected RateLimited for code '{code}', got {err:?}"
            );
        }
    }

    // ---- 记录已存在 ----

    #[test]
    fn record_exist_maps_to_record_exists() {
        let p = provider();
        let raw = RawApiError::with_code("InvalidParameter.DomainRecordExist", "dup");
        let err = p.map_error(raw, ctx_with_record_name("www"));
        assert!(
            matches!(err, ProviderError::RecordExists { ref record_name, .. } if record_name == "www"),
            "expected RecordExists, got {err:?}"
        );
    }

    // ---- 域名不存在 ----

    #[test]
    fn domain_not_found_codes() {
        let p = provider();
        for code in [
            "ResourceNotFound.NoDataOfDomain",
            "InvalidParameterValue.DomainNotExists",
        ] {
            let raw = RawApiError::with_code(code, "no domain");
            let err = p.map_error(raw, ctx_with_domain("example.com"));
            assert!(
                matches!(err, ProviderError::DomainNotFound { ref domain, .. } if domain == "example.com"),
                "expected DomainNotFound for code '{code}', got {err:?}"
            );
        }
    }

    // ---- 域名被锁定 ----

    #[test]
    fn domain_locked_codes() {
        let p = provider();
        for code in [
            "FailedOperation.DomainIsLocked",
            "FailedOperation.DomainIsSpam",
        ] {
            let raw = RawApiError::with_code(code, "locked");
            let err = p.map_error(raw, ctx_with_domain("example.com"));
            assert!(
                matches!(err, ProviderError::DomainLocked { ref domain, .. } if domain == "example.com"),
                "expected DomainLocked for code '{code}', got {err:?}"
            );
        }
    }

    // ---- 权限被拒绝 ----

    #[test]
    fn permission_denied_codes() {
        let p = provider();
        for code in [
            "OperationDenied",
            "UnauthorizedOperation",
            "FailedOperation.NotDomainOwner",
        ] {
            let raw = RawApiError::with_code(code, "denied");
            let err = p.map_error(raw, default_ctx());
            assert!(
                matches!(err, ProviderError::PermissionDenied { .. }),
                "expected PermissionDenied for code '{code}', got {err:?}"
            );
        }
    }

    // ---- 参数无效 - 线路 ----

    #[test]
    fn invalid_param_line() {
        let p = provider();
        let raw = RawApiError::with_code("InvalidParameter.RecordLineInvalid", "bad line");
        let err = p.map_error(raw, default_ctx());
        assert!(
            matches!(err, ProviderError::InvalidParameter { ref param, .. } if param == "line"),
            "expected InvalidParameter(line), got {err:?}"
        );
    }

    // ---- 参数无效 - 记录类型 ----

    #[test]
    fn invalid_param_type() {
        let p = provider();
        let raw = RawApiError::with_code("InvalidParameter.RecordTypeInvalid", "bad type");
        let err = p.map_error(raw, default_ctx());
        assert!(
            matches!(err, ProviderError::InvalidParameter { ref param, .. } if param == "type"),
            "expected InvalidParameter(type), got {err:?}"
        );
    }

    // ---- 参数无效 - 记录值 ----

    #[test]
    fn invalid_param_value() {
        let p = provider();
        let raw = RawApiError::with_code("InvalidParameter.RecordValueInvalid", "bad value");
        let err = p.map_error(raw, default_ctx());
        assert!(
            matches!(err, ProviderError::InvalidParameter { ref param, .. } if param == "value"),
            "expected InvalidParameter(value), got {err:?}"
        );
    }

    // ---- 参数无效 - 子域名 ----

    #[test]
    fn invalid_param_subdomain() {
        let p = provider();
        let raw = RawApiError::with_code("InvalidParameter.SubdomainInvalid", "bad sub");
        let err = p.map_error(raw, default_ctx());
        assert!(
            matches!(err, ProviderError::InvalidParameter { ref param, .. } if param == "subdomain"),
            "expected InvalidParameter(subdomain), got {err:?}"
        );
    }

    // ---- 参数无效 - TTL ----

    #[test]
    fn invalid_param_ttl() {
        let p = provider();
        let raw = RawApiError::with_code("LimitExceeded.RecordTtlLimit", "ttl too high");
        let err = p.map_error(raw, default_ctx());
        assert!(
            matches!(err, ProviderError::InvalidParameter { ref param, .. } if param == "ttl"),
            "expected InvalidParameter(ttl), got {err:?}"
        );
    }

    // ---- 参数无效 - MX ----

    #[test]
    fn invalid_param_mx() {
        let p = provider();
        let raw = RawApiError::with_code("InvalidParameter.MxInvalid", "bad mx");
        let err = p.map_error(raw, default_ctx());
        assert!(
            matches!(err, ProviderError::InvalidParameter { ref param, .. } if param == "mx"),
            "expected InvalidParameter(mx), got {err:?}"
        );
    }

    // ---- 参数无效 - 域名 ----

    #[test]
    fn invalid_param_domain() {
        let p = provider();
        let raw = RawApiError::with_code("InvalidParameter.DomainIdInvalid", "bad domain id");
        let err = p.map_error(raw, default_ctx());
        assert!(
            matches!(err, ProviderError::InvalidParameter { ref param, .. } if param == "domain"),
            "expected InvalidParameter(domain), got {err:?}"
        );
    }

    // ---- 参数无效 - 记录ID ----

    #[test]
    fn invalid_param_record_id() {
        let p = provider();
        let raw = RawApiError::with_code("InvalidParameter.RecordIdInvalid", "bad record id");
        let err = p.map_error(raw, default_ctx());
        assert!(
            matches!(err, ProviderError::InvalidParameter { ref param, .. } if param == "record_id"),
            "expected InvalidParameter(record_id), got {err:?}"
        );
    }

    // ---- Fallback: 未知错误码 ----

    #[test]
    fn unknown_code_maps_to_unknown() {
        let p = provider();
        let raw = RawApiError::with_code("SomeNewError.NeverSeenBefore", "surprise");
        let err = p.map_error(raw, default_ctx());
        assert!(
            matches!(err, ProviderError::Unknown { ref raw_code, .. } if raw_code.as_deref() == Some("SomeNewError.NeverSeenBefore")),
            "expected Unknown with raw_code, got {err:?}"
        );
    }

    // ---- Fallback: 无错误码 ----

    #[test]
    fn no_code_maps_to_unknown() {
        let p = provider();
        let raw = RawApiError::new("something went wrong");
        let err = p.map_error(raw, default_ctx());
        assert!(
            matches!(err, ProviderError::Unknown { ref raw_code, .. } if raw_code.is_none()),
            "expected Unknown with no raw_code, got {err:?}"
        );
    }
}
