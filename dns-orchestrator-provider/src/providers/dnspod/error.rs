//! `DNSPod` wrong mapping

use crate::error::ProviderError;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

use super::DnspodProvider;

/// `DNSPod` Error code mapping
/// Reference: <https://cloud.tencent.com/document/api/1427/56192>
impl ProviderErrorMapper for DnspodProvider {
    fn provider_name(&self) -> &'static str {
        "dnspod"
    }

    fn map_error(&self, raw: RawApiError, context: ErrorContext) -> ProviderError {
        match raw.code.as_deref() {
            // ============ Authentication error ============
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

            // ============ Quota limit (resources run out, no retry) ============
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

            // ============ Frequency limit (temporary limit, can be retried) ============
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

            // ============ Record already exists ============
            Some("InvalidParameter.DomainRecordExist") => ProviderError::RecordExists {
                provider: self.provider_name().to_string(),
                record_name: context
                    .record_name
                    .unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ The domain name does not exist ============
            Some("ResourceNotFound.NoDataOfDomain" | "InvalidParameterValue.DomainNotExists") => {
                ProviderError::DomainNotFound {
                    provider: self.provider_name().to_string(),
                    domain: context.domain.unwrap_or_else(|| "<unknown>".to_string()),
                    raw_message: Some(raw.message),
                }
            }

            // ============ Domain name is locked/disabled ============
            Some(
                "FailedOperation.DomainIsLocked"
                | "FailedOperation.DomainIsSpam"
                | "FailedOperation.AccountIsLocked"
                | "InvalidParameter.UserAlreadyLocked"
                | "InvalidParameter.DomainIsNotlocked"
                | "InvalidParameter.DomainNotAllowedLock",
            ) => ProviderError::DomainLocked {
                provider: self.provider_name().to_string(),
                domain: context.domain.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ Permission/Operation Denied ============
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

            // ============ Invalid parameter - line ============
            Some("InvalidParameter.RecordLineInvalid" | "InvalidParameter.LineNotExist") => {
                ProviderError::InvalidParameter {
                    provider: self.provider_name().to_string(),
                    param: "line".to_string(),
                    detail: raw.message,
                }
            }

            // ============ Invalid parameter - record type ============
            Some("InvalidParameter.RecordTypeInvalid") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "type".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - record value ============
            Some(
                "InvalidParameter.RecordValueInvalid" | "InvalidParameter.RecordValueLengthInvalid",
            ) => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "value".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - subdomain ============
            Some("InvalidParameter.SubdomainInvalid") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "subdomain".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - TTL ============
            Some("LimitExceeded.RecordTtlLimit") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "ttl".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - MX priority ============
            Some("InvalidParameter.MxInvalid") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "mx".to_string(),
                detail: raw.message,
            },

            // ============ Invalid parameter - domain name ============
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

            // ============ Invalid parameter - record ID ============
            Some("InvalidParameter.RecordIdInvalid") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "record_id".to_string(),
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

    // ---- Authentication error ----

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

    // ---- Quota Limitation ----

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

    // ---- Frequency current limit ----

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

    // ---- Record already exists ----

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

    // ---- The domain name does not exist ----

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

    // ---- Domain name is locked ----

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

    // ---- Permission denied ----

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

    // ---- Invalid parameter - line ----

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

    // ---- Invalid parameter - record type ----

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

    // ---- Invalid parameter - record value ----

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

    // ---- Invalid parameter - subdomain name ----

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

    // ---- Invalid parameter - TTL ----

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

    // ---- Invalid parameter - MX ----

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

    // ---- Invalid parameter - domain name ----

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

    // ---- Invalid parameter - Record ID ----

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

    // ---- Fallback: Unknown error code ----

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

    // ---- Fallback: No error code ----

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
