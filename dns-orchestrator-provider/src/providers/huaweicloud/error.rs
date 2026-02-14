//! 华为云错误映射
//!
//! 参考: <https://support.huaweicloud.com/api-dns/ErrorCode.html>
//!
//! ## 错误码分类（共 29 个核心错误码）
//!
//! - **认证错误 (7)**：APIGW.0301, APIGW.0101, APIGW.0303, APIGW.0305, DNS.0005, DNS.0013, DNS.0040
//! - **权限拒绝 (4)**：APIGW.0302, APIGW.0306, DNS.0030, DNS.1802
//! - **配额超限 (8)**：DNS.0403, DNS.0404, DNS.0405, DNS.0408, DNS.0409, APIGW.0308, DNS.0021, DNS.2002
//! - **记录操作 (4)**：DNS.0312, DNS.0335, DNS.0016 (`RecordExists`), DNS.0313, DNS.0004 (`RecordNotFound`)
//! - **域名操作 (6)**：DNS.0302, DNS.0301, DNS.1206 (`DomainNotFound`), DNS.0213, DNS.0214, DNS.0209 (`DomainLocked`)
//! - **参数错误 (多种)**：DNS.0303(ttl), DNS.0307(type), DNS.0308(value), DNS.0304(name) 等
//! - **网络错误 (5)**：APIGW.0201, DNS.0012, DNS.0015, DNS.0022, DNS.0036
//!
//! ## 未映射的特殊功能（fallback 到 Unknown）
//!
//! - 健康检查 (DNS.11xx)：项目未使用
//! - VPC 关联 (DNS.07xx)：项目使用 Public Zone
//! - PTR 记录 (DNS.05xx)：反向解析，项目未使用
//! - DNSSEC (DNS.23xx)：高级功能
//! - 企业项目 (DNS.19xx)：企业功能

use crate::error::ProviderError;
use crate::traits::{ErrorContext, ProviderErrorMapper, RawApiError};

use super::HuaweicloudProvider;

/// 华为云错误码映射实现
impl ProviderErrorMapper for HuaweicloudProvider {
    fn provider_name(&self) -> &'static str {
        "huaweicloud"
    }

    fn map_error(&self, raw: RawApiError, context: ErrorContext) -> ProviderError {
        match raw.code.as_deref() {
            // ============ 认证错误 ============
            Some(
                "APIGW.0301" // IAM 认证信息错误
                | "APIGW.0101" // API 不存在/未发布（认证路径错误）
                | "APIGW.0303" // APP 认证信息错误
                | "APIGW.0305" // 通用认证错误
                | "DNS.0005"   // 权限认证失败
                | "DNS.0013"   // 无权限操作 API
                | "DNS.0040",  // 账号未实名认证
            ) => ProviderError::InvalidCredentials {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ 权限/操作被拒绝 ============
            Some(
                "APIGW.0302" // IAM 用户不允许访问（黑/白名单限制）
                | "APIGW.0306" // API 访问被拒绝
                | "DNS.0030"   // 不允许操作该资源
                | "DNS.1802",  // 策略不允许操作
            ) => ProviderError::PermissionDenied {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ 配额限制（资源用完，不可重试） ============
            Some(
                "DNS.0403"     // Record Set 配额不足
                | "DNS.0404"   // Zone 配额不足
                | "DNS.0405"   // PTR 配额不足
                | "DNS.0408"   // 自定义线路配额不足
                | "DNS.0409"   // 线路分组配额不足
                | "DNS.0021"   // 无法获取锁（并发冲突）
                | "DNS.2002",  // 租户配额不足
            ) => ProviderError::QuotaExceeded {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ 频率限流（可重试） ============
            Some("APIGW.0308") => ProviderError::RateLimited { // 流控阈值达到（429）
                provider: self.provider_name().to_string(),
                retry_after: None,
                raw_message: Some(raw.message),
            },

            // ============ 记录已存在 ============
            Some(
                "DNS.0312"     // 记录集名称已存在
                | "DNS.0335"   // 存在重复记录集
                | "DNS.0016",  // 记录已存在或冲突
            ) => ProviderError::RecordExists {
                provider: self.provider_name().to_string(),
                record_name: context.record_name.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ 记录不存在 ============
            Some("DNS.0313" | "DNS.0004") => ProviderError::RecordNotFound {
                provider: self.provider_name().to_string(),
                record_id: context.record_id.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ 域名不存在 ============
            Some(
                "DNS.0302"     // Zone 不存在
                | "DNS.0101"   // Zone 不存在（旧错误码保留兼容性）
                | "DNS.1206",  // 域名无效
            ) => ProviderError::DomainNotFound {
                provider: self.provider_name().to_string(),
                domain: context.domain.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ 域名被锁定/禁用 ============
            Some(
                "DNS.0213"     // 域名已被暂停
                | "DNS.0214"   // 域名处于非正常状态
                | "DNS.0209"   // 域名不在正常状态
                | "DNS.2003"   // 公安冻结
                | "DNS.2005"   // 公安冻结
                | "DNS.2006",  // 域名冻结
            ) => ProviderError::DomainLocked {
                provider: self.provider_name().to_string(),
                domain: context.domain.unwrap_or_else(|| "<unknown>".to_string()),
                raw_message: Some(raw.message),
            },

            // ============ 参数无效 - TTL ============
            Some("DNS.0303" | "DNS.0319") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "ttl".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 记录类型 ============
            Some("DNS.0307") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "type".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 记录值 ============
            Some("DNS.0308") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "value".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 记录名称 ============
            Some("DNS.0304" | "DNS.0202") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "name".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 子域名级别 ============
            Some("DNS.0321") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "subdomain".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 权重 ============
            Some("DNS.0323") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "weight".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 线路 ============
            Some(
                "DNS.0806"     // 线路不支持
                | "DNS.1601"   // 线路 ID 无效
                | "DNS.1602"   // 线路名称无效
                | "DNS.1604",  // 线路不存在
            ) => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "line".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 线路分组 ============
            Some(
                "DNS.1702"     // 线路分组包含无效线路
                | "DNS.1704"   // 线路分组名称已存在
                | "DNS.1706"   // 线路分组包含重复线路
                | "DNS.1707",  // 线路分组不存在
            ) => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "line_group".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - Record ID ============
            Some("DNS.0309") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "record_id".to_string(),
                detail: raw.message,
            },

            // ============ 参数无效 - 描述 ============
            Some("DNS.0206" | "DNS.0305") => ProviderError::InvalidParameter {
                provider: self.provider_name().to_string(),
                param: "description".to_string(),
                detail: raw.message,
            },

            // ============ 网络/后端服务错误 ============
            Some(
                "APIGW.0201"   // 请求格式错误/后端不可用/超时
                | "DNS.0012"   // VPC 服务异常
                | "DNS.0015"   // IAM 服务异常
                | "DNS.0022"   // Cloud Eye 服务异常
                | "DNS.0036",  // Neutron 服务异常
            ) => ProviderError::NetworkError {
                provider: self.provider_name().to_string(),
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

    // ============ 1. 认证错误 ============

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

    // ============ 2. 权限拒绝 ============

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

    // ============ 3. 配额超限 ============

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

    // ============ 4. 频率限流 ============

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

    // ============ 5. 记录已存在 ============

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

    // ============ 6. 记录不存在 ============

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

    // ============ 7. 域名不存在 ============

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

    // ============ 8. 域名被锁定 ============

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

    // ============ 9. 参数无效 - TTL ============

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

    // ============ 10. 参数无效 - type ============

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

    // ============ 11. 参数无效 - value ============

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

    // ============ 12. 参数无效 - name ============

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

    // ============ 13. 参数无效 - subdomain ============

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

    // ============ 14. 参数无效 - weight ============

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

    // ============ 15. 参数无效 - line ============

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

    // ============ 16. 参数无效 - line_group ============

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

    // ============ 17. 参数无效 - record_id ============

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

    // ============ 18. 参数无效 - description ============

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

    // ============ 19. 网络错误 ============

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

    // ============ 验证 provider_name ============

    #[test]
    fn provider_name_is_huaweicloud() {
        let p = provider();
        assert_eq!(p.provider_name(), "huaweicloud");
    }

    // ============ 验证上下文字段传递 ============

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
