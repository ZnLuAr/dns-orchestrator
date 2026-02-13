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

            // ============ 配额/频率限制 ============
            Some(
                "DNS.0403"     // Record Set 配额不足
                | "DNS.0404"   // Zone 配额不足
                | "DNS.0405"   // PTR 配额不足
                | "DNS.0408"   // 自定义线路配额不足
                | "DNS.0409"   // 线路分组配额不足
                | "APIGW.0308" // 流控阈值达到（429）
                | "DNS.0021"   // 无法获取锁（并发冲突）
                | "DNS.2002",  // 租户配额不足
            ) => ProviderError::QuotaExceeded {
                provider: self.provider_name().to_string(),
                raw_message: Some(raw.message),
            },

            // ============ 记录已存在 ============
            Some(
                "DNS.0312"     // 记录集名称已存在
                | "DNS.0335"   // 存在重复记录集
                | "DNS.0016",  // 记录已存在或冲突
            ) => ProviderError::RecordExists {
                provider: self.provider_name().to_string(),
                record_name: context.record_name.unwrap_or_default(),
                raw_message: Some(raw.message),
            },

            // ============ 记录不存在 ============
            Some("DNS.0313" | "DNS.0004") => ProviderError::RecordNotFound {
                provider: self.provider_name().to_string(),
                record_id: context.record_id.unwrap_or_default(),
                raw_message: Some(raw.message),
            },

            // ============ 域名不存在 ============
            Some(
                "DNS.0302"     // Zone 不存在
                | "DNS.0101"   // Zone 不存在（旧错误码保留兼容性）
                | "DNS.1206",  // 域名无效
            ) => ProviderError::DomainNotFound {
                provider: self.provider_name().to_string(),
                domain: context.domain.unwrap_or_default(),
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
                domain: context.domain.unwrap_or_default(),
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
