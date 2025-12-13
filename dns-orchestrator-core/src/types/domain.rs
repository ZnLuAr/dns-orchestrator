//! 域名相关类型定义

use serde::{Deserialize, Serialize};

use dns_orchestrator_provider::{DomainStatus, ProviderDomain, ProviderType};

/// 应用层域名类型（包含 `account_id`）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDomain {
    /// 域名 ID
    pub id: String,
    /// 域名名称
    pub name: String,
    /// 所属账户 ID
    #[serde(rename = "accountId")]
    pub account_id: String,
    /// DNS 服务商类型
    pub provider: ProviderType,
    /// 域名状态
    pub status: DomainStatus,
    /// DNS 记录数量
    #[serde(rename = "recordCount", skip_serializing_if = "Option::is_none")]
    pub record_count: Option<u32>,
}

impl AppDomain {
    /// 从 Provider 层的 Domain 构造应用层 Domain
    #[must_use]
    pub fn from_provider(provider_domain: ProviderDomain, account_id: String) -> Self {
        Self {
            id: provider_domain.id,
            name: provider_domain.name,
            account_id,
            provider: provider_domain.provider,
            status: provider_domain.status,
            record_count: provider_domain.record_count,
        }
    }
}
