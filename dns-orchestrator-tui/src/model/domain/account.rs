//! 账号数据模型
//!
//! TUI 使用 dns-orchestrator-core 的 Account 和 AccountStatus
//! 本地仅定义 ProviderType 包装类，提供 UI 渲染所需的显示方法

use dns_orchestrator_provider::ProviderType as CoreProviderType;

/// DNS 服务商类型（TUI 包装）
///
/// 提供 display_name() 和 short_name() 方法用于 UI 渲染
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderType {
    Cloudflare,
    Aliyun,
    Dnspod,
    Huaweicloud,
}

impl ProviderType {
    /// 获取服务商显示名称（用于 UI 渲染）
    pub fn display_name(&self) -> &'static str {
        match self {
            ProviderType::Cloudflare => "Cloudflare",
            ProviderType::Aliyun => "Aliyun",
            ProviderType::Dnspod => "DNSPod",
            ProviderType::Huaweicloud => "Huawei Cloud",
        }
    }

    /// 获取服务商简称（用于紧凑显示）
    pub fn short_name(&self) -> &'static str {
        match self {
            ProviderType::Cloudflare => "CF",
            ProviderType::Aliyun => "Ali",
            ProviderType::Dnspod => "DP",
            ProviderType::Huaweicloud => "HW",
        }
    }

    /// 转换为 core 库的 ProviderType
    pub fn to_core(&self) -> CoreProviderType {
        match self {
            ProviderType::Cloudflare => CoreProviderType::Cloudflare,
            ProviderType::Aliyun => CoreProviderType::Aliyun,
            ProviderType::Dnspod => CoreProviderType::Dnspod,
            ProviderType::Huaweicloud => CoreProviderType::Huaweicloud,
        }
    }

    /// 从 core 库的 ProviderType 转换
    pub fn from_core(core_provider: &CoreProviderType) -> Self {
        match core_provider {
            CoreProviderType::Cloudflare => ProviderType::Cloudflare,
            CoreProviderType::Aliyun => ProviderType::Aliyun,
            CoreProviderType::Dnspod => ProviderType::Dnspod,
            CoreProviderType::Huaweicloud => ProviderType::Huaweicloud,
        }
    }
}