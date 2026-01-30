//! 业务领域模型
//!
//! 直接使用 dns-orchestrator-core 的类型，以保持类型一致
//! TUI 本地仅保留用于 UI 渲染的辅助类型（如 ProviderType 的显示名称）

mod account;
mod dns_record;
mod domain;

// 从 core 库导出 Account 和 AccountStatus（统一使用 chrono::DateTime<Utc>）
pub use dns_orchestrator_core::types::{Account, AccountStatus};

// TUI 本地的 ProviderType 包装（提供 display_name, short_name 等 UI 辅助方法）
pub use account::ProviderType;

pub use dns_record::{DnsRecord, DnsRecordType, RecordData};
pub use domain::{Domain, DomainStatus};