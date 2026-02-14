//! DNS Orchestrator Core Library
//!
//! 提供 DNS 管理应用的核心业务逻辑，包括：
//! - 账户管理 (Account Service)
//! - 域名管理 (Domain Service)
//! - DNS 记录管理 (DNS Service)
//!
//! 此库设计为平台无关，通过 trait 抽象存储层，
//! 支持 Tauri (Desktop/Android) 和 Actix-Web 后端。

pub mod crypto;
pub mod error;
pub mod services;
pub mod traits;
pub mod types;
pub mod utils;

#[cfg(test)]
mod test_utils;

// Re-export 常用类型
pub use error::{CoreError, CoreResult};
pub use services::ServiceContext;
pub use traits::{AccountRepository, CredentialStore, DomainMetadataRepository, ProviderRegistry};
