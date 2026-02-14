//! DNS Orchestrator Core Library
//!
//! Provides core business logic for DNS management applications, including:
//! -Account Service
//! -Domain Service
//! - DNS record management (DNS Service)
//!
//! This library is designed to be platform-independent, abstracting the storage layer through traits,
//! Supports Tauri (Desktop/Android) and Actix-Web backends.

pub mod crypto;
pub mod error;
pub mod services;
pub mod traits;
pub mod types;
pub mod utils;

#[cfg(test)]
mod test_utils;

// Re-export common types
pub use error::{CoreError, CoreResult};
pub use services::ServiceContext;
pub use traits::{AccountRepository, CredentialStore, DomainMetadataRepository, ProviderRegistry};
