//! Platform-agnostic storage adapters for non-Tauri frontends (MCP, TUI, CLI).

#[cfg(feature = "keyring-store")]
mod keyring_credential_store;

#[cfg(feature = "keyring-store")]
pub use keyring_credential_store::KeyringCredentialStore;

#[cfg(feature = "sqlite-store")]
mod sqlite;

#[cfg(feature = "sqlite-store")]
pub use sqlite::SqliteStore;
