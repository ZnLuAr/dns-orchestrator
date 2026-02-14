# dns-orchestrator-app

Platform-agnostic app bootstrap crate for DNS Orchestrator.

[简体中文](./README.zh-CN.md) | English

## Features

- Build shared application state with `AppStateBuilder`
- Run unified startup flow: `run_startup()` / `run_migration()` / `run_account_restore()`
- Inject platform-specific startup behavior with `StartupHooks`

## Feature Flags

- `rustls` (default): forwards to `dns-orchestrator-core/rustls`
- `keyring-store`: enables `KeyringCredentialStore` (system keychain)
- `sqlite-store`: enables `SqliteStore` (SQLite + SeaORM)

## Quick Start (SQLite)

> Requires `sqlite-store` feature.

```rust
use std::sync::Arc;

use dns_orchestrator_app::adapters::SqliteStore;
use dns_orchestrator_app::{AppStateBuilder, NoopStartupHooks};

async fn bootstrap() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = std::path::Path::new("./data/dns-orchestrator.db");

    let store = Arc::new(SqliteStore::new(
        db_path,
        Some("replace-with-your-password".to_string()),
    ).await?);

    let app = AppStateBuilder::new()
        .credential_store(store.clone())
        .account_repository(store.clone())
        .domain_metadata_repository(store)
        .build()?;

    app.run_startup(&NoopStartupHooks).await?;
    Ok(())
}
```

## Development

```bash
# Build check with all optional features
cargo check -p dns-orchestrator-app --all-features

# Run tests for this crate (current tests require sqlite-store)
cargo test -p dns-orchestrator-app --features sqlite-store
```

## Structure

- `src/lib.rs`: `AppState`, `AppStateBuilder`, `StartupHooks`
- `src/adapters/`: built-in adapters (Keyring / SQLite)
- `tests/`: startup and SQLite store integration tests

## License

MIT
