# dns-orchestrator-app

DNS Orchestrator 的平台无关引导层 crate。

简体中文 | [English](./README.md)

## 功能特性

- 通过 `AppStateBuilder` 组装共享应用状态
- 提供统一启动流程：`run_startup()` / `run_migration()` / `run_account_restore()`
- 通过 `StartupHooks` 注入平台特定的启动逻辑

## Feature Flags

- `rustls`（默认）：透传到 `dns-orchestrator-core/rustls`
- `keyring-store`：启用 `KeyringCredentialStore`（系统钥匙串）
- `sqlite-store`：启用 `SqliteStore`（SQLite + SeaORM）

## 快速开始（SQLite）

> 需要启用 `sqlite-store`。

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

## 开发

```bash
# 编译检查（含全部可选 feature）
cargo check -p dns-orchestrator-app --all-features

# 运行该 crate 测试（当前测试依赖 sqlite-store）
cargo test -p dns-orchestrator-app --features sqlite-store
```

## 目录结构

- `src/lib.rs`：`AppState`、`AppStateBuilder`、`StartupHooks`
- `src/adapters/`：内置适配器（Keyring / SQLite）
- `tests/`：启动流程与 SQLite 存储集成测试

## 许可证

MIT
