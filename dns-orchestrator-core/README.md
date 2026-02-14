# dns-orchestrator-core

Platform-agnostic core business logic for DNS Orchestrator, providing account management, domain management, DNS record operations, and encrypted import/export.

Designed to be shared between different frontends (Tauri Desktop/Android, Actix-Web) through trait-based storage abstractions.

## Architecture

```
┌─────────────────────────────────────────────┐
│            Platform Layer                    │
│  (Tauri / Actix-Web / your own backend)     │
│  Implements storage traits                  │
└──────────────────┬──────────────────────────┘
                   │ injects via ServiceContext
┌──────────────────▼──────────────────────────┐
│          dns-orchestrator-core               │
│  AccountService, DnsService, DomainService  │
│  ImportExportService, MigrationService ...  │
└──────────────────┬──────────────────────────┘
                   │ delegates DNS operations
┌──────────────────▼──────────────────────────┐
│        dns-orchestrator-provider             │
│  Cloudflare, Aliyun, DNSPod, Huaweicloud   │
└─────────────────────────────────────────────┘
```

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
dns-orchestrator-core = "0.1"
```

### Implement Storage Traits

The core library requires four trait implementations from the platform layer:

```rust
use dns_orchestrator_core::{AccountRepository, CredentialStore, ProviderRegistry};
use dns_orchestrator_core::traits::DomainMetadataRepository;

// Implement these for your storage backend:
// - AccountRepository    -- CRUD for account metadata
// - CredentialStore      -- Secure credential storage
// - ProviderRegistry     -- In-memory DNS provider instance cache
// - DomainMetadataRepository -- Domain favorites, tags, notes, colors
```

An `InMemoryProviderRegistry` implementation is provided out of the box:

```rust
use dns_orchestrator_core::traits::provider_registry::InMemoryProviderRegistry;

let registry = InMemoryProviderRegistry::new();
```

### Create a ServiceContext

```rust
use std::sync::Arc;
use dns_orchestrator_core::ServiceContext;

let ctx = ServiceContext::new(
    Arc::new(my_credential_store),
    Arc::new(my_account_repository),
    Arc::new(my_provider_registry),
    Arc::new(my_domain_metadata_repository),
);
let ctx = Arc::new(ctx);
```

### Use Services

```rust
use dns_orchestrator_core::services::*;

// Account management
let account_svc = AccountService::new(
    ctx.account_repository().clone(),
    ctx.credential_store().clone(),
    ctx.provider_registry().clone(),
);

// Restore accounts on startup (loads credentials, creates providers)
let restore = account_svc.restore_accounts().await?;
println!("Restored: {}, Errors: {}", restore.success_count, restore.error_count);

// DNS record operations
let dns_svc = DnsService::new(ctx.clone());
let records = dns_svc.list_records("account-id", "example.com", 1, 20, None, None).await?;

// Domain listing (with metadata: favorites, tags, colors)
let domain_svc = DomainService::new(ctx.clone());
let domains = domain_svc.list_domains("account-id", 1, 20).await?;

// Encrypted export/import
let ie_svc = ImportExportService::new(ctx.clone());
let export = ie_svc.export_accounts(
    ExportAccountsRequest {
        account_ids: vec!["account-id".to_string()],
        encrypt: true,
        password: Some("secret".to_string()),
    },
    "1.8.0",
).await?;
```

## Services

| Service | Description |
|---------|-------------|
| `AccountService` | Create, update, delete accounts; validate credentials; restore on startup |
| `DnsService` | List, create, update, delete DNS records (single and batch) |
| `DomainService` | List domains with attached metadata |
| `DomainMetadataService` | Favorites, tags, colors, notes for domains |
| `ImportExportService` | AES-256-GCM encrypted account export/import (`.dnso` files) |
| `MigrationService` | Credential format migration (v1.7.0 legacy to typed) |
| `ProviderMetadataService` | List supported DNS provider metadata |

## Encryption

Import/export uses AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation:

- 16-byte random salt, 12-byte random nonce
- Version-aware PBKDF2 iterations (v1: 100,000; v2: 600,000 per OWASP 2023)
- Backward-compatible decryption for older file versions

## License

MIT
