# dns-orchestrator-provider

A unified DNS provider abstraction library for managing DNS records across multiple cloud platforms.

## Supported Providers

| Provider | Feature Flag | Auth Method | Credential Fields |
|----------|-------------|-------------|-------------------|
| [Cloudflare](https://www.cloudflare.com/) | `cloudflare` | Bearer Token | `api_token` |
| [Aliyun DNS](https://www.aliyun.com/product/dns) | `aliyun` | HMAC-SHA256 (V3) | `access_key_id`, `access_key_secret` |
| [DNSPod (Tencent Cloud)](https://www.dnspod.cn/) | `dnspod` | TC3-HMAC-SHA256 | `secret_id`, `secret_key` |
| [Huawei Cloud DNS](https://www.huaweicloud.com/product/dns.html) | `huaweicloud` | AK/SK Signing | `access_key_id`, `secret_access_key` |

## Features

- Unified `DnsProvider` trait for all providers
- Full CRUD operations on DNS records (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA)
- Batch create / update / delete with per-record error handling
- Paginated domain and record listing with search/filter
- Credential validation against remote APIs
- Automatic retry on transient errors (network, timeout, rate limit)
- Structured error types with provider-specific error code mapping
- Feature flags for selective provider compilation

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
dns-orchestrator-provider = { version = "0.1", features = ["all-providers"] }
```

Or enable only the providers you need:

```toml
[dependencies]
dns-orchestrator-provider = { version = "0.1", default-features = false, features = ["cloudflare", "rustls"] }
```

### TLS Backend

- `native-tls` (default) -- Uses the platform's native TLS implementation
- `rustls` -- Uses rustls, recommended for cross-compilation and Android

### Example

```rust
use dns_orchestrator_provider::{
    create_provider, DnsProvider, PaginationParams, ProviderCredentials,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let credentials = ProviderCredentials::Cloudflare {
        api_token: "your-api-token".to_string(),
    };

    let provider = create_provider(credentials)?;

    // Validate credentials
    provider.validate_credentials().await?;

    // List domains
    let domains = provider.list_domains(&PaginationParams::default()).await?;
    for domain in &domains.items {
        println!("{} ({:?})", domain.name, domain.status);
    }

    // List DNS records
    let records = provider.list_records(
        &domains.items[0].id,
        &Default::default(),
    ).await?;
    for record in &records.items {
        println!("{} {} -> {}", record.name, record.data.record_type(), record.data.display_value());
    }

    Ok(())
}
```

### Creating Records

```rust
use dns_orchestrator_provider::{CreateDnsRecordRequest, RecordData};

let request = CreateDnsRecordRequest {
    domain_id: "example.com".to_string(),
    name: "www".to_string(),
    ttl: 600,
    data: RecordData::A { address: "1.2.3.4".to_string() },
    proxied: None,
};

let record = provider.create_record(&request).await?;
```

### Batch Operations

```rust
use dns_orchestrator_provider::BatchUpdateItem;

let result = provider.batch_delete_records("example.com", &[
    "record-id-1".to_string(),
    "record-id-2".to_string(),
]).await?;

println!("Deleted: {}, Failed: {}", result.success_count, result.failed_count);
for failure in &result.failures {
    eprintln!("  {} -- {}", failure.record_id, failure.reason);
}
```

## Error Handling

All provider operations return `Result<T, ProviderError>`. The error enum provides structured variants:

| Variant | Description |
|---------|-------------|
| `InvalidCredentials` | Authentication failed |
| `RecordExists` | DNS record already exists |
| `RecordNotFound` | DNS record not found |
| `DomainNotFound` | Domain/zone not found |
| `InvalidParameter` | Invalid request parameter |
| `RateLimited` | API rate limit exceeded |
| `QuotaExceeded` | Account quota exceeded |
| `DomainLocked` | Domain is locked |
| `PermissionDenied` | Insufficient permissions |
| `NetworkError` | Network connectivity issue |
| `Timeout` | Request timed out |

Each variant includes the provider name and the original error message from the API.

## License

MIT
