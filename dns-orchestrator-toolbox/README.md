# dns-orchestrator-toolbox

Async network diagnostic toolkit providing WHOIS, DNS lookup, IP geolocation, SSL certificate inspection, HTTP header analysis, DNS propagation checking, and DNSSEC validation.

All functions are stateless and independent -- no shared state, no business logic dependencies.

## Features

- **WHOIS Lookup** -- Query domain registration info with structured field parsing
- **DNS Lookup** -- Resolve any record type (A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, CAA, PTR) with custom nameserver support
- **DNS Propagation Check** -- Test record consistency across 13 global DNS servers (Google, Cloudflare, Quad9, Alibaba, Tencent, etc.)
- **DNSSEC Validation** -- Verify DNSSEC deployment (DNSKEY, DS, RRSIG records) and validation status
- **IP Geolocation** -- Look up country, region, city, ISP, ASN for IPs or domains
- **SSL Certificate Check** -- Inspect certificate chain, validity, SAN, expiration via rustls
- **HTTP Header Analysis** -- Send requests with any method/headers and get security header recommendations

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
dns-orchestrator-toolbox = "0.1"
```

### WHOIS Lookup

```rust
use dns_orchestrator_toolbox::ToolboxService;

let result = ToolboxService::whois_lookup("example.com").await?;
println!("Registrar: {:?}", result.registrar);
println!("Expires: {:?}", result.expiration_date);
println!("Name servers: {:?}", result.name_servers);
```

### DNS Lookup

```rust
// Query A records using system default nameserver
let result = ToolboxService::dns_lookup("example.com", "A", None).await?;
for record in &result.records {
    println!("{} {} TTL={}", record.record_type, record.value, record.ttl);
}

// Query all record types using a custom nameserver
let result = ToolboxService::dns_lookup("example.com", "ALL", Some("8.8.8.8")).await?;
```

### DNS Propagation Check

```rust
let result = ToolboxService::dns_propagation_check("example.com", "A").await?;
println!("Consistency: {:.1}%", result.consistency_percentage);
for server_result in &result.results {
    println!("  {} ({}): {}", server_result.server.name, server_result.server.region, server_result.status);
}
```

### DNSSEC Validation

```rust
let result = ToolboxService::dnssec_check("example.com", None).await?;
println!("DNSSEC enabled: {}", result.dnssec_enabled);
println!("Status: {}", result.validation_status); // "secure", "insecure", or "indeterminate"
for key in &result.dnskey_records {
    println!("  {} key: {} ({})", key.key_type, key.algorithm_name, key.key_tag);
}
```

### IP Geolocation

```rust
// Look up an IP address
let result = ToolboxService::ip_lookup("1.1.1.1").await?;

// Look up a domain (resolves A/AAAA first, then geolocates each IP)
let result = ToolboxService::ip_lookup("example.com").await?;
for info in &result.results {
    println!("{} -- {} {} ({})", info.ip, info.country.as_deref().unwrap_or("?"), info.city.as_deref().unwrap_or("?"), info.isp.as_deref().unwrap_or("?"));
}
```

### SSL Certificate Check

```rust
let result = ToolboxService::ssl_check("example.com", None).await?;
println!("Connection: {}", result.connection_status); // "https", "http", or "failed"
if let Some(cert) = &result.cert_info {
    println!("Issuer: {}", cert.issuer);
    println!("Valid: {} -> {}", cert.valid_from, cert.valid_to);
    println!("Days remaining: {}", cert.days_remaining);
    println!("SAN: {:?}", cert.san);
}
```

### HTTP Header Analysis

```rust
use dns_orchestrator_toolbox::{HttpHeaderCheckRequest, HttpMethod};

let request = HttpHeaderCheckRequest {
    url: "https://example.com".to_string(),
    method: HttpMethod::GET,
    custom_headers: vec![],
    body: None,
    content_type: None,
};

let result = ToolboxService::http_header_check(&request).await?;
println!("Status: {} {}", result.status_code, result.status_text);
println!("Response time: {}ms", result.response_time_ms);

// Security header analysis
for analysis in &result.security_analysis {
    println!("  {} [{}]: {:?}", analysis.name, analysis.status, analysis.recommendation);
}
```

## Checked Security Headers

The HTTP header analysis evaluates these security headers:

| Header | Status if Missing |
|--------|-------------------|
| `Strict-Transport-Security` | missing |
| `X-Frame-Options` | missing |
| `X-Content-Type-Options` | missing |
| `Content-Security-Policy` | missing |
| `Referrer-Policy` | warning |
| `Permissions-Policy` | warning |
| `X-XSS-Protection` | warning |

## DNS Propagation Servers

Propagation checks query 13 servers across 4 regions:

- **North America**: Google DNS, Cloudflare, Quad9, Level3
- **Europe**: Cloudflare (1.0.0.1), Quad9 (149.112.112.112), Google (8.8.4.4)
- **Asia**: Alibaba DNS, Tencent DNS, DNSPod
- **Other**: OpenDNS, AdGuard, Telstra

## License

MIT
