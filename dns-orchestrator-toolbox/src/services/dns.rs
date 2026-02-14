//! DNS record lookup module.

use std::net::IpAddr;
use std::sync::LazyLock;

use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};

use crate::error::{ToolboxError, ToolboxResult};
use crate::types::{DnsLookupRecord, DnsLookupResult};

/// Shared default DNS resolver (system configuration).
static DEFAULT_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    let provider = TokioConnectionProvider::default();
    TokioResolver::builder_with_config(ResolverConfig::default(), provider)
        .with_options(ResolverOpts::default())
        .build()
});

/// Cached description of the system default DNS servers.
static SYSTEM_DNS_LABEL: LazyLock<String> = LazyLock::new(|| {
    let config = ResolverConfig::default();
    let servers: Vec<String> = config
        .name_servers()
        .iter()
        .map(|ns| ns.socket_addr.ip().to_string())
        .collect();
    if servers.is_empty() {
        "System Default".to_string()
    } else {
        servers.join(", ")
    }
});

/// Extract the TTL from the first record in a lookup response.
fn first_record_ttl(lookup: &hickory_resolver::lookup::Lookup) -> u32 {
    lookup
        .record_iter()
        .next()
        .map_or(0, hickory_resolver::proto::rr::Record::ttl)
}

/// Resolve DNS records for a domain.
pub async fn dns_lookup(
    domain: &str,
    record_type: &str,
    nameserver: Option<&str>,
) -> ToolboxResult<DnsLookupResult> {
    // Use custom nameserver if provided, otherwise fall back to cached default
    let effective_ns = nameserver.filter(|s| !s.is_empty());

    let (resolver, used_nameserver) = if let Some(ns) = effective_ns {
        let ns_ip: IpAddr = ns.parse().map_err(|_| {
            ToolboxError::ValidationError(format!("Invalid DNS server address: {ns}"))
        })?;

        let config = ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&[ns_ip], 53, true),
        );
        let provider = TokioConnectionProvider::default();
        let custom = TokioResolver::builder_with_config(config, provider)
            .with_options(ResolverOpts::default())
            .build();
        (custom, ns.to_string())
    } else {
        // Return a clone — TokioResolver is cheaply cloneable (Arc internals)
        (DEFAULT_RESOLVER.clone(), SYSTEM_DNS_LABEL.clone())
    };

    let mut records: Vec<DnsLookupRecord> = Vec::new();
    let record_type_upper = record_type.to_uppercase();

    match record_type_upper.as_str() {
        "A" => lookup_a(&resolver, domain, &mut records).await,
        "AAAA" => lookup_aaaa(&resolver, domain, &mut records).await,
        "MX" => lookup_mx(&resolver, domain, &mut records).await,
        "TXT" => lookup_txt(&resolver, domain, &mut records).await,
        "NS" => lookup_ns(&resolver, domain, &mut records).await,
        "CNAME" => lookup_cname(&resolver, domain, &mut records).await,
        "SOA" => lookup_soa(&resolver, domain, &mut records).await,
        "SRV" => lookup_srv(&resolver, domain, &mut records).await,
        "CAA" => lookup_caa(&resolver, domain, &mut records).await,
        "PTR" => lookup_ptr(&resolver, domain, &mut records).await,
        "ALL" => {
            // Call internal lookup functions directly to reuse the resolver
            lookup_a(&resolver, domain, &mut records).await;
            lookup_aaaa(&resolver, domain, &mut records).await;
            lookup_cname(&resolver, domain, &mut records).await;
            lookup_mx(&resolver, domain, &mut records).await;
            lookup_txt(&resolver, domain, &mut records).await;
            lookup_ns(&resolver, domain, &mut records).await;
            lookup_soa(&resolver, domain, &mut records).await;
            lookup_srv(&resolver, domain, &mut records).await;
            lookup_caa(&resolver, domain, &mut records).await;
            lookup_ptr(&resolver, domain, &mut records).await;
        }
        _ => {
            return Err(ToolboxError::ValidationError(format!(
                "Unsupported record type: {record_type}"
            )));
        }
    }

    Ok(DnsLookupResult {
        nameserver: used_nameserver,
        records,
    })
}

async fn lookup_a(resolver: &TokioResolver, domain: &str, records: &mut Vec<DnsLookupRecord>) {
    match resolver.ipv4_lookup(domain).await {
        Ok(response) => {
            for ip in response.iter() {
                records.push(DnsLookupRecord {
                    record_type: "A".to_string(),
                    name: domain.to_string(),
                    value: ip.to_string(),
                    ttl: first_record_ttl(response.as_lookup()),
                    priority: None,
                });
            }
        }
        Err(e) => {
            log::debug!("A lookup failed for {domain}: {e}");
        }
    }
}

async fn lookup_aaaa(resolver: &TokioResolver, domain: &str, records: &mut Vec<DnsLookupRecord>) {
    match resolver.ipv6_lookup(domain).await {
        Ok(response) => {
            for ip in response.iter() {
                records.push(DnsLookupRecord {
                    record_type: "AAAA".to_string(),
                    name: domain.to_string(),
                    value: ip.to_string(),
                    ttl: first_record_ttl(response.as_lookup()),
                    priority: None,
                });
            }
        }
        Err(e) => {
            log::debug!("AAAA lookup failed for {domain}: {e}");
        }
    }
}

async fn lookup_mx(resolver: &TokioResolver, domain: &str, records: &mut Vec<DnsLookupRecord>) {
    match resolver.mx_lookup(domain).await {
        Ok(response) => {
            for mx in response.iter() {
                records.push(DnsLookupRecord {
                    record_type: "MX".to_string(),
                    name: domain.to_string(),
                    value: mx.exchange().to_string().trim_end_matches('.').to_string(),
                    ttl: first_record_ttl(response.as_lookup()),
                    priority: Some(mx.preference()),
                });
            }
        }
        Err(e) => {
            log::debug!("MX lookup failed for {domain}: {e}");
        }
    }
}

async fn lookup_txt(resolver: &TokioResolver, domain: &str, records: &mut Vec<DnsLookupRecord>) {
    match resolver.txt_lookup(domain).await {
        Ok(response) => {
            for txt in response.iter() {
                let txt_data: String = txt
                    .iter()
                    .map(|data| String::from_utf8_lossy(data).to_string())
                    .collect::<String>();
                records.push(DnsLookupRecord {
                    record_type: "TXT".to_string(),
                    name: domain.to_string(),
                    value: txt_data,
                    ttl: first_record_ttl(response.as_lookup()),
                    priority: None,
                });
            }
        }
        Err(e) => {
            log::debug!("TXT lookup failed for {domain}: {e}");
        }
    }
}

async fn lookup_ns(resolver: &TokioResolver, domain: &str, records: &mut Vec<DnsLookupRecord>) {
    match resolver.ns_lookup(domain).await {
        Ok(response) => {
            for ns in response.iter() {
                records.push(DnsLookupRecord {
                    record_type: "NS".to_string(),
                    name: domain.to_string(),
                    value: ns.to_string().trim_end_matches('.').to_string(),
                    ttl: first_record_ttl(response.as_lookup()),
                    priority: None,
                });
            }
        }
        Err(e) => {
            log::debug!("NS lookup failed for {domain}: {e}");
        }
    }
}

async fn lookup_cname(resolver: &TokioResolver, domain: &str, records: &mut Vec<DnsLookupRecord>) {
    match resolver
        .lookup(domain, hickory_resolver::proto::rr::RecordType::CNAME)
        .await
    {
        Ok(response) => {
            for record in response.record_iter() {
                if let Some(cname) = record.data().as_cname() {
                    records.push(DnsLookupRecord {
                        record_type: "CNAME".to_string(),
                        name: domain.to_string(),
                        value: cname.0.to_string().trim_end_matches('.').to_string(),
                        ttl: record.ttl(),
                        priority: None,
                    });
                }
            }
        }
        Err(e) => {
            log::debug!("CNAME lookup failed for {domain}: {e}");
        }
    }
}

async fn lookup_soa(resolver: &TokioResolver, domain: &str, records: &mut Vec<DnsLookupRecord>) {
    match resolver.soa_lookup(domain).await {
        Ok(response) => {
            if let Some(soa) = response.iter().next() {
                let value = format!(
                    "{} {} {} {} {} {} {}",
                    soa.mname().to_string().trim_end_matches('.'),
                    soa.rname().to_string().trim_end_matches('.'),
                    soa.serial(),
                    soa.refresh(),
                    soa.retry(),
                    soa.expire(),
                    soa.minimum()
                );
                records.push(DnsLookupRecord {
                    record_type: "SOA".to_string(),
                    name: domain.to_string(),
                    value,
                    ttl: first_record_ttl(response.as_lookup()),
                    priority: None,
                });
            }
        }
        Err(e) => {
            log::debug!("SOA lookup failed for {domain}: {e}");
        }
    }
}

async fn lookup_srv(resolver: &TokioResolver, domain: &str, records: &mut Vec<DnsLookupRecord>) {
    match resolver.srv_lookup(domain).await {
        Ok(response) => {
            for srv in response.iter() {
                let value = format!(
                    "{} {} {}",
                    srv.weight(),
                    srv.port(),
                    srv.target().to_string().trim_end_matches('.')
                );
                records.push(DnsLookupRecord {
                    record_type: "SRV".to_string(),
                    name: domain.to_string(),
                    value,
                    ttl: first_record_ttl(response.as_lookup()),
                    priority: Some(srv.priority()),
                });
            }
        }
        Err(e) => {
            log::debug!("SRV lookup failed for {domain}: {e}");
        }
    }
}

async fn lookup_caa(resolver: &TokioResolver, domain: &str, records: &mut Vec<DnsLookupRecord>) {
    match resolver
        .lookup(domain, hickory_resolver::proto::rr::RecordType::CAA)
        .await
    {
        Ok(response) => {
            for record in response.record_iter() {
                if let Some(caa) = record.data().as_caa() {
                    let value = format!(
                        "{} {} \"{}\"",
                        if caa.issuer_critical() { 128 } else { 0 },
                        caa.tag().as_str(),
                        String::from_utf8_lossy(caa.raw_value())
                    );
                    records.push(DnsLookupRecord {
                        record_type: "CAA".to_string(),
                        name: domain.to_string(),
                        value,
                        ttl: record.ttl(),
                        priority: None,
                    });
                }
            }
        }
        Err(e) => {
            log::debug!("CAA lookup failed for {domain}: {e}");
        }
    }
}

async fn lookup_ptr(resolver: &TokioResolver, domain: &str, records: &mut Vec<DnsLookupRecord>) {
    match resolver
        .lookup(domain, hickory_resolver::proto::rr::RecordType::PTR)
        .await
    {
        Ok(response) => {
            for record in response.record_iter() {
                if let Some(ptr) = record.data().as_ptr() {
                    records.push(DnsLookupRecord {
                        record_type: "PTR".to_string(),
                        name: domain.to_string(),
                        value: ptr.0.to_string().trim_end_matches('.').to_string(),
                        ttl: record.ttl(),
                        priority: None,
                    });
                }
            }
        }
        Err(e) => {
            log::debug!("PTR lookup failed for {domain}: {e}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_lookup_invalid_record_type() {
        let result = dns_lookup("example.com", "INVALID", None).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ToolboxError::ValidationError(_)));
        assert!(err.to_string().contains("INVALID"));
    }

    #[tokio::test]
    async fn test_dns_lookup_invalid_nameserver() {
        let result = dns_lookup("example.com", "A", Some("not-an-ip")).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ToolboxError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_dns_lookup_empty_nameserver_uses_system_default() {
        // Empty nameserver should fall back to system default, not error
        let result = dns_lookup("example.com", "A", Some("")).await;
        assert!(result.is_ok());
        let lookup = result.unwrap();
        assert!(!lookup.nameserver.is_empty());
    }

    #[tokio::test]
    async fn test_dns_lookup_record_type_case_insensitive() {
        // Record type should be case-insensitive
        let result_lower = dns_lookup("example.com", "a", None).await;
        let result_upper = dns_lookup("example.com", "A", None).await;
        // Both should succeed (or both fail due to network), neither should return ValidationError
        assert!(
            result_lower.is_ok()
                || !matches!(result_lower.unwrap_err(), ToolboxError::ValidationError(_))
        );
        assert!(
            result_upper.is_ok()
                || !matches!(result_upper.unwrap_err(), ToolboxError::ValidationError(_))
        );
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dns_lookup_a_record_real() {
        let result = dns_lookup("google.com", "A", None).await;
        assert!(result.is_ok());
        let lookup = result.unwrap();
        assert!(!lookup.records.is_empty());
        assert!(lookup.records.iter().all(|r| r.record_type == "A"));
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dns_lookup_mx_record_real() {
        let result = dns_lookup("google.com", "MX", None).await;
        assert!(result.is_ok());
        let lookup = result.unwrap();
        assert!(!lookup.records.is_empty());
        for record in &lookup.records {
            assert_eq!(record.record_type, "MX");
            assert!(record.priority.is_some());
        }
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dns_lookup_ns_record_real() {
        let result = dns_lookup("google.com", "NS", None).await;
        assert!(result.is_ok());
        let lookup = result.unwrap();
        assert!(!lookup.records.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dns_lookup_txt_record_real() {
        let result = dns_lookup("google.com", "TXT", None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dns_lookup_soa_record_real() {
        let result = dns_lookup("google.com", "SOA", None).await;
        assert!(result.is_ok());
        let lookup = result.unwrap();
        assert!(!lookup.records.is_empty());
        assert_eq!(lookup.records[0].record_type, "SOA");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dns_lookup_with_custom_nameserver() {
        let result = dns_lookup("google.com", "A", Some("8.8.8.8")).await;
        assert!(result.is_ok());
        let lookup = result.unwrap();
        assert_eq!(lookup.nameserver, "8.8.8.8");
        assert!(!lookup.records.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dns_lookup_all_types_real() {
        let result = dns_lookup("google.com", "ALL", None).await;
        assert!(result.is_ok());
        let lookup = result.unwrap();
        // ALL should return multiple record types
        let types: Vec<_> = lookup
            .records
            .iter()
            .map(|r| r.record_type.as_str())
            .collect();
        assert!(types.contains(&"A") || types.contains(&"AAAA") || types.contains(&"NS"));
    }
}
