//! Shared DNS resolver helpers used across service modules.

use std::net::IpAddr;
use std::sync::LazyLock;

use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};

/// Shared default DNS resolver (no DNSSEC validation).
///
/// On Unix/Windows this uses the host system configuration (e.g. `/etc/resolv.conf`).
/// If the system configuration cannot be loaded, it falls back to Hickory's default
/// upstream set (Google Public DNS).
pub(crate) static DEFAULT_RESOLVER: LazyLock<TokioResolver> =
    LazyLock::new(|| build_system_resolver(false));

/// Human-readable description of the DNS servers used by the default resolver.
pub(crate) static SYSTEM_DNS_LABEL: LazyLock<String> = LazyLock::new(|| {
    #[cfg(any(unix, target_os = "windows"))]
    {
        if let Ok((config, _opts)) = hickory_resolver::system_conf::read_system_conf() {
            let ips = dedup_ips(&config);
            if !ips.is_empty() {
                return ips.join(", ");
            }
        }
    }

    let fallback = ResolverConfig::default();
    let ips = dedup_ips(&fallback);
    if ips.is_empty() {
        "Default".to_string()
    } else {
        ips.join(", ")
    }
});

/// Deduplicate nameserver IP addresses from a resolver configuration.
pub(crate) fn dedup_ips(config: &ResolverConfig) -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();
    for ns in config.name_servers() {
        let ip = ns.socket_addr.ip().to_string();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    ips
}

/// Build a resolver that targets a specific nameserver IP, or falls back to the
/// system configuration when `ns_ip` is `None`.
///
/// Set `validate` to `true` to enable DNSSEC validation.
pub(crate) fn build_resolver_for_ns(ns_ip: Option<IpAddr>, validate: bool) -> TokioResolver {
    if let Some(ns_ip) = ns_ip {
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&[ns_ip], 53, true),
        );
        let provider = TokioConnectionProvider::default();
        let mut opts = ResolverOpts::default();
        opts.validate = validate;
        return TokioResolver::builder_with_config(config, provider)
            .with_options(opts)
            .build();
    }

    build_system_resolver(validate)
}

/// Build a resolver using the host system DNS configuration (with fallback).
fn build_system_resolver(validate: bool) -> TokioResolver {
    #[cfg(any(unix, target_os = "windows"))]
    {
        match TokioResolver::builder_tokio() {
            Ok(mut builder) => {
                builder.options_mut().validate = validate;
                return builder.build();
            }
            Err(e) => {
                log::warn!(
                    "Failed to load system DNS configuration, falling back to defaults: {e}"
                );
            }
        }
    }

    let provider = TokioConnectionProvider::default();
    let mut opts = ResolverOpts::default();
    opts.validate = validate;
    TokioResolver::builder_with_config(ResolverConfig::default(), provider)
        .with_options(opts)
        .build()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_ips_default_config() {
        let config = ResolverConfig::default();
        let ips = dedup_ips(&config);
        assert!(
            !ips.is_empty(),
            "Default config should have at least one nameserver IP"
        );
    }

    #[test]
    fn test_dedup_ips_empty_config() {
        let config = ResolverConfig::from_parts(None, vec![], NameServerConfigGroup::new());
        let ips = dedup_ips(&config);
        assert!(ips.is_empty(), "Empty config should produce no IPs");
    }

    #[test]
    fn test_dedup_ips_removes_duplicates() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // Create a config with the same IP twice (two ports = two entries, same IP)
        let ns_group = NameServerConfigGroup::from_ips_clear(&[ip, ip], 53, true);
        let config = ResolverConfig::from_parts(None, vec![], ns_group);
        let ips = dedup_ips(&config);
        assert_eq!(
            ips.iter().filter(|&x| x == "1.2.3.4").count(),
            1,
            "Duplicate IPs should be deduplicated"
        );
    }

    #[test]
    fn test_build_resolver_for_ns_with_ip() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        // Should not panic
        let _resolver = build_resolver_for_ns(Some(ip), false);
    }

    #[test]
    fn test_build_resolver_for_ns_without_ip() {
        // Should not panic -- falls back to system resolver
        let _resolver = build_resolver_for_ns(None, false);
    }

    #[test]
    fn test_build_resolver_for_ns_with_validation() {
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        // Should not panic
        let _resolver = build_resolver_for_ns(Some(ip), true);
    }

    #[test]
    fn test_system_dns_label_not_empty() {
        let label = &*SYSTEM_DNS_LABEL;
        assert!(!label.is_empty(), "SYSTEM_DNS_LABEL should not be empty");
    }

    #[test]
    fn test_default_resolver_accessible() {
        // Accessing the lazy static should not panic
        let _resolver = &*DEFAULT_RESOLVER;
    }
}
