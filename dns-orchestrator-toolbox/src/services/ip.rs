//! IP geolocation lookup module.

use std::sync::LazyLock;

use hickory_resolver::{
    TokioResolver,
    config::{ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};
use serde::Deserialize;

use crate::error::{ToolboxError, ToolboxResult};
use crate::types::{IpGeoInfo, IpLookupResult};

/// Shared HTTP client for ipwho.is API calls.
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

/// Shared default DNS resolver for domain-to-IP resolution.
static DEFAULT_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    let provider = TokioConnectionProvider::default();
    TokioResolver::builder_with_config(ResolverConfig::default(), provider)
        .with_options(ResolverOpts::default())
        .build()
});

/// Response structure from ipwho.is API.
#[derive(Deserialize)]
struct IpWhoisResponse {
    ip: String,
    success: bool,
    message: Option<String>,
    #[serde(rename = "type")]
    ip_type: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    timezone: Option<IpWhoisTimezone>,
    connection: Option<IpWhoisConnection>,
}

#[derive(Deserialize)]
struct IpWhoisTimezone {
    id: Option<String>,
}

#[derive(Deserialize)]
struct IpWhoisConnection {
    asn: Option<i64>,
    org: Option<String>,
    isp: Option<String>,
}

/// Look up geolocation for a single IP address.
async fn lookup_single_ip(ip: &str, client: &reqwest::Client) -> ToolboxResult<IpGeoInfo> {
    let url = format!(
        "https://ipwho.is/{ip}?fields=ip,success,message,type,country,country_code,region,city,latitude,longitude,timezone,connection"
    );

    let response: IpWhoisResponse = client
        .get(&url)
        .send()
        .await
        .map_err(|e| ToolboxError::NetworkError(format!("Request failed: {e}")))?
        .json()
        .await
        .map_err(|e| ToolboxError::NetworkError(format!("Failed to parse response: {e}")))?;

    if !response.success {
        let error_msg = match response.message.as_deref() {
            Some("You've hit the monthly limit") => {
                "IP lookup service monthly quota exceeded, please try again later".to_string()
            }
            Some("Invalid IP address") => "Invalid IP address".to_string(),
            Some("Reserved range") => {
                "This IP belongs to a reserved range and cannot be looked up".to_string()
            }
            Some(msg) => format!("Lookup failed: {msg}"),
            None => "Lookup failed".to_string(),
        };
        return Err(ToolboxError::NetworkError(error_msg));
    }

    let ip_version = response.ip_type.unwrap_or_else(|| {
        if response.ip.parse::<std::net::Ipv6Addr>().is_ok() {
            "IPv6"
        } else {
            "IPv4"
        }
        .to_string()
    });

    let (isp, org, asn) = response.connection.map_or((None, None, None), |conn| {
        (
            conn.isp,
            conn.org.clone(),
            conn.asn.map(|n| format!("AS{n}")),
        )
    });

    let timezone = response.timezone.and_then(|tz| tz.id);

    Ok(IpGeoInfo {
        ip: response.ip,
        ip_version,
        country: response.country,
        country_code: response.country_code,
        region: response.region,
        city: response.city,
        latitude: response.latitude,
        longitude: response.longitude,
        timezone,
        isp,
        org: org.clone(),
        asn,
        as_name: org,
    })
}

/// Look up geolocation for an IP address or domain.
pub async fn ip_lookup(query: &str) -> ToolboxResult<IpLookupResult> {
    let query = query.trim().to_string();
    if query.is_empty() {
        return Err(ToolboxError::ValidationError(
            "IP address or domain required".to_string(),
        ));
    }

    let client = &*HTTP_CLIENT;

    // Check if the query is an IP address
    if query.parse::<std::net::IpAddr>().is_ok() {
        let result = lookup_single_ip(&query, client).await?;
        return Ok(IpLookupResult {
            query,
            is_domain: false,
            results: vec![result],
        });
    }

    // Treat as domain — resolve A and AAAA records
    let resolver = &*DEFAULT_RESOLVER;

    let mut ips: Vec<String> = Vec::new();

    // Resolve IPv4 (A records)
    if let Ok(response) = resolver.ipv4_lookup(&query).await {
        for ip in response.iter() {
            ips.push(ip.to_string());
        }
    }

    // Resolve IPv6 (AAAA records)
    if let Ok(response) = resolver.ipv6_lookup(&query).await {
        for ip in response.iter() {
            ips.push(ip.to_string());
        }
    }

    if ips.is_empty() {
        return Err(ToolboxError::NetworkError(format!(
            "Failed to resolve domain: {query}"
        )));
    }

    // Geolocate each resolved IP
    let mut results = Vec::new();
    for ip in ips {
        match lookup_single_ip(&ip, client).await {
            Ok(info) => results.push(info),
            Err(e) => {
                log::warn!("Failed to look up IP {ip}: {e}");
            }
        }
    }

    if results.is_empty() {
        return Err(ToolboxError::NetworkError(
            "All IP address lookups failed".to_string(),
        ));
    }

    Ok(IpLookupResult {
        query,
        is_domain: true,
        results,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_lookup_empty_query() {
        let result = ip_lookup("").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolboxError::ValidationError(_)
        ));
    }

    #[tokio::test]
    async fn test_ip_lookup_whitespace_only() {
        let result = ip_lookup("   ").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolboxError::ValidationError(_)
        ));
    }

    // NOTE: These tests depend on the ipwho.is external API; failures may be due to rate limiting or network issues

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_ip_lookup_ipv4_real() {
        let result = ip_lookup("8.8.8.8").await;
        let info =
            result.unwrap_or_else(|e| panic!("IPv4 lookup failed (ipwho.is unreachable?): {e}"));
        assert_eq!(info.query, "8.8.8.8");
        assert!(!info.is_domain);
        assert_eq!(info.results.len(), 1);
        assert_eq!(info.results[0].ip, "8.8.8.8");
        assert_eq!(info.results[0].ip_version, "IPv4");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_ip_lookup_domain_real() {
        let result = ip_lookup("google.com").await;
        let info =
            result.unwrap_or_else(|e| panic!("Domain lookup failed (DNS or ipwho.is issue?): {e}"));
        assert_eq!(info.query, "google.com");
        assert!(info.is_domain);
        assert!(!info.results.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_ip_lookup_ipv6_real() {
        let result = ip_lookup("2606:4700:4700::1111").await;
        let info =
            result.unwrap_or_else(|e| panic!("IPv6 lookup failed (ipwho.is unreachable?): {e}"));
        assert!(!info.is_domain);
        assert_eq!(info.results.len(), 1);
    }
}
