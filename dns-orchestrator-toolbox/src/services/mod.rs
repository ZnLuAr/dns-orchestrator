//! Stateless service façade exposing all toolbox operations.
//!
//! Every method on [`ToolboxService`] is an async associated function — no instance needed.

mod dns;
mod dns_propagation;
mod dnssec;
mod http_headers;
mod ip;
mod ssl;
mod whois;

use crate::error::ToolboxResult;
use crate::types::{
    DnsLookupResult, DnsPropagationResult, DnssecResult, HttpHeaderCheckResult, IpLookupResult,
    WhoisResult,
};

/// Embedded WHOIS server mapping (TLD → server).
const WHOIS_SERVERS: &str = include_str!("whois_servers.json");

/// Entry point for all network diagnostic operations.
///
/// All methods are stateless associated functions — call them directly on the type.
///
/// ```rust,no_run
/// use dns_orchestrator_toolbox::ToolboxService;
/// # async fn demo() -> dns_orchestrator_toolbox::ToolboxResult<()> {
/// let dns = ToolboxService::dns_lookup("example.com", "A", None).await?;
/// # Ok(())
/// # }
/// ```
pub struct ToolboxService;

impl ToolboxService {
    /// Query WHOIS information for a domain.
    ///
    /// Returns structured registration data (registrar, dates, name servers, status)
    /// parsed from the raw WHOIS response.
    pub async fn whois_lookup(domain: &str) -> ToolboxResult<WhoisResult> {
        whois::whois_lookup(domain, WHOIS_SERVERS).await
    }

    /// Resolve DNS records for a domain.
    ///
    /// `record_type` can be `"A"`, `"AAAA"`, `"MX"`, `"TXT"`, `"NS"`, `"CNAME"`,
    /// `"SOA"`, `"SRV"`, `"CAA"`, `"PTR"`, or `"ALL"`.
    ///
    /// Pass `None` for `nameserver` to use the system default resolver.
    pub async fn dns_lookup(
        domain: &str,
        record_type: &str,
        nameserver: Option<&str>,
    ) -> ToolboxResult<DnsLookupResult> {
        dns::dns_lookup(domain, record_type, nameserver).await
    }

    /// Look up geolocation data for an IP address or domain.
    ///
    /// When given a domain, resolves A/AAAA records first and geolocates each resulting IP.
    pub async fn ip_lookup(query: &str) -> ToolboxResult<IpLookupResult> {
        ip::ip_lookup(query).await
    }

    /// Inspect the SSL/TLS certificate served by a host.
    ///
    /// Defaults to port 443 when `port` is `None`.
    /// Returns connection status (`"https"`, `"http"`, or `"failed"`) and certificate details.
    pub async fn ssl_check(
        domain: &str,
        port: Option<u16>,
    ) -> ToolboxResult<crate::types::SslCheckResult> {
        ssl::ssl_check(domain, port).await
    }

    /// Send an HTTP request and analyse the response headers.
    ///
    /// Evaluates security headers (HSTS, CSP, X-Frame-Options, etc.) and returns
    /// per-header status with recommendations.
    pub async fn http_header_check(
        request: &crate::types::HttpHeaderCheckRequest,
    ) -> ToolboxResult<HttpHeaderCheckResult> {
        http_headers::http_header_check(request).await
    }

    /// Check DNS propagation across 13 global resolvers.
    ///
    /// Returns per-server results and an overall consistency percentage.
    pub async fn dns_propagation_check(
        domain: &str,
        record_type: &str,
    ) -> ToolboxResult<DnsPropagationResult> {
        dns_propagation::dns_propagation_check(domain, record_type).await
    }

    /// Validate DNSSEC deployment for a domain.
    ///
    /// Queries DNSKEY, DS, and RRSIG records. The `validation_status` field will be
    /// `"secure"`, `"insecure"`, or `"indeterminate"`.
    pub async fn dnssec_check(
        domain: &str,
        nameserver: Option<&str>,
    ) -> ToolboxResult<DnssecResult> {
        dnssec::dnssec_check(domain, nameserver).await
    }
}
