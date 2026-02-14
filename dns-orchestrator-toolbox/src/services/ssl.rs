//! SSL/TLS certificate inspection module.
//!
//! Uses rustls for fully async certificate checking with complete chain retrieval.

use std::sync::Arc;
use std::time::Duration;

use log::{debug, trace, warn};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::error::{ToolboxError, ToolboxResult};
use crate::types::{CertChainItem, ConnectionStatus, SslCertInfo, SslCheckResult};

// Timeout constants
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);

/// Initialize the rustls `CryptoProvider` (once).
///
/// If a provider is already installed (by another part of the application),
/// this is a no-op — `install_default` returns `Err` only to indicate that
/// a provider was already set, which is perfectly fine.
fn ensure_crypto_provider() {
    // Ignore the error: Err means a provider is already installed.
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

/// Check whether a plain HTTP connection is available (async).
async fn check_http_connection(domain: &str, port: u16) -> bool {
    // Wrap the entire HTTP probe in a timeout
    let result = timeout(HTTP_TIMEOUT, async {
        // Establish TCP connection
        let mut stream = timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect(format!("{domain}:{port}")),
        )
        .await
        .ok()?
        .ok()?;

        // Send HTTP HEAD request
        let request = format!("HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;

        // Read response
        let mut response = vec![0u8; 128];
        let _ = stream.read(&mut response).await.ok()?;

        let response_str = String::from_utf8_lossy(&response);
        Some(response_str.starts_with("HTTP/"))
    })
    .await;

    result.unwrap_or(None).unwrap_or(false)
}

/// Perform an SSL/TLS certificate check (fully async via rustls).
pub async fn ssl_check(domain: &str, port: Option<u16>) -> ToolboxResult<SslCheckResult> {
    // Ensure CryptoProvider is initialized
    ensure_crypto_provider();

    let port = port.unwrap_or(443);
    let domain = domain.to_string();

    debug!("[SSL] Starting check for {domain}:{port}");
    let start_time = std::time::Instant::now();

    // 1. Establish TCP connection (with timeout)
    trace!("[SSL] Establishing TCP connection...");
    let stream = match timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect(format!("{domain}:{port}")),
    )
    .await
    {
        Ok(Ok(s)) => {
            trace!(
                "[SSL] TCP connection succeeded, took {:?}",
                start_time.elapsed()
            );
            s
        }
        Ok(Err(e)) => {
            warn!("[SSL] TCP connection failed: {e}");
            return Ok(SslCheckResult {
                domain,
                port,
                connection_status: ConnectionStatus::Failed,
                cert_info: None,
                error: Some(format!("Connection failed: {e}")),
            });
        }
        Err(_) => {
            warn!(
                "[SSL] TCP connection timeout ({}s)",
                CONNECT_TIMEOUT.as_secs()
            );
            return Ok(SslCheckResult {
                domain,
                port,
                connection_status: ConnectionStatus::Failed,
                cert_info: None,
                error: Some("Connection timed out".to_string()),
            });
        }
    };

    // 2. Configure rustls client
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let Ok(server_name) = ServerName::try_from(domain.clone()) else {
        warn!("[SSL] Invalid domain name: {domain}");
        return Ok(SslCheckResult {
            domain,
            port,
            connection_status: ConnectionStatus::Failed,
            cert_info: None,
            error: Some("Invalid domain name".to_string()),
        });
    };

    // 3. TLS handshake (with timeout)
    trace!("[SSL] Performing TLS handshake...");
    let tls_start = std::time::Instant::now();
    let tls_result = timeout(TLS_TIMEOUT, connector.connect(server_name, stream)).await;

    let tls_stream = match tls_result {
        Ok(Ok(stream)) => {
            trace!(
                "[SSL] TLS handshake succeeded, took {:?}",
                tls_start.elapsed()
            );
            stream
        }
        Ok(Err(e)) => {
            warn!("[SSL] TLS handshake failed: {e}");
            // TLS handshake failed — check if plain HTTP is available
            trace!("[SSL] Checking if HTTP connection...");
            if check_http_connection(&domain, port).await {
                debug!(
                    "[SSL] Detected HTTP connection, total time {:?}",
                    start_time.elapsed()
                );
                return Ok(SslCheckResult {
                    domain,
                    port,
                    connection_status: ConnectionStatus::Http,
                    cert_info: None,
                    error: None,
                });
            }
            return Ok(SslCheckResult {
                domain,
                port,
                connection_status: ConnectionStatus::Failed,
                cert_info: None,
                error: Some(format!("TLS handshake failed: {e}")),
            });
        }
        Err(_) => {
            warn!("[SSL] TLS handshake timeout ({}s)", TLS_TIMEOUT.as_secs());
            // Timeout
            trace!("[SSL] Checking if HTTP connection...");
            if check_http_connection(&domain, port).await {
                debug!(
                    "[SSL] Detected HTTP connection, total time {:?}",
                    start_time.elapsed()
                );
                return Ok(SslCheckResult {
                    domain,
                    port,
                    connection_status: ConnectionStatus::Http,
                    cert_info: None,
                    error: None,
                });
            }
            return Ok(SslCheckResult {
                domain,
                port,
                connection_status: ConnectionStatus::Failed,
                cert_info: None,
                error: Some("TLS handshake timed out".to_string()),
            });
        }
    };

    // 4. Retrieve certificate chain
    trace!("[SSL] Retrieving certificate chain...");
    let (_, tls_conn) = tls_stream.get_ref();
    let certs = match tls_conn.peer_certificates() {
        Some(c) if !c.is_empty() => {
            trace!("[SSL] Retrieved {} certificate(s)", c.len());
            c
        }
        _ => {
            warn!("[SSL] No certificates found");
            return Ok(SslCheckResult {
                domain,
                port,
                connection_status: ConnectionStatus::Https,
                cert_info: None,
                error: Some("No certificate found".to_string()),
            });
        }
    };

    let cert_der = certs
        .first()
        .ok_or_else(|| ToolboxError::NetworkError("No certificate in chain".to_string()))?
        .as_ref();

    // 5. Parse leaf certificate
    trace!("[SSL] Parsing certificate...");
    let (_, cert) = match X509Certificate::from_der(cert_der) {
        Ok(c) => c,
        Err(e) => {
            warn!("[SSL] Certificate parsing failed: {e}");
            return Ok(SslCheckResult {
                domain,
                port,
                connection_status: ConnectionStatus::Https,
                cert_info: None,
                error: Some(format!("Certificate parsing failed: {e}")),
            });
        }
    };

    // 6. Extract certificate info
    let mut cert_info = parse_certificate(&domain, port, &cert);

    // 7. Parse full certificate chain
    cert_info.certificate_chain = certs
        .iter()
        .filter_map(|c: &CertificateDer| {
            X509Certificate::from_der(c.as_ref())
                .ok()
                .map(|(_, parsed)| CertChainItem {
                    subject: parsed.subject().to_string(),
                    issuer: parsed.issuer().to_string(),
                    is_ca: parsed.is_ca(),
                })
        })
        .collect();

    debug!(
        "[SSL] Check completed: {} - valid={}, expired={}, days_remaining={}, chain_length={}, total_time={:?}",
        domain,
        cert_info.is_valid,
        cert_info.is_expired,
        cert_info.days_remaining,
        cert_info.certificate_chain.len(),
        start_time.elapsed()
    );

    Ok(SslCheckResult {
        domain: domain.clone(),
        port,
        connection_status: ConnectionStatus::Https,
        cert_info: Some(cert_info),
        error: None,
    })
}

/// Parse certificate fields into [`SslCertInfo`].
fn parse_certificate(
    query: &str,
    _port: u16,
    cert: &x509_parser::certificate::X509Certificate,
) -> SslCertInfo {
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let valid_from = cert.validity().not_before.to_rfc2822().unwrap_or_default();
    let valid_to = cert.validity().not_after.to_rfc2822().unwrap_or_default();

    // Calculate days remaining
    let now = chrono::Utc::now();
    let not_after = chrono::DateTime::parse_from_rfc2822(&valid_to)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or(now);
    let days_remaining = (not_after - now).num_days();
    let is_expired = days_remaining < 0;

    // Extract Subject Alternative Names
    let san: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(dns) => Some((*dns).to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    // Extract CN from certificate
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(String::from);

    // Determine the effective domain from the certificate
    // Priority: CN > first SAN entry > queried value
    let cert_domain = cn
        .clone()
        .or_else(|| san.first().cloned())
        .unwrap_or_else(|| query.to_string());

    // Check whether the queried domain matches (CN or any SAN)
    let domain_matches = check_domain_match(query, cn.as_deref(), &san);

    // is_valid = not expired AND domain matches
    let is_valid = !is_expired && domain_matches;

    let serial_number = cert.serial.to_str_radix(16).to_uppercase();
    let signature_algorithm = cert.signature_algorithm.algorithm.to_string();

    // Certificate chain will be filled in by ssl_check(); initialize empty here
    let certificate_chain = vec![];

    SslCertInfo {
        domain: cert_domain,
        issuer,
        subject,
        valid_from,
        valid_to,
        days_remaining,
        is_expired,
        is_valid,
        san,
        serial_number,
        signature_algorithm,
        certificate_chain,
    }
}

/// Check whether the queried domain/IP matches the certificate's CN or SANs.
fn check_domain_match(query: &str, cn: Option<&str>, san: &[String]) -> bool {
    let query_lower = query.to_lowercase();

    // Check CN
    if let Some(cn) = cn
        && matches_domain(&query_lower, &cn.to_lowercase())
    {
        return true;
    }

    // Check SANs
    for name in san {
        if matches_domain(&query_lower, &name.to_lowercase()) {
            return true;
        }
    }

    false
}

/// Domain matching with wildcard support.
fn matches_domain(query: &str, pattern: &str) -> bool {
    // Exact match
    if query == pattern {
        return true;
    }

    // Wildcard match (*.example.com)
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcards match exactly one subdomain level
        // e.g. *.example.com matches foo.example.com but NOT foo.bar.example.com
        if let Some(prefix) = query.strip_suffix(suffix) {
            // prefix should be "xxx." where xxx contains no "."
            if prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.') {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ==================== matches_domain tests ====================

    #[test]
    fn test_matches_domain_exact() {
        assert!(matches_domain("example.com", "example.com"));
    }

    #[test]
    fn test_matches_domain_exact_no_match() {
        assert!(!matches_domain("example.com", "other.com"));
    }

    #[test]
    fn test_matches_domain_wildcard_basic() {
        assert!(matches_domain("sub.example.com", "*.example.com"));
    }

    #[test]
    fn test_matches_domain_wildcard_different_sub() {
        assert!(matches_domain("www.example.com", "*.example.com"));
        assert!(matches_domain("api.example.com", "*.example.com"));
        assert!(matches_domain("test.example.com", "*.example.com"));
    }

    #[test]
    fn test_matches_domain_wildcard_no_bare_domain() {
        // *.example.com should NOT match example.com
        assert!(!matches_domain("example.com", "*.example.com"));
    }

    #[test]
    fn test_matches_domain_wildcard_no_multi_level() {
        // *.example.com should NOT match a.b.example.com
        assert!(!matches_domain("a.b.example.com", "*.example.com"));
    }

    #[test]
    fn test_matches_domain_no_partial_match() {
        assert!(!matches_domain("notexample.com", "example.com"));
    }

    // ==================== check_domain_match tests ====================

    #[test]
    fn test_check_domain_match_cn_match() {
        assert!(check_domain_match("example.com", Some("example.com"), &[]));
    }

    #[test]
    fn test_check_domain_match_san_match() {
        assert!(check_domain_match(
            "www.example.com",
            Some("example.com"),
            &["www.example.com".to_string()],
        ));
    }

    #[test]
    fn test_check_domain_match_wildcard_in_san() {
        assert!(check_domain_match(
            "api.example.com",
            None,
            &["*.example.com".to_string()],
        ));
    }

    #[test]
    fn test_check_domain_match_case_insensitive() {
        assert!(check_domain_match("EXAMPLE.COM", Some("example.com"), &[]));
        assert!(check_domain_match("example.com", Some("EXAMPLE.COM"), &[]));
    }

    #[test]
    fn test_check_domain_match_no_cn_no_san() {
        assert!(!check_domain_match("example.com", None, &[]));
    }

    #[test]
    fn test_check_domain_match_no_match() {
        assert!(!check_domain_match(
            "evil.com",
            Some("example.com"),
            &["www.example.com".to_string()],
        ));
    }

    // ==================== integration tests ====================

    // NOTE: These tests depend on external networks; failures may be due to firewall/proxy issues

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_ssl_check_https_site_real() {
        let result = ssl_check("google.com", None).await;
        let check = result.unwrap_or_else(|e| panic!("SSL check failed: {e}"));
        // Network issues may cause connection failure; only verify cert if connected
        if check.connection_status == ConnectionStatus::Https {
            let cert = check
                .cert_info
                .expect("cert_info should be Some when connection_status is https");
            assert!(!cert.is_expired, "Google cert should not be expired");
            assert!(cert.days_remaining > 0);
            assert!(!cert.san.is_empty(), "SAN should not be empty");
            assert!(
                !cert.certificate_chain.is_empty(),
                "Certificate chain should not be empty"
            );
        } else {
            eprintln!(
                "WARN: SSL connection to google.com returned '{}', error: {:?} (network issue?)",
                check.connection_status, check.error
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_ssl_check_custom_port_real() {
        let result = ssl_check("google.com", Some(443)).await;
        let check = result.unwrap_or_else(|e| panic!("SSL check with custom port failed: {e}"));
        assert_eq!(check.port, 443);
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_ssl_check_invalid_domain_real() {
        let result = ssl_check("this-domain-does-not-exist-12345.com", None).await;
        let check = result.unwrap_or_else(|e| panic!("SSL check on invalid domain failed: {e}"));
        assert_eq!(
            check.connection_status,
            ConnectionStatus::Failed,
            "Invalid domain should fail, got: {}",
            check.connection_status
        );
        assert!(check.error.is_some());
    }
}
