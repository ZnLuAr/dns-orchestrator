//! DNSSEC validation module.

use std::net::IpAddr;
use std::time::Instant;

use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    proto::{
        dnssec::{PublicKey, rdata::DNSSECRData},
        rr::{RecordType, record_data::RData},
    },
};

use crate::error::{ToolboxError, ToolboxResult};
use crate::types::{DnskeyRecord, DnssecResult, DnssecValidationStatus, DsRecord, RrsigRecord};

/// Get algorithm name from algorithm number (RFC 8624)
fn get_algorithm_name(algorithm: u8) -> String {
    match algorithm {
        1 => "RSA/MD5 (deprecated)".to_string(),
        3 => "DSA/SHA-1 (deprecated)".to_string(),
        5 => "RSA/SHA-1".to_string(),
        6 => "DSA-NSEC3-SHA1 (deprecated)".to_string(),
        7 => "RSASHA1-NSEC3-SHA1".to_string(),
        8 => "RSA/SHA-256".to_string(),
        10 => "RSA/SHA-512".to_string(),
        12 => "GOST R 34.10-2001".to_string(),
        13 => "ECDSAP256SHA256".to_string(),
        14 => "ECDSAP384SHA384".to_string(),
        15 => "Ed25519".to_string(),
        16 => "Ed448".to_string(),
        _ => format!("Unknown ({algorithm})"),
    }
}

/// Get digest type name from digest type number (RFC 4034)
fn get_digest_type_name(digest_type: u8) -> String {
    match digest_type {
        1 => "SHA-1".to_string(),
        2 => "SHA-256".to_string(),
        3 => "GOST R 34.11-94".to_string(),
        4 => "SHA-384".to_string(),
        _ => format!("Unknown ({digest_type})"),
    }
}

/// Extract signature fields from an RRSIG/SIG record.
#[allow(clippy::too_many_arguments)]
fn extract_signature_record(
    type_covered: RecordType,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    sig_expiration: u32,
    sig_inception: u32,
    key_tag: u16,
    signer_name: &str,
    signature_bytes: &[u8],
) -> RrsigRecord {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use chrono::{DateTime, Utc};

    // Format timestamps
    let expiration = DateTime::<Utc>::from_timestamp(i64::from(sig_expiration), 0).map_or_else(
        || format!("Invalid ({sig_expiration})"),
        |dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );

    let inception = DateTime::<Utc>::from_timestamp(i64::from(sig_inception), 0).map_or_else(
        || format!("Invalid ({sig_inception})"),
        |dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );

    // Base64-encode signature
    let signature_b64 = STANDARD.encode(signature_bytes);

    RrsigRecord {
        type_covered: format!("{type_covered:?}"),
        algorithm,
        algorithm_name: get_algorithm_name(algorithm),
        labels,
        original_ttl,
        signature_expiration: expiration,
        signature_inception: inception,
        key_tag,
        signer_name: signer_name.to_string(),
        signature: signature_b64,
    }
}

/// Validate DNSSEC deployment for a domain.
pub async fn dnssec_check(domain: &str, nameserver: Option<&str>) -> ToolboxResult<DnssecResult> {
    // Get system default DNS server addresses
    fn get_system_dns() -> String {
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
    }

    let start_time = Instant::now();

    // Use custom nameserver if provided, otherwise fall back to system default
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
        let mut opts = ResolverOpts::default();
        opts.validate = true; // Enable DNSSEC validation
        let resolver = TokioResolver::builder_with_config(config, provider)
            .with_options(opts)
            .build();
        (resolver, ns.to_string())
    } else {
        let system_dns = get_system_dns();
        let provider = TokioConnectionProvider::default();
        let mut opts = ResolverOpts::default();
        opts.validate = true; // Enable DNSSEC validation
        let resolver = TokioResolver::builder_with_config(ResolverConfig::default(), provider)
            .with_options(opts)
            .build();
        (resolver, system_dns)
    };

    let mut dnskey_records = Vec::new();
    let mut ds_records = Vec::new();
    let mut rrsig_records = Vec::new();
    let mut dnssec_enabled = false;

    // Query DNSKEY records
    if let Ok(response) = resolver.lookup(domain, RecordType::DNSKEY).await {
        dnssec_enabled = true;
        for record in response.record_iter() {
            // Try to parse DNSKEY from RData
            match record.data() {
                RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => {
                    use base64::{Engine, engine::general_purpose::STANDARD};

                    // Extract flags
                    let flags = dnskey.flags();

                    // Extract algorithm
                    let public_key = dnskey.public_key();
                    let algorithm = public_key.algorithm();
                    let algorithm_u8: u8 = algorithm.into();

                    // Extract public key bytes and encode as Base64
                    let public_key_bytes = public_key.public_bytes();
                    let public_key_b64 = STANDARD.encode(public_key_bytes);

                    // Calculate key tag
                    let key_tag = match dnskey.calculate_key_tag() {
                        Ok(tag) => tag,
                        Err(e) => {
                            log::warn!("Failed to calculate key_tag: {e}");
                            0
                        }
                    };

                    // Determine key type based on flags
                    let key_type = if dnskey.is_key_signing_key() {
                        "KSK".to_string()
                    } else if dnskey.zone_key() {
                        "ZSK".to_string()
                    } else {
                        format!("Unknown (flags={flags})")
                    };

                    dnskey_records.push(DnskeyRecord {
                        flags,
                        protocol: 3,
                        algorithm: algorithm_u8,
                        algorithm_name: get_algorithm_name(algorithm_u8),
                        public_key: public_key_b64,
                        key_tag,
                        key_type,
                    });
                }
                _ => {
                    log::warn!("Unexpected RData type in DNSKEY query: {:?}", record.data());
                }
            }
        }
    }

    // Query DS records
    if let Ok(response) = resolver.lookup(domain, RecordType::DS).await {
        dnssec_enabled = true;
        for record in response.record_iter() {
            match record.data() {
                RData::DNSSEC(DNSSECRData::DS(ds)) => {
                    // Extract fields
                    let key_tag = ds.key_tag();
                    let algorithm: u8 = ds.algorithm().into();
                    let digest_type_enum = ds.digest_type();
                    let digest_type_u8: u8 = digest_type_enum.into();
                    let digest_bytes = ds.digest();

                    // Hex encode digest
                    let digest_hex = hex::encode(digest_bytes);

                    ds_records.push(DsRecord {
                        key_tag,
                        algorithm,
                        algorithm_name: get_algorithm_name(algorithm),
                        digest_type: digest_type_u8,
                        digest_type_name: get_digest_type_name(digest_type_u8),
                        digest: digest_hex,
                    });
                }
                _ => {
                    log::warn!("Unexpected RData type in DS query: {:?}", record.data());
                }
            }
        }
    }

    // Query RRSIG records
    if let Ok(response) = resolver.soa_lookup(domain).await {
        for record in response.as_lookup().record_iter() {
            if record.record_type() == RecordType::RRSIG {
                dnssec_enabled = true;

                match record.data() {
                    RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                        let sig_record = extract_signature_record(
                            rrsig.type_covered(),
                            rrsig.algorithm().into(),
                            rrsig.num_labels(),
                            rrsig.original_ttl(),
                            rrsig.sig_expiration().get(),
                            rrsig.sig_inception().get(),
                            rrsig.key_tag(),
                            &rrsig.signer_name().to_string(),
                            rrsig.sig(),
                        );
                        rrsig_records.push(sig_record);
                    }
                    RData::DNSSEC(DNSSECRData::SIG(sig)) => {
                        let sig_record = extract_signature_record(
                            sig.type_covered(),
                            sig.algorithm().into(),
                            sig.num_labels(),
                            sig.original_ttl(),
                            sig.sig_expiration().get(),
                            sig.sig_inception().get(),
                            sig.key_tag(),
                            &sig.signer_name().to_string(),
                            sig.sig(),
                        );
                        rrsig_records.push(sig_record);
                    }
                    _ => {
                        log::warn!("Unexpected RData type in RRSIG query: {:?}", record.data());
                    }
                }
            }
        }
    }

    // Determine validation status
    // Note: with ResolverOpts.validate = true, hickory-resolver automatically validates DNSSEC.
    // If validation fails (bogus signature), the query returns a SERVFAIL error.
    // Therefore, successfully retrieving DNSSEC records means validation passed or DNSSEC is not enabled.
    let validation_status = if dnssec_enabled {
        if !dnskey_records.is_empty() && !ds_records.is_empty() {
            log::debug!(
                "DNSSEC validation for {}: Found DNSKEY ({}) and DS ({}) records, validation passed",
                domain,
                dnskey_records.len(),
                ds_records.len()
            );
            DnssecValidationStatus::Secure
        } else if !dnskey_records.is_empty() || !ds_records.is_empty() {
            log::debug!(
                "DNSSEC validation for {}: Partial DNSSEC records (DNSKEY: {}, DS: {})",
                domain,
                dnskey_records.len(),
                ds_records.len()
            );
            DnssecValidationStatus::Indeterminate
        } else {
            log::debug!("DNSSEC validation for {domain}: No DNSSEC records found");
            DnssecValidationStatus::Insecure
        }
    } else {
        log::debug!("DNSSEC validation for {domain}: DNSSEC not enabled");
        DnssecValidationStatus::Insecure
    };

    // u128 -> u64: elapsed millis for a DNSSEC check will never exceed u64::MAX
    #[allow(clippy::cast_possible_truncation)]
    let response_time_ms = start_time.elapsed().as_millis() as u64;

    Ok(DnssecResult {
        domain: domain.to_string(),
        dnssec_enabled,
        dnskey_records,
        ds_records,
        rrsig_records,
        validation_status,
        nameserver: used_nameserver,
        response_time_ms,
        error: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::unreadable_literal)]
mod tests {
    use super::*;

    // ==================== get_algorithm_name tests ====================

    #[test]
    fn test_get_algorithm_name_known() {
        assert_eq!(get_algorithm_name(1), "RSA/MD5 (deprecated)");
        assert_eq!(get_algorithm_name(5), "RSA/SHA-1");
        assert_eq!(get_algorithm_name(8), "RSA/SHA-256");
        assert_eq!(get_algorithm_name(10), "RSA/SHA-512");
        assert_eq!(get_algorithm_name(13), "ECDSAP256SHA256");
        assert_eq!(get_algorithm_name(14), "ECDSAP384SHA384");
        assert_eq!(get_algorithm_name(15), "Ed25519");
        assert_eq!(get_algorithm_name(16), "Ed448");
    }

    #[test]
    fn test_get_algorithm_name_deprecated() {
        assert!(get_algorithm_name(3).contains("deprecated"));
        assert!(get_algorithm_name(6).contains("deprecated"));
    }

    #[test]
    fn test_get_algorithm_name_unknown() {
        assert_eq!(get_algorithm_name(0), "Unknown (0)");
        assert_eq!(get_algorithm_name(99), "Unknown (99)");
        assert_eq!(get_algorithm_name(255), "Unknown (255)");
    }

    // ==================== get_digest_type_name tests ====================

    #[test]
    fn test_get_digest_type_name_known() {
        assert_eq!(get_digest_type_name(1), "SHA-1");
        assert_eq!(get_digest_type_name(2), "SHA-256");
        assert_eq!(get_digest_type_name(3), "GOST R 34.11-94");
        assert_eq!(get_digest_type_name(4), "SHA-384");
    }

    #[test]
    fn test_get_digest_type_name_unknown() {
        assert_eq!(get_digest_type_name(0), "Unknown (0)");
        assert_eq!(get_digest_type_name(5), "Unknown (5)");
        assert_eq!(get_digest_type_name(255), "Unknown (255)");
    }

    // ==================== extract_signature_record tests ====================

    #[test]
    fn test_extract_signature_record_basic() {
        let record = extract_signature_record(
            RecordType::A,
            13, // ECDSAP256SHA256
            3,
            3600,
            1700000000, // 2023-11-14
            1699000000, // 2023-11-03
            12345,
            "example.com.",
            &[1, 2, 3, 4],
        );
        assert_eq!(record.algorithm, 13);
        assert_eq!(record.algorithm_name, "ECDSAP256SHA256");
        assert_eq!(record.labels, 3);
        assert_eq!(record.original_ttl, 3600);
        assert_eq!(record.key_tag, 12345);
        assert_eq!(record.signer_name, "example.com.");
        assert!(!record.signature.is_empty());
        // Verify base64 encoding
        assert_eq!(record.signature, "AQIDBA==");
    }

    #[test]
    fn test_extract_signature_record_timestamps() {
        let record = extract_signature_record(
            RecordType::SOA,
            8,
            2,
            86400,
            0,          // epoch
            1700000000, // valid timestamp
            999,
            "test.com.",
            &[0],
        );
        // epoch 0 => 1970-01-01
        assert!(record.signature_expiration.contains("1970"));
        assert!(record.signature_inception.contains("2023"));
    }

    #[test]
    fn test_extract_signature_record_empty_signature() {
        let record = extract_signature_record(
            RecordType::A,
            8,
            2,
            300,
            1700000000,
            1699000000,
            1,
            "example.com.",
            &[],
        );
        // Empty bytes => empty base64
        assert_eq!(record.signature, "");
    }

    // ==================== dnssec_check integration tests ====================

    #[tokio::test]
    async fn test_dnssec_check_invalid_nameserver() {
        let result = dnssec_check("example.com", Some("not-an-ip")).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolboxError::ValidationError(_)
        ));
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dnssec_check_cloudflare_real() {
        // cloudflare.com has DNSSEC enabled
        let result = dnssec_check("cloudflare.com", Some("8.8.8.8")).await;
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.domain, "cloudflare.com");
        assert!(info.dnssec_enabled);
        assert!(!info.dnskey_records.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dnssec_check_no_dnssec_real() {
        // Many domains don't have DNSSEC, use system default
        let result = dnssec_check("example.com", None).await;
        let info = result.unwrap_or_else(|e| panic!("DNSSEC check failed (network issue?): {e}"));
        assert_eq!(info.domain, "example.com");
    }
}
