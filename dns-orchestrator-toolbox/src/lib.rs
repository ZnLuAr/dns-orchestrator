//! Network toolbox utilities for DNS Orchestrator
//!
//! 提供各种网络工具函数：WHOIS、DNS 查询、IP 查询、SSL 检查、HTTP 头检查、DNSSEC 验证。
//! 所有功能无状态，独立于 DNS 业务逻辑。

mod error;
mod services;
mod types;

pub use error::{ToolboxError, ToolboxResult};
pub use services::ToolboxService;
pub use types::{
    CertChainItem, DnsLookupRecord, DnsLookupResult, DnsPropagationResult, DnsPropagationServer,
    DnsPropagationServerResult, DnskeyRecord, DnssecResult, DsRecord, HttpHeader,
    HttpHeaderCheckRequest, HttpHeaderCheckResult, HttpMethod, IpGeoInfo, IpLookupResult,
    RrsigRecord, SecurityHeaderAnalysis, SslCertInfo, SslCheckResult, WhoisResult,
};
