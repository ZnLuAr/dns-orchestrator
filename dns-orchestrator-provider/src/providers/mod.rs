//! DNS Provider implementations

/// Shared utilities used by provider implementations.
pub mod common;

#[cfg(feature = "aliyun")]
mod aliyun;
#[cfg(feature = "cloudflare")]
mod cloudflare;
#[cfg(feature = "dnspod")]
mod dnspod;
#[cfg(feature = "huaweicloud")]
mod huaweicloud;

#[cfg(feature = "aliyun")]
pub use aliyun::AliyunProvider;
#[cfg(feature = "cloudflare")]
pub use cloudflare::CloudflareProvider;
#[cfg(feature = "dnspod")]
pub use dnspod::DnspodProvider;
#[cfg(feature = "huaweicloud")]
pub use huaweicloud::HuaweicloudProvider;
