use serde::{Deserialize, Serialize};

/// Provider 统一错误类型
/// 用于将各 DNS Provider 的原始错误映射到统一的错误类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "code")]
pub enum ProviderError {
    /// 网络请求失败
    NetworkError { provider: String, detail: String },

    /// 凭证无效
    InvalidCredentials {
        provider: String,
        raw_message: Option<String>,
    },

    /// 记录已存在
    RecordExists {
        provider: String,
        record_name: String,
        raw_message: Option<String>,
    },

    /// 记录不存在
    RecordNotFound {
        provider: String,
        record_id: String,
        raw_message: Option<String>,
    },

    /// 参数无效（TTL、值等）
    InvalidParameter {
        provider: String,
        param: String,
        detail: String,
    },

    /// 不支持的记录类型
    UnsupportedRecordType {
        provider: String,
        record_type: String,
    },

    /// 配额超限
    QuotaExceeded {
        provider: String,
        raw_message: Option<String>,
    },

    /// API 限流（HTTP 429 或等效错误码）
    ///
    /// 与 `QuotaExceeded` 不同：限流是临时的，应 backoff 重试；
    /// 配额超限是资源用完了，重试无意义。
    RateLimited {
        provider: String,
        retry_after: Option<u64>,
        raw_message: Option<String>,
    },

    /// 请求超时
    Timeout { provider: String, detail: String },

    /// 域名不存在
    DomainNotFound {
        provider: String,
        domain: String,
        raw_message: Option<String>,
    },

    /// 域名被锁定/禁用
    DomainLocked {
        provider: String,
        domain: String,
        raw_message: Option<String>,
    },

    /// 权限/操作被拒绝
    PermissionDenied {
        provider: String,
        raw_message: Option<String>,
    },

    /// 响应解析失败
    ParseError { provider: String, detail: String },

    /// 序列化/反序列化失败
    SerializationError { provider: String, detail: String },

    /// 未知错误（fallback）
    Unknown {
        provider: String,
        raw_code: Option<String>,
        raw_message: String,
    },
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError { provider, detail } => {
                write!(f, "[{provider}] Network error: {detail}")
            }
            Self::InvalidCredentials {
                provider,
                raw_message,
            } => {
                if let Some(msg) = raw_message {
                    write!(f, "[{provider}] Invalid credentials: {msg}")
                } else {
                    write!(f, "[{provider}] Invalid credentials")
                }
            }
            Self::RecordExists {
                provider,
                record_name,
                ..
            } => {
                write!(f, "[{provider}] Record '{record_name}' already exists")
            }
            Self::RecordNotFound {
                provider,
                record_id,
                ..
            } => {
                write!(f, "[{provider}] Record '{record_id}' not found")
            }
            Self::InvalidParameter {
                provider,
                param,
                detail,
            } => {
                write!(f, "[{provider}] Invalid parameter '{param}': {detail}")
            }
            Self::UnsupportedRecordType {
                provider,
                record_type,
            } => {
                write!(f, "[{provider}] Unsupported record type: {record_type}")
            }
            Self::QuotaExceeded { provider, .. } => {
                write!(f, "[{provider}] Quota exceeded")
            }
            Self::RateLimited {
                provider,
                retry_after,
                ..
            } => {
                if let Some(secs) = retry_after {
                    write!(f, "[{provider}] Rate limited (retry after {secs}s)")
                } else {
                    write!(f, "[{provider}] Rate limited")
                }
            }
            Self::Timeout { provider, detail } => {
                write!(f, "[{provider}] Request timeout: {detail}")
            }
            Self::DomainNotFound {
                provider,
                domain,
                raw_message,
            } => {
                if let Some(msg) = raw_message {
                    write!(f, "[{provider}] Domain '{domain}' not found: {msg}")
                } else {
                    write!(f, "[{provider}] Domain '{domain}' not found")
                }
            }
            Self::DomainLocked {
                provider,
                domain,
                raw_message,
            } => {
                if let Some(msg) = raw_message {
                    write!(f, "[{provider}] Domain '{domain}' is locked: {msg}")
                } else {
                    write!(f, "[{provider}] Domain '{domain}' is locked")
                }
            }
            Self::PermissionDenied {
                provider,
                raw_message,
            } => {
                if let Some(msg) = raw_message {
                    write!(f, "[{provider}] Permission denied: {msg}")
                } else {
                    write!(f, "[{provider}] Permission denied")
                }
            }
            Self::ParseError { provider, detail } => {
                write!(f, "[{provider}] Parse error: {detail}")
            }
            Self::SerializationError { provider, detail } => {
                write!(f, "[{provider}] Serialization error: {detail}")
            }
            Self::Unknown {
                provider,
                raw_message,
                ..
            } => {
                write!(f, "[{provider}] {raw_message}")
            }
        }
    }
}

impl std::error::Error for ProviderError {}

/// 库的统一 Result 类型
pub type Result<T> = std::result::Result<T, ProviderError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_network_error() {
        let e = ProviderError::NetworkError {
            provider: "test".to_string(),
            detail: "connection refused".to_string(),
        };
        assert_eq!(e.to_string(), "[test] Network error: connection refused");
    }

    #[test]
    fn display_invalid_credentials_with_message() {
        let e = ProviderError::InvalidCredentials {
            provider: "aliyun".to_string(),
            raw_message: Some("bad key".to_string()),
        };
        assert_eq!(e.to_string(), "[aliyun] Invalid credentials: bad key");
    }

    #[test]
    fn display_invalid_credentials_without_message() {
        let e = ProviderError::InvalidCredentials {
            provider: "aliyun".to_string(),
            raw_message: None,
        };
        assert_eq!(e.to_string(), "[aliyun] Invalid credentials");
    }

    #[test]
    fn display_record_exists() {
        let e = ProviderError::RecordExists {
            provider: "dnspod".to_string(),
            record_name: "www".to_string(),
            raw_message: None,
        };
        assert_eq!(e.to_string(), "[dnspod] Record 'www' already exists");
    }

    #[test]
    fn display_record_not_found() {
        let e = ProviderError::RecordNotFound {
            provider: "cf".to_string(),
            record_id: "123".to_string(),
            raw_message: None,
        };
        assert_eq!(e.to_string(), "[cf] Record '123' not found");
    }

    #[test]
    fn display_invalid_parameter() {
        let e = ProviderError::InvalidParameter {
            provider: "test".to_string(),
            param: "ttl".to_string(),
            detail: "must be > 0".to_string(),
        };
        assert_eq!(e.to_string(), "[test] Invalid parameter 'ttl': must be > 0");
    }

    #[test]
    fn display_unsupported_record_type() {
        let e = ProviderError::UnsupportedRecordType {
            provider: "test".to_string(),
            record_type: "LOC".to_string(),
        };
        assert_eq!(e.to_string(), "[test] Unsupported record type: LOC");
    }

    #[test]
    fn display_quota_exceeded() {
        let e = ProviderError::QuotaExceeded {
            provider: "test".to_string(),
            raw_message: None,
        };
        assert_eq!(e.to_string(), "[test] Quota exceeded");
    }

    #[test]
    fn display_rate_limited_with_retry() {
        let e = ProviderError::RateLimited {
            provider: "cloudflare".to_string(),
            retry_after: Some(30),
            raw_message: None,
        };
        assert_eq!(e.to_string(), "[cloudflare] Rate limited (retry after 30s)");
    }

    #[test]
    fn display_rate_limited_without_retry() {
        let e = ProviderError::RateLimited {
            provider: "aliyun".to_string(),
            retry_after: None,
            raw_message: None,
        };
        assert_eq!(e.to_string(), "[aliyun] Rate limited");
    }

    #[test]
    fn display_timeout() {
        let e = ProviderError::Timeout {
            provider: "test".to_string(),
            detail: "30s elapsed".to_string(),
        };
        assert_eq!(e.to_string(), "[test] Request timeout: 30s elapsed");
    }

    #[test]
    fn display_domain_not_found_with_message() {
        let e = ProviderError::DomainNotFound {
            provider: "test".to_string(),
            domain: "example.com".to_string(),
            raw_message: Some("no such zone".to_string()),
        };
        assert_eq!(
            e.to_string(),
            "[test] Domain 'example.com' not found: no such zone"
        );
    }

    #[test]
    fn display_domain_not_found_without_message() {
        let e = ProviderError::DomainNotFound {
            provider: "test".to_string(),
            domain: "example.com".to_string(),
            raw_message: None,
        };
        assert_eq!(e.to_string(), "[test] Domain 'example.com' not found");
    }

    #[test]
    fn display_domain_locked() {
        let e = ProviderError::DomainLocked {
            provider: "test".to_string(),
            domain: "example.com".to_string(),
            raw_message: None,
        };
        assert_eq!(e.to_string(), "[test] Domain 'example.com' is locked");
    }

    #[test]
    fn display_permission_denied() {
        let e = ProviderError::PermissionDenied {
            provider: "test".to_string(),
            raw_message: Some("no access".to_string()),
        };
        assert_eq!(e.to_string(), "[test] Permission denied: no access");
    }

    #[test]
    fn display_parse_error() {
        let e = ProviderError::ParseError {
            provider: "test".to_string(),
            detail: "bad json".to_string(),
        };
        assert_eq!(e.to_string(), "[test] Parse error: bad json");
    }

    #[test]
    fn display_serialization_error() {
        let e = ProviderError::SerializationError {
            provider: "test".to_string(),
            detail: "failed".to_string(),
        };
        assert_eq!(e.to_string(), "[test] Serialization error: failed");
    }

    #[test]
    fn display_unknown() {
        let e = ProviderError::Unknown {
            provider: "test".to_string(),
            raw_code: Some("E001".to_string()),
            raw_message: "something broke".to_string(),
        };
        assert_eq!(e.to_string(), "[test] something broke");
    }

    #[test]
    fn serialize_json_round_trip() {
        let e = ProviderError::RateLimited {
            provider: "cloudflare".to_string(),
            retry_after: Some(60),
            raw_message: Some("too many requests".to_string()),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"code\":\"RateLimited\""));
        assert!(json.contains("\"retry_after\":60"));
    }

    #[test]
    fn deserialize_json_round_trip() {
        let original = ProviderError::NetworkError {
            provider: "aliyun".to_string(),
            detail: "connection refused".to_string(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: ProviderError = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.to_string(), original.to_string());
    }

    #[test]
    fn deserialize_all_variants() {
        let variants: Vec<ProviderError> = vec![
            ProviderError::NetworkError {
                provider: "t".into(),
                detail: "d".into(),
            },
            ProviderError::InvalidCredentials {
                provider: "t".into(),
                raw_message: None,
            },
            ProviderError::RecordExists {
                provider: "t".into(),
                record_name: "www".into(),
                raw_message: None,
            },
            ProviderError::RecordNotFound {
                provider: "t".into(),
                record_id: "1".into(),
                raw_message: None,
            },
            ProviderError::InvalidParameter {
                provider: "t".into(),
                param: "ttl".into(),
                detail: "bad".into(),
            },
            ProviderError::UnsupportedRecordType {
                provider: "t".into(),
                record_type: "LOC".into(),
            },
            ProviderError::QuotaExceeded {
                provider: "t".into(),
                raw_message: None,
            },
            ProviderError::RateLimited {
                provider: "t".into(),
                retry_after: Some(30),
                raw_message: None,
            },
            ProviderError::Timeout {
                provider: "t".into(),
                detail: "30s".into(),
            },
            ProviderError::DomainNotFound {
                provider: "t".into(),
                domain: "x.com".into(),
                raw_message: None,
            },
            ProviderError::DomainLocked {
                provider: "t".into(),
                domain: "x.com".into(),
                raw_message: None,
            },
            ProviderError::PermissionDenied {
                provider: "t".into(),
                raw_message: None,
            },
            ProviderError::ParseError {
                provider: "t".into(),
                detail: "bad".into(),
            },
            ProviderError::SerializationError {
                provider: "t".into(),
                detail: "fail".into(),
            },
            ProviderError::Unknown {
                provider: "t".into(),
                raw_code: Some("E1".into()),
                raw_message: "oops".into(),
            },
        ];

        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ProviderError = serde_json::from_str(&json).unwrap();
            assert_eq!(back.to_string(), v.to_string());
        }
    }

    #[test]
    fn is_retryable_variants() {
        // 引入 http_client 的 is_retryable 逻辑做等价测试
        let retryable = |e: &ProviderError| {
            matches!(
                e,
                ProviderError::NetworkError { .. }
                    | ProviderError::Timeout { .. }
                    | ProviderError::RateLimited { .. }
            )
        };

        assert!(retryable(&ProviderError::NetworkError {
            provider: "t".into(),
            detail: "x".into(),
        }));
        assert!(retryable(&ProviderError::Timeout {
            provider: "t".into(),
            detail: "x".into(),
        }));
        assert!(retryable(&ProviderError::RateLimited {
            provider: "t".into(),
            retry_after: None,
            raw_message: None,
        }));
        assert!(!retryable(&ProviderError::QuotaExceeded {
            provider: "t".into(),
            raw_message: None,
        }));
        assert!(!retryable(&ProviderError::InvalidCredentials {
            provider: "t".into(),
            raw_message: None,
        }));
        assert!(!retryable(&ProviderError::RecordNotFound {
            provider: "t".into(),
            record_id: "x".into(),
            raw_message: None,
        }));
    }
}
