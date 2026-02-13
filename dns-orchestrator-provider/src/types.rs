use serde::{Deserialize, Serialize};

// ============ 分页相关类型 ============

/// 分页参数
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationParams {
    pub page: u32,
    pub page_size: u32,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 20,
        }
    }
}

/// DNS 记录查询参数（包含搜索和过滤）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordQueryParams {
    pub page: u32,
    pub page_size: u32,
    /// 搜索关键词（匹配记录名称或值）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyword: Option<String>,
    /// 记录类型过滤
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_type: Option<DnsRecordType>,
}

impl Default for RecordQueryParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 20,
            keyword: None,
            record_type: None,
        }
    }
}

impl RecordQueryParams {
    /// 转换为基础分页参数
    pub fn to_pagination(&self) -> PaginationParams {
        PaginationParams {
            page: self.page,
            page_size: self.page_size,
        }
    }
}

/// 分页响应
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub page_size: u32,
    pub total_count: u32,
    pub has_more: bool,
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, page: u32, page_size: u32, total_count: u32) -> Self {
        let has_more = (page * page_size) < total_count;
        Self {
            items,
            page,
            page_size,
            total_count,
            has_more,
        }
    }
}

// ============ Provider 相关类型 ============

/// Provider 类型枚举（原名 DnsProvider，重命名避免与 trait 冲突）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    #[cfg(feature = "cloudflare")]
    Cloudflare,
    #[cfg(feature = "aliyun")]
    Aliyun,
    #[cfg(feature = "dnspod")]
    Dnspod,
    #[cfg(feature = "huaweicloud")]
    Huaweicloud,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "cloudflare")]
            Self::Cloudflare => write!(f, "cloudflare"),
            #[cfg(feature = "aliyun")]
            Self::Aliyun => write!(f, "aliyun"),
            #[cfg(feature = "dnspod")]
            Self::Dnspod => write!(f, "dnspod"),
            #[cfg(feature = "huaweicloud")]
            Self::Huaweicloud => write!(f, "huaweicloud"),
        }
    }
}

// ============ 域名相关类型 ============

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainStatus {
    Active,
    Paused,
    Pending,
    Error,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDomain {
    pub id: String,
    pub name: String,
    pub provider: ProviderType,
    pub status: DomainStatus,
    #[serde(rename = "recordCount", skip_serializing_if = "Option::is_none")]
    pub record_count: Option<u32>,
}

// ============ DNS 记录相关类型 ============

/// DNS 记录类型（用于查询过滤）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Srv,
    Caa,
}

/// DNS 记录数据 - 类型安全的多态表示
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "content")]
pub enum RecordData {
    /// A 记录：IPv4 地址
    A { address: String },

    /// AAAA 记录：IPv6 地址
    AAAA { address: String },

    /// CNAME 记录：别名
    CNAME { target: String },

    /// MX 记录：邮件交换
    MX { priority: u16, exchange: String },

    /// TXT 记录：文本
    TXT { text: String },

    /// NS 记录：域名服务器
    NS { nameserver: String },

    /// SRV 记录：服务定位
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },

    /// CAA 记录：证书颁发机构授权
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },
}

impl RecordData {
    /// 获取记录类型
    pub fn record_type(&self) -> DnsRecordType {
        match self {
            Self::A { .. } => DnsRecordType::A,
            Self::AAAA { .. } => DnsRecordType::Aaaa,
            Self::CNAME { .. } => DnsRecordType::Cname,
            Self::MX { .. } => DnsRecordType::Mx,
            Self::TXT { .. } => DnsRecordType::Txt,
            Self::NS { .. } => DnsRecordType::Ns,
            Self::SRV { .. } => DnsRecordType::Srv,
            Self::CAA { .. } => DnsRecordType::Caa,
        }
    }

    /// 获取显示用的主要值（用于列表显示）
    pub fn display_value(&self) -> String {
        match self {
            Self::A { address } | Self::AAAA { address } => address.clone(),
            Self::CNAME { target } | Self::SRV { target, .. } => target.clone(),
            Self::MX { exchange, .. } => exchange.clone(),
            Self::TXT { text } => text.clone(),
            Self::NS { nameserver } => nameserver.clone(),
            Self::CAA { value, .. } => value.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecord {
    pub id: String,
    pub domain_id: String,
    pub name: String,
    pub ttl: u32,
    pub data: RecordData,

    /// Cloudflare 专用：是否启用代理
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,

    #[serde(with = "crate::utils::datetime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,

    #[serde(with = "crate::utils::datetime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDnsRecordRequest {
    pub domain_id: String,
    pub name: String,
    pub ttl: u32,
    pub data: RecordData,
    pub proxied: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDnsRecordRequest {
    pub domain_id: String,
    pub name: String,
    pub ttl: u32,
    pub data: RecordData,
    pub proxied: Option<bool>,
}

// ============ 批量操作类型 ============

/// 批量创建结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchCreateResult {
    pub success_count: usize,
    pub failed_count: usize,
    pub created_records: Vec<DnsRecord>,
    pub failures: Vec<BatchCreateFailure>,
}

/// 批量创建失败项
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchCreateFailure {
    pub request_index: usize,
    pub record_name: String,
    pub reason: String,
}

/// 批量更新结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateResult {
    pub success_count: usize,
    pub failed_count: usize,
    pub updated_records: Vec<DnsRecord>,
    pub failures: Vec<BatchUpdateFailure>,
}

/// 批量更新失败项
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateFailure {
    pub record_id: String,
    pub reason: String,
}

/// 批量更新请求项
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateItem {
    pub record_id: String,
    pub request: UpdateDnsRecordRequest,
}

/// 批量删除结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeleteResult {
    pub success_count: usize,
    pub failed_count: usize,
    pub failures: Vec<BatchDeleteFailure>,
}

/// 批量删除失败项
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeleteFailure {
    pub record_id: String,
    pub reason: String,
}

// ============ Provider 元数据类型 ============

/// 凭证字段类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Text,
    Password,
}

/// 提供商凭证字段定义
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCredentialField {
    pub key: String,
    pub label: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_text: Option<String>,
}

/// 提供商支持的功能
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProviderFeatures {
    /// 是否支持代理功能 (如 Cloudflare 的 CDN 代理)
    pub proxy: bool,
}

/// 提供商分页限制
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderLimits {
    /// 域名列表的最大分页大小
    pub max_page_size_domains: u32,
    /// DNS 记录列表的最大分页大小
    pub max_page_size_records: u32,
}

/// 提供商元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderMetadata {
    pub id: ProviderType,
    pub name: String,
    pub description: String,
    pub required_fields: Vec<ProviderCredentialField>,
    pub features: ProviderFeatures,
    pub limits: ProviderLimits,
}

// ============ 凭证类型 ============

/// 凭证验证错误
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CredentialValidationError {
    /// 缺失必需字段
    MissingField {
        provider: ProviderType,
        field: String,
        label: String,
    },
    /// 字段值为空
    EmptyField {
        provider: ProviderType,
        field: String,
        label: String,
    },
    /// 字段格式无效
    InvalidFormat {
        provider: ProviderType,
        field: String,
        label: String,
        reason: String,
    },
}

impl std::fmt::Display for CredentialValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField { label, .. } => write!(f, "缺少必填字段: {label}"),
            Self::EmptyField { label, .. } => write!(f, "字段不能为空: {label}"),
            Self::InvalidFormat { label, reason, .. } => write!(f, "{label}: {reason}"),
        }
    }
}

impl std::error::Error for CredentialValidationError {}

/// 凭证枚举 - 类型安全的凭证定义
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "provider", content = "credentials")]
pub enum ProviderCredentials {
    #[cfg(feature = "cloudflare")]
    #[serde(rename = "cloudflare")]
    Cloudflare { api_token: String },

    #[cfg(feature = "aliyun")]
    #[serde(rename = "aliyun")]
    Aliyun {
        access_key_id: String,
        access_key_secret: String,
    },

    #[cfg(feature = "dnspod")]
    #[serde(rename = "dnspod")]
    Dnspod {
        secret_id: String,
        secret_key: String,
    },

    #[cfg(feature = "huaweicloud")]
    #[serde(rename = "huaweicloud")]
    Huaweicloud {
        access_key_id: String,
        secret_access_key: String,
    },
}

impl ProviderCredentials {
    /// 从 `HashMap` 转换（兼容旧格式存储）
    pub fn from_map(
        provider: &ProviderType,
        map: &std::collections::HashMap<String, String>,
    ) -> Result<Self, CredentialValidationError> {
        match provider {
            #[cfg(feature = "cloudflare")]
            ProviderType::Cloudflare => Ok(Self::Cloudflare {
                api_token: Self::get_required_field(provider, map, "apiToken", "API Token")?,
            }),
            #[cfg(feature = "aliyun")]
            ProviderType::Aliyun => Ok(Self::Aliyun {
                access_key_id: Self::get_required_field(
                    provider,
                    map,
                    "accessKeyId",
                    "Access Key ID",
                )?,
                access_key_secret: Self::get_required_field(
                    provider,
                    map,
                    "accessKeySecret",
                    "Access Key Secret",
                )?,
            }),
            #[cfg(feature = "dnspod")]
            ProviderType::Dnspod => Ok(Self::Dnspod {
                secret_id: Self::get_required_field(provider, map, "secretId", "Secret ID")?,
                secret_key: Self::get_required_field(provider, map, "secretKey", "Secret Key")?,
            }),
            #[cfg(feature = "huaweicloud")]
            ProviderType::Huaweicloud => Ok(Self::Huaweicloud {
                access_key_id: Self::get_required_field(
                    provider,
                    map,
                    "accessKeyId",
                    "Access Key ID",
                )?,
                secret_access_key: Self::get_required_field(
                    provider,
                    map,
                    "secretAccessKey",
                    "Secret Access Key",
                )?,
            }),
            #[allow(unreachable_patterns)]
            _ => Err(CredentialValidationError::InvalidFormat {
                provider: provider.clone(),
                field: "provider".to_string(),
                label: "Provider".to_string(),
                reason: format!(
                    "Provider '{provider}' is not supported or its feature is not enabled."
                ),
            }),
        }
    }

    /// 从 `HashMap` 中获取必需字段，校验非空
    fn get_required_field(
        provider: &ProviderType,
        map: &std::collections::HashMap<String, String>,
        key: &str,
        label: &str,
    ) -> Result<String, CredentialValidationError> {
        match map.get(key) {
            None => Err(CredentialValidationError::MissingField {
                provider: provider.clone(),
                field: key.to_string(),
                label: label.to_string(),
            }),
            Some(v) if v.trim().is_empty() => Err(CredentialValidationError::EmptyField {
                provider: provider.clone(),
                field: key.to_string(),
                label: label.to_string(),
            }),
            Some(v) => Ok(v.clone()),
        }
    }

    /// 转换为 HashMap（保存时用，保持存储格式兼容）
    pub fn to_map(&self) -> std::collections::HashMap<String, String> {
        match self {
            Self::Cloudflare { api_token } => [("apiToken".to_string(), api_token.clone())].into(),
            Self::Aliyun {
                access_key_id,
                access_key_secret,
            } => [
                ("accessKeyId".to_string(), access_key_id.clone()),
                ("accessKeySecret".to_string(), access_key_secret.clone()),
            ]
            .into(),
            Self::Dnspod {
                secret_id,
                secret_key,
            } => [
                ("secretId".to_string(), secret_id.clone()),
                ("secretKey".to_string(), secret_key.clone()),
            ]
            .into(),
            Self::Huaweicloud {
                access_key_id,
                secret_access_key,
            } => [
                ("accessKeyId".to_string(), access_key_id.clone()),
                ("secretAccessKey".to_string(), secret_access_key.clone()),
            ]
            .into(),
        }
    }

    /// 获取凭证对应的 provider 类型
    pub fn provider_type(&self) -> ProviderType {
        match self {
            Self::Cloudflare { .. } => ProviderType::Cloudflare,
            Self::Aliyun { .. } => ProviderType::Aliyun,
            Self::Dnspod { .. } => ProviderType::Dnspod,
            Self::Huaweicloud { .. } => ProviderType::Huaweicloud,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ============ ProviderCredentials 往返测试 ============

    #[test]
    fn credentials_cloudflare_roundtrip() {
        let map: HashMap<String, String> =
            [("apiToken".to_string(), "my-token".to_string())].into();
        let cred = ProviderCredentials::from_map(&ProviderType::Cloudflare, &map).unwrap();
        let back = cred.to_map();
        assert_eq!(back.get("apiToken").unwrap(), "my-token");
        assert_eq!(cred.provider_type(), ProviderType::Cloudflare);
    }

    #[test]
    fn credentials_aliyun_roundtrip() {
        let map: HashMap<String, String> = [
            ("accessKeyId".to_string(), "id123".to_string()),
            ("accessKeySecret".to_string(), "secret456".to_string()),
        ]
        .into();
        let cred = ProviderCredentials::from_map(&ProviderType::Aliyun, &map).unwrap();
        let back = cred.to_map();
        assert_eq!(back.get("accessKeyId").unwrap(), "id123");
        assert_eq!(back.get("accessKeySecret").unwrap(), "secret456");
    }

    #[test]
    fn credentials_dnspod_roundtrip() {
        let map: HashMap<String, String> = [
            ("secretId".to_string(), "sid".to_string()),
            ("secretKey".to_string(), "skey".to_string()),
        ]
        .into();
        let cred = ProviderCredentials::from_map(&ProviderType::Dnspod, &map).unwrap();
        let back = cred.to_map();
        assert_eq!(back.get("secretId").unwrap(), "sid");
        assert_eq!(back.get("secretKey").unwrap(), "skey");
    }

    #[test]
    fn credentials_huaweicloud_roundtrip() {
        let map: HashMap<String, String> = [
            ("accessKeyId".to_string(), "ak".to_string()),
            ("secretAccessKey".to_string(), "sk".to_string()),
        ]
        .into();
        let cred = ProviderCredentials::from_map(&ProviderType::Huaweicloud, &map).unwrap();
        let back = cred.to_map();
        assert_eq!(back.get("accessKeyId").unwrap(), "ak");
        assert_eq!(back.get("secretAccessKey").unwrap(), "sk");
    }

    #[test]
    fn credentials_missing_field() {
        let map: HashMap<String, String> = HashMap::new();
        let err = ProviderCredentials::from_map(&ProviderType::Cloudflare, &map).unwrap_err();
        assert!(matches!(
            err,
            CredentialValidationError::MissingField { .. }
        ));
    }

    #[test]
    fn credentials_empty_field() {
        let map: HashMap<String, String> = [("apiToken".to_string(), "  ".to_string())].into();
        let err = ProviderCredentials::from_map(&ProviderType::Cloudflare, &map).unwrap_err();
        assert!(matches!(err, CredentialValidationError::EmptyField { .. }));
    }

    // ============ PaginatedResponse 分页计算测试 ============

    #[test]
    fn paginated_response_has_more() {
        let resp = PaginatedResponse::new(vec![1, 2, 3], 1, 3, 10);
        assert!(resp.has_more);
        assert_eq!(resp.total_count, 10);
    }

    #[test]
    fn paginated_response_no_more() {
        let resp = PaginatedResponse::new(vec![1, 2], 2, 3, 5);
        assert!(!resp.has_more); // page 2 * page_size 3 = 6 >= 5
    }

    #[test]
    fn paginated_response_exact_boundary() {
        let resp = PaginatedResponse::new(vec![1, 2, 3], 1, 3, 3);
        assert!(!resp.has_more); // 1 * 3 = 3, not < 3
    }

    #[test]
    fn paginated_response_empty() {
        let resp: PaginatedResponse<i32> = PaginatedResponse::new(vec![], 1, 20, 0);
        assert!(!resp.has_more);
        assert_eq!(resp.items.len(), 0);
    }

    // ============ DnsRecordType serde 测试 ============

    #[test]
    fn dns_record_type_serialize() {
        let a = DnsRecordType::A;
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"A\"");
    }

    #[test]
    fn dns_record_type_deserialize() {
        let a: DnsRecordType = serde_json::from_str("\"AAAA\"").unwrap();
        assert_eq!(a, DnsRecordType::Aaaa);
    }

    #[test]
    fn dns_record_type_roundtrip_all() {
        let types = vec![
            DnsRecordType::A,
            DnsRecordType::Aaaa,
            DnsRecordType::Cname,
            DnsRecordType::Mx,
            DnsRecordType::Txt,
            DnsRecordType::Ns,
            DnsRecordType::Srv,
            DnsRecordType::Caa,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let back: DnsRecordType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, t);
        }
    }

    // ============ RecordData serde 测试 ============

    #[test]
    fn record_data_srv_serde_roundtrip() {
        let data = RecordData::SRV {
            priority: 10,
            weight: 20,
            port: 443,
            target: "example.com".to_string(),
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: RecordData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn record_data_caa_serde_roundtrip() {
        let data = RecordData::CAA {
            flags: 0,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: RecordData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn record_data_record_type() {
        assert_eq!(
            RecordData::A {
                address: "1.2.3.4".into()
            }
            .record_type(),
            DnsRecordType::A
        );
        assert_eq!(
            RecordData::SRV {
                priority: 0,
                weight: 0,
                port: 0,
                target: ".".into()
            }
            .record_type(),
            DnsRecordType::Srv
        );
    }

    #[test]
    fn record_data_display_value() {
        assert_eq!(
            RecordData::A {
                address: "1.2.3.4".into()
            }
            .display_value(),
            "1.2.3.4"
        );
        assert_eq!(
            RecordData::MX {
                priority: 10,
                exchange: "mail.x.com".into()
            }
            .display_value(),
            "mail.x.com"
        );
        assert_eq!(
            RecordData::CAA {
                flags: 0,
                tag: "issue".into(),
                value: "le.org".into()
            }
            .display_value(),
            "le.org"
        );
    }
}
