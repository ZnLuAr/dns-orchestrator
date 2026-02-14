//! Domain name metadata type definition

use serde::{Deserialize, Serialize};

/// Default color value (no color)
fn default_color() -> String {
    "none".to_string()
}

/// Domain name metadata key (composite primary key)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainMetadataKey {
    pub account_id: String,
    pub domain_id: String,
}

impl DomainMetadataKey {
    /// Create new metadata key
    #[must_use]
    pub fn new(account_id: String, domain_id: String) -> Self {
        Self {
            account_id,
            domain_id,
        }
    }

    /// Generate a string key for storage (format: `account_id::domain_id`)
    #[must_use]
    pub fn to_storage_key(&self) -> String {
        format!("{}::{}", self.account_id, self.domain_id)
    }

    /// Parse from storage key
    #[must_use]
    pub fn from_storage_key(key: &str) -> Option<Self> {
        let parts: Vec<&str> = key.split("::").collect();
        if parts.len() != 2 {
            return None;
        }
        Some(Self {
            account_id: parts[0].to_string(),
            domain_id: parts[1].to_string(),
        })
    }
}

/// Domain name metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DomainMetadata {
    /// Whether to collect
    #[serde(default)]
    pub is_favorite: bool,

    /// Tag list (Phase 2 implementation)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Color tag ("none" means no color, Phase 3 implementation)
    #[serde(default = "default_color")]
    pub color: String,

    /// Remarks (optional, Phase 3 implementation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,

    /// Collection time (only valuable when collecting)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favorited_at: Option<chrono::DateTime<chrono::Utc>>,

    /// last modified time
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Default for DomainMetadata {
    fn default() -> Self {
        Self {
            is_favorite: false,
            tags: Vec::new(),
            color: "none".to_string(),
            note: None,
            favorited_at: None,
            updated_at: chrono::Utc::now(),
        }
    }
}

impl DomainMetadata {
    /// Create new metadata (all fields)
    #[must_use]
    pub fn new(
        is_favorite: bool,
        tags: Vec<String>,
        color: String,
        note: Option<String>,
        favorited_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        Self {
            is_favorite,
            tags,
            color,
            note,
            favorited_at,
            updated_at: chrono::Utc::now(),
        }
    }

    /// Refresh update time
    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now();
    }

    /// Whether the metadata is empty (all fields are default values)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.is_favorite
            && self.tags.is_empty()
            && self.color == "none"
            && self.note.is_none()
            && self.favorited_at.is_none()
    }
}

/// Domain name metadata update request (supports partial updates)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainMetadataUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_favorite: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// An empty string indicates clear color
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<Option<String>>,
}

impl DomainMetadataUpdate {
    /// Apply updates to existing metadata
    pub fn apply_to(&self, metadata: &mut DomainMetadata) {
        if let Some(is_favorite) = self.is_favorite {
            metadata.is_favorite = is_favorite;
        }
        if let Some(ref tags) = self.tags {
            metadata.tags.clone_from(tags);
        }
        if let Some(ref color) = self.color {
            metadata.color.clone_from(color);
        }
        if let Some(ref note) = self.note {
            metadata.note.clone_from(note);
        }
        metadata.touch();
    }
}

/// Bulk label operation request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchTagRequest {
    pub account_id: String,
    pub domain_id: String,
    pub tags: Vec<String>,
}

/// Batch label operation results
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchTagResult {
    pub success_count: usize,
    pub failed_count: usize,
    pub failures: Vec<BatchTagFailure>,
}

/// Batch label operation failure details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchTagFailure {
    pub account_id: String,
    pub domain_id: String,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_metadata_is_empty() {
        let m = DomainMetadata::default();
        assert!(m.is_empty());
    }

    #[test]
    fn metadata_with_favorite_not_empty() {
        let mut m = DomainMetadata::default();
        m.is_favorite = true;
        assert!(!m.is_empty());
    }

    #[test]
    fn metadata_with_tag_not_empty() {
        let mut m = DomainMetadata::default();
        m.tags = vec!["important".to_string()];
        assert!(!m.is_empty());
    }

    #[test]
    fn metadata_with_color_not_empty() {
        let mut m = DomainMetadata::default();
        m.color = "red".to_string();
        assert!(!m.is_empty());
    }

    #[test]
    fn metadata_with_color_none_is_empty() {
        let m = DomainMetadata::default();
        assert_eq!(m.color, "none");
        assert!(m.is_empty());
    }

    #[test]
    fn metadata_touch_updates_timestamp() {
        let mut m = DomainMetadata::default();
        let before = m.updated_at;
        // chrono::Utc::now() is precise enough to allow two calls to produce different timestamps
        std::thread::sleep(std::time::Duration::from_millis(2));
        m.touch();
        assert!(m.updated_at >= before);
    }

    #[test]
    fn metadata_key_storage_roundtrip() {
        let key = DomainMetadataKey::new("acc-123".to_string(), "domain.com".to_string());
        let storage = key.to_storage_key();
        assert_eq!(storage, "acc-123::domain.com");

        let parsed = DomainMetadataKey::from_storage_key(&storage).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn metadata_key_invalid_storage_key() {
        assert!(DomainMetadataKey::from_storage_key("no-separator").is_none());
        assert!(DomainMetadataKey::from_storage_key("a::b::c").is_none());
    }

    #[test]
    fn apply_to_partial_update() {
        let mut m = DomainMetadata::default();
        m.tags = vec!["old".to_string()];
        m.color = "red".to_string();

        let update = DomainMetadataUpdate {
            is_favorite: Some(true),
            tags: None,
            color: None,
            note: None,
        };
        update.apply_to(&mut m);

        assert!(m.is_favorite);
        // Unupdated fields remain unchanged
        assert_eq!(m.tags, vec!["old".to_string()]);
        assert_eq!(m.color, "red");
    }

    #[test]
    fn apply_to_full_update() {
        let mut m = DomainMetadata::default();

        let update = DomainMetadataUpdate {
            is_favorite: Some(true),
            tags: Some(vec!["a".to_string(), "b".to_string()]),
            color: Some("blue".to_string()),
            note: Some(Some("hello".to_string())),
        };
        update.apply_to(&mut m);

        assert!(m.is_favorite);
        assert_eq!(m.tags, vec!["a", "b"]);
        assert_eq!(m.color, "blue");
        assert_eq!(m.note, Some("hello".to_string()));
    }

    #[test]
    fn metadata_serde_roundtrip() {
        let m = DomainMetadata::new(
            true,
            vec!["tag1".to_string(), "tag2".to_string()],
            "green".to_string(),
            Some("a note".to_string()),
            Some(chrono::Utc::now()),
        );
        let json = serde_json::to_string(&m).unwrap();
        let deserialized: DomainMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(m, deserialized);
    }
}
