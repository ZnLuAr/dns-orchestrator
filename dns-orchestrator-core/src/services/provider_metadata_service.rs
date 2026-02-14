//! Provider metadata service
//!
//! Provide static metadata information for DNS Provider (stateless service)

use dns_orchestrator_provider::get_all_provider_metadata;

use crate::types::ProviderMetadata;

/// Provider metadata service (stateless)
pub struct ProviderMetadataService;

impl ProviderMetadataService {
    /// Create Provider metadata service instance
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Get a list of all supported providers
    pub fn list_providers(&self) -> Vec<ProviderMetadata> {
        get_all_provider_metadata()
    }
}

impl Default for ProviderMetadataService {
    fn default() -> Self {
        Self::new()
    }
}
