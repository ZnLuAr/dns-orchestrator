//! Error types for the toolbox crate.

use serde::Serialize;
use thiserror::Error;

/// Errors returned by toolbox operations.
#[derive(Error, Debug, Serialize)]
#[serde(tag = "code", content = "details")]
pub enum ToolboxError {
    /// Invalid input (e.g. malformed domain, unsupported record type).
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Network-level failure (e.g. DNS timeout, connection refused).
    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Convenience alias used throughout the crate.
pub type ToolboxResult<T> = std::result::Result<T, ToolboxError>;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_display() {
        let err = ToolboxError::ValidationError("test error".to_string());
        assert_eq!(err.to_string(), "Validation error: test error");
    }

    #[test]
    fn test_network_error_display() {
        let err = ToolboxError::NetworkError("connection refused".to_string());
        assert_eq!(err.to_string(), "Network error: connection refused");
    }

    #[test]
    fn test_error_serialization() {
        let err = ToolboxError::ValidationError("bad input".to_string());
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "ValidationError");
        assert_eq!(json["details"], "bad input");
    }

    #[test]
    fn test_network_error_serialization() {
        let err = ToolboxError::NetworkError("timeout".to_string());
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NetworkError");
        assert_eq!(json["details"], "timeout");
    }
}
