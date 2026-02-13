use dns_orchestrator_core::error::CoreError;
use serde::Serialize;

/// 应用层错误 — 直接包装 `CoreError`
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct AppError(pub CoreError);

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<CoreError> for AppError {
    fn from(err: CoreError) -> Self {
        Self(err)
    }
}
