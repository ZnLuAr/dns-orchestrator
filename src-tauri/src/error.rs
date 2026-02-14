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
        match &err {
            // 预期行为（用户输入、资源不存在等），用 warn
            CoreError::AccountNotFound(_)
            | CoreError::DomainNotFound(_)
            | CoreError::RecordNotFound(_)
            | CoreError::ProviderNotFound(_)
            | CoreError::ValidationError(_)
            | CoreError::NoAccountsSelected
            | CoreError::UnsupportedFileVersion
            | CoreError::CredentialValidation(_)
            | CoreError::InvalidCredentials(_) => {
                log::warn!("AppError: {err}");
            }
            // 真正的错误
            _ => {
                log::error!("AppError: {err}");
            }
        }
        Self(err)
    }
}

impl From<dns_orchestrator_toolbox::ToolboxError> for AppError {
    fn from(err: dns_orchestrator_toolbox::ToolboxError) -> Self {
        use dns_orchestrator_toolbox::ToolboxError;
        let core_err = match err {
            ToolboxError::ValidationError(msg) => {
                let e = CoreError::ValidationError(msg);
                log::warn!("ToolboxError: {e}");
                e
            }
            ToolboxError::NetworkError(msg) => {
                let e = CoreError::NetworkError(msg);
                log::error!("ToolboxError: {e}");
                e
            }
        };
        Self(core_err)
    }
}
