//! 统一错误类型定义

use serde::Serialize;
use thiserror::Error;

/// 工具箱错误类型
#[derive(Error, Debug, Serialize)]
#[serde(tag = "code", content = "details")]
pub enum ToolboxError {
    /// 验证错误
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// 网络错误
    #[error("Network error: {0}")]
    NetworkError(String),
}

/// 工具箱 Result 类型别名
pub type ToolboxResult<T> = std::result::Result<T, ToolboxError>;
