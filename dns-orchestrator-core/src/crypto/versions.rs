//! 加密算法版本管理
//!
//! 定义每个文件版本对应的加密参数（隐式契约）
//!
//! 设计原则：
//! - 文件版本号不暴露加密参数，参数在代码中隐式定义
//! - Version 1: PBKDF2-HMAC-SHA256, 100,000 次迭代
//! - Version 2: PBKDF2-HMAC-SHA256, 600,000 次迭代（OWASP 2023 推荐）
//! - 将来可扩展到 Version 3（Argon2 等算法）

/// Version 1: PBKDF2-HMAC-SHA256, 100,000 次迭代
const VERSION_1_ITERATIONS: u32 = 100_000;

/// Version 2: PBKDF2-HMAC-SHA256, 600,000 次迭代（OWASP 2023 推荐）
const VERSION_2_ITERATIONS: u32 = 600_000;

/// 当前文件格式版本号
///
/// 修改此常量即可切换版本（迭代次数会自动从版本号派生）
pub const CURRENT_FILE_VERSION: u32 = 2;

/// 获取当前版本的迭代次数（编译时计算）
///
/// 从 `CURRENT_FILE_VERSION` 自动派生，确保加密和解密使用相同参数
///
/// # Panics
/// Panics at compile time if `CURRENT_FILE_VERSION` does not map to a known iteration count.
/// This is intentional: the const fn is evaluated at compile time, so an invalid version
/// will cause a build failure rather than a runtime error.
#[allow(clippy::panic)]
pub const fn get_current_iterations() -> u32 {
    match get_pbkdf2_iterations(CURRENT_FILE_VERSION) {
        Some(iterations) => iterations,
        None => panic!("Invalid CURRENT_FILE_VERSION"),
    }
}

/// 获取指定文件版本的 PBKDF2 迭代次数
///
/// # Arguments
/// * `version` - 文件版本号
///
/// # Returns
/// - `Some(iterations)` - 该版本对应的迭代次数
/// - `None` - 不支持的版本号
pub const fn get_pbkdf2_iterations(version: u32) -> Option<u32> {
    match version {
        1 => Some(VERSION_1_ITERATIONS),
        2 => Some(VERSION_2_ITERATIONS),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_1_iterations() {
        assert_eq!(get_pbkdf2_iterations(1), Some(100_000));
    }

    #[test]
    fn version_2_iterations() {
        assert_eq!(get_pbkdf2_iterations(2), Some(600_000));
    }

    #[test]
    fn unknown_version_returns_none() {
        assert_eq!(get_pbkdf2_iterations(0), None);
        assert_eq!(get_pbkdf2_iterations(99), None);
    }

    #[test]
    fn current_version_is_2() {
        assert_eq!(CURRENT_FILE_VERSION, 2);
    }
}
