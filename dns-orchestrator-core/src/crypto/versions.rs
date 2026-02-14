//! Encryption algorithm version management
//!
//! Define encryption parameters corresponding to each file version (implicit contract)
//!
//! Design principles:
//! - The file version number does not expose encryption parameters, and the parameters are implicitly defined in the code
//! - Version 1: PBKDF2-HMAC-SHA256, 100,000 iterations
//! - Version 2: PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2023 Recommended)
//! - Can be expanded to Version 3 in the future (algorithms such as Argon2)

/// Version 1: PBKDF2-HMAC-SHA256, 100,000 iterations
const VERSION_1_ITERATIONS: u32 = 100_000;

/// Version 2: PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2023 Recommended)
const VERSION_2_ITERATIONS: u32 = 600_000;

/// Current file format version number
///
/// Modify this constant to switch versions (the number of iterations is automatically derived from the version number)
pub const CURRENT_FILE_VERSION: u32 = 2;

/// Get the number of iterations of the current version (calculated at compile time)
///
/// Automatically derived from `CURRENT_FILE_VERSION`, ensuring the same parameters are used for encryption and decryption
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

/// Get the number of PBKDF2 iterations for the specified file version
///
/// # Arguments
/// * `version` - file version number
///
/// # Returns
/// - `Some(iterations)` - the number of iterations corresponding to this version
/// - `None` - Unsupported version number
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
