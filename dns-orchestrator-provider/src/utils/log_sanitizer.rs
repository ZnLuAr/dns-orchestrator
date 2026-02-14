//! Log sanitization utilities
//!
//! Prevents sensitive data (DKIM keys, SPF records, API tokens, etc.)
//! from being fully exposed in debug/error logs.

/// Maximum number of characters to include in truncated log output.
const TRUNCATE_LIMIT: usize = 256;

/// MSRV-compatible replacement for `str::floor_char_boundary` (stable since 1.91.0).
fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        s.len()
    } else {
        let mut i = index;
        while i > 0 && !s.is_char_boundary(i) {
            i -= 1;
        }
        i
    }
}

/// Truncate a string for safe logging.
///
/// Returns the original string if it's within the limit,
/// otherwise returns the first `TRUNCATE_LIMIT` characters with a suffix
/// indicating the total length.
pub fn truncate_for_log(s: &str) -> String {
    if s.len() <= TRUNCATE_LIMIT {
        s.to_string()
    } else {
        format!(
            "{}... [truncated, total {} bytes]",
            &s[..floor_char_boundary(s, TRUNCATE_LIMIT)],
            s.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_string_unchanged() {
        let s = "hello world";
        assert_eq!(truncate_for_log(s), s);
    }

    #[test]
    fn exactly_at_limit() {
        let s = "a".repeat(TRUNCATE_LIMIT);
        assert_eq!(truncate_for_log(&s), s);
    }

    #[test]
    fn over_limit_truncated() {
        let s = "a".repeat(TRUNCATE_LIMIT + 100);
        let result = truncate_for_log(&s);
        assert!(result.contains("... [truncated, total"));
        assert!(result.contains(&format!("{} bytes]", TRUNCATE_LIMIT + 100)));
        assert!(result.len() < s.len());
    }

    #[test]
    fn multibyte_chars_safe() {
        // Ensure truncation doesn't split multi-byte characters
        let s = "你".repeat(200); // Each '你' is 3 bytes
        let result = truncate_for_log(&s);
        assert!(result.contains("... [truncated, total"));
    }
}
