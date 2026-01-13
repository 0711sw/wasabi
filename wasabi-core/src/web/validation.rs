//! Input validation helpers for request data.
//!
//! These functions return 400 Bad Request errors on validation failure,
//! making them suitable for use in request handlers.

use crate::status_bail;
use regex::Regex;
use std::sync::LazyLock;
use warp::http::StatusCode;

/// Checks if a string's byte length is within bounds.
pub fn is_valid_str(data: &str, min_length: usize, max_length: usize) -> bool {
    let len = data.len();
    len >= min_length && len <= max_length
}

/// Validates string length, returning 400 on failure.
pub fn validate_str<S: AsRef<str>>(
    field_name: &str,
    data: S,
    min_length: usize,
    max_length: usize,
) -> anyhow::Result<S> {
    if !is_valid_str(data.as_ref(), min_length, max_length) {
        status_bail!(
            StatusCode::BAD_REQUEST,
            "'{}' must be between {} and {} characters long",
            field_name,
            min_length,
            max_length
        );
    }

    Ok(data)
}

/// Matches safe ID characters: alphanumeric plus `_`, `-`, `:`, `/` (max 64 chars).
static VALID_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_\-:/]{1,64}$").expect("Invalid regex"));

/// Checks if an ID contains only safe characters and is within length limit.
pub fn is_valid_id(id: &str) -> bool {
    VALID_ID_REGEX.is_match(id)
}

/// Validates an ID, returning 400 on failure.
pub fn validate_id<S: AsRef<str>>(field_name: &str, id: S) -> anyhow::Result<S> {
    if !is_valid_id(id.as_ref()) {
        status_bail!(
            StatusCode::BAD_REQUEST,
            "'{}' must only contain letters, digits, '_', '-', ':', or '/'",
            field_name
        );
    }

    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::error::ApiError;

    // is_valid_str tests

    #[test]
    fn is_valid_str_accepts_valid_length() {
        assert!(is_valid_str("hello", 1, 10));
        assert!(is_valid_str("hello", 5, 5)); // exact length
        assert!(is_valid_str("", 0, 10)); // empty allowed
    }

    #[test]
    fn is_valid_str_rejects_too_short() {
        assert!(!is_valid_str("hi", 3, 10));
        assert!(!is_valid_str("", 1, 10));
    }

    #[test]
    fn is_valid_str_rejects_too_long() {
        assert!(!is_valid_str("hello world", 1, 5));
        assert!(!is_valid_str("abc", 1, 2));
    }

    // validate_str tests

    #[test]
    fn validate_str_returns_value_on_success() {
        let result = validate_str("field", "hello", 1, 10);
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn validate_str_returns_400_on_failure() {
        let err = validate_str("username", "hi", 3, 10).unwrap_err();
        let api_error = err.downcast_ref::<ApiError>().unwrap();
        assert_eq!(api_error.status, StatusCode::BAD_REQUEST);
        assert!(api_error.message.contains("username"));
    }

    // is_valid_id tests

    #[test]
    fn is_valid_id_accepts_alphanumeric() {
        assert!(is_valid_id("abc123"));
        assert!(is_valid_id("ABC"));
        assert!(is_valid_id("123"));
    }

    #[test]
    fn is_valid_id_accepts_special_chars() {
        assert!(is_valid_id("user_name"));
        assert!(is_valid_id("user-name"));
        assert!(is_valid_id("namespace:id"));
        assert!(is_valid_id("path/to/resource"));
        assert!(is_valid_id("a_b-c:d/e"));
    }

    #[test]
    fn is_valid_id_rejects_invalid_chars() {
        assert!(!is_valid_id("hello world")); // space
        assert!(!is_valid_id("user@domain")); // @
        assert!(!is_valid_id("a.b")); // dot
        assert!(!is_valid_id("a#b")); // hash
        assert!(!is_valid_id("über")); // umlaut
    }

    #[test]
    fn is_valid_id_rejects_empty() {
        assert!(!is_valid_id(""));
    }

    #[test]
    fn is_valid_id_rejects_too_long() {
        let long_id = "a".repeat(65);
        assert!(!is_valid_id(&long_id));

        let max_id = "a".repeat(64);
        assert!(is_valid_id(&max_id));
    }

    // validate_id tests

    #[test]
    fn validate_id_returns_value_on_success() {
        let result = validate_id("user_id", "abc123");
        assert_eq!(result.unwrap(), "abc123");
    }

    #[test]
    fn validate_id_returns_400_on_failure() {
        let err = validate_id("user_id", "invalid@id").unwrap_err();
        let api_error = err.downcast_ref::<ApiError>().unwrap();
        assert_eq!(api_error.status, StatusCode::BAD_REQUEST);
        assert!(api_error.message.contains("user_id"));
    }
}
