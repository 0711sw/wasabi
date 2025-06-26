use crate::status_bail;
use regex::Regex;
use std::sync::LazyLock;
use warp::http::StatusCode;

pub fn is_valid_str(data: &str, min_length: usize, max_length: usize) -> bool {
    let len = data.len();
    len >= min_length && len <= max_length
}

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

/// Erlaubte Zeichen: a-z, A-Z, 0-9, _, -, :, /
static VALID_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_\-:/]{1,64}$").expect("Invalid regex"));

pub fn is_valid_id(id: &str) -> bool {
    VALID_ID_REGEX.is_match(id)
}
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
