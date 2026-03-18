//! Warp response helpers for serving PDF documents.

use warp::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use warp::reply::{self, Reply};

/// Create a warp reply with PDF content-type and attachment disposition.
pub fn pdf_response(bytes: Vec<u8>, filename: &str) -> impl Reply {
    reply::with_header(
        reply::with_header(bytes, CONTENT_TYPE, "application/pdf"),
        CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\""),
    )
}
