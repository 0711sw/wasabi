use bytesize::MB;

pub mod auth;
pub mod error;
pub mod info_service;
pub mod favicon_service;
pub mod validation;
pub mod warp;

pub const DEFAULT_MAX_JSON_BODY_SIZE: u64 = 10 * MB;
