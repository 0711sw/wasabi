use bytesize::MB;

pub mod error;
pub mod info_service;
pub mod auth;
pub mod warp;
pub mod validation;

pub const DEFAULT_MAX_JSON_BODY_SIZE: u64 = 10 * MB;
