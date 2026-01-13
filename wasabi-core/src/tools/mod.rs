//! Common utilities used across the framework.

use bytes::Bytes;
use futures_util::Stream;
use std::pin::Pin;

pub mod i18n_string;
pub mod id_generator;
pub mod system;
pub mod watch;

/// A pinned, boxed byte stream for async streaming responses.
///
/// Used throughout the framework for streaming HTTP response bodies
/// without tying handlers to a specific stream implementation.
pub type PinnedBytesStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Unpin + Send>>;

/// Negates a predicate function.
///
/// Useful for filtering with iterator methods when you need the inverse
/// of an existing predicate without writing a closure.
pub fn not<F, T>(f: F) -> impl Fn(&T) -> bool
where
    F: Fn(&T) -> bool,
{
    move |x| !f(x)
}
