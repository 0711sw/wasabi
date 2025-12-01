use bytes::Bytes;
use futures_util::Stream;
use std::pin::Pin;

pub mod i18n_string;
pub mod id_generator;
pub mod system;
pub mod watch;

pub type PinnedBytesStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Unpin + Send>>;

pub fn not<F, T>(f: F) -> impl Fn(&T) -> bool
where
    F: Fn(&T) -> bool,
{
    move |x| !f(x)
}
