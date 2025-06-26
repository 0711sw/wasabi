use std::pin::Pin;
use bytes::Bytes;
use futures_util::Stream;

pub mod system;
pub mod id_generator;
pub mod i18n_string;


pub type PinnedBytesStream = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Unpin + Send>>;

pub fn not<F, T>(f: F) -> impl Fn(&T) -> bool
where
    F: Fn(&T) -> bool,
{
    move |x| !f(x)
}