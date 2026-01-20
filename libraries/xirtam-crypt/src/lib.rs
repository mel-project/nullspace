#![doc = include_str!(concat!(env!("OUT_DIR"), "/README-rustdocified.md"))]

pub mod aead;
pub mod dh;
mod encoding;
pub mod hash;
pub mod signing;
pub mod stream;
pub use encoding::ParseKeyError;

fn redacted_debug<T>(_value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("REDACTED")
}
