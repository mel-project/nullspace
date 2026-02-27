pub mod certificate;
pub mod directory;
pub mod e2ee;
pub mod event;
pub mod fragment;
pub mod group;
pub mod mailbox;
pub mod profile;
pub mod server;
pub mod timestamp;
pub mod username;

pub use nullspace_crypt::stream::StreamKey;

use bytes::Bytes;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{FromInto, IfIsHumanReadable, serde_as};

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative)]
#[derivative(Debug)]
#[serde(transparent)]
/// Opaque byte payload serialized as base64 in human-readable formats.
pub struct Blob(
    #[derivative(Debug(format_with = "debug_bytes_len"))]
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    pub Bytes,
);

fn debug_bytes_len<T: AsRef<[u8]>>(bytes: &T, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "[{} bytes]", bytes.as_ref().len())
}
