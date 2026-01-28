pub mod certificate;
pub mod directory;
pub mod e2ee;
pub mod event;
pub mod fragment;
pub mod group;
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
use smol_str::SmolStr;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative)]
#[derivative(Debug)]
/// A generic tagged blob, used across the nullspace ecosystem.
pub struct Blob {
    pub kind: SmolStr,
    #[derivative(Debug(format_with = "debug_bytes_len"))]
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    pub inner: Bytes,
}

macro_rules! v1_kind {
    ($name:ident) => {
        paste::paste! {
            pub const [<V1_ $name:upper>]: &str = concat!("v1.", stringify!($name));
        }
    };
}

impl Blob {
    v1_kind!(user_descriptor);
    v1_kind!(server_descriptor);

    v1_kind!(message_content);
    v1_kind!(plaintext_direct_message);
    v1_kind!(direct_message);
    v1_kind!(group_message);
    v1_kind!(group_rekey);
}

fn debug_bytes_len<T: AsRef<[u8]>>(bytes: &T, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "[{} bytes]", bytes.as_ref().len())
}
