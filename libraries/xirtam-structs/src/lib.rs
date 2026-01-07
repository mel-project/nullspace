pub mod certificate;
pub mod directory;
pub mod envelope;
pub mod gateway;
pub mod handle;
pub mod timestamp;

use bytes::Bytes;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use serde_with::{FromInto, IfIsHumanReadable, base64::Base64, serde_as};
use smol_str::SmolStr;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative)]
#[derivative(Debug)]
/// A generic message type, used across the xirtam ecosystem.
pub struct Message {
    pub kind: SmolStr,
    #[derivative(Debug(format_with = "debug_bytes_len"))]
    #[serde_as(as = "IfIsHumanReadable<Base64, FromInto<Vec<u8>>>")]
    pub inner: Bytes,
}

macro_rules! v1_kind {
    ($name:ident) => {
        paste::paste! {
            pub const [<V1_ $name:upper>]: &str = concat!("v1.", stringify!($name));
        }
    };
}

impl Message {
    v1_kind!(root_cert_hash);
    v1_kind!(gateway_descriptor);

    v1_kind!(message_content);
    v1_kind!(direct_message);
    v1_kind!(group_message);
}

fn debug_bytes_len(bytes: &Bytes, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "[{} bytes]", bytes.len())
}
