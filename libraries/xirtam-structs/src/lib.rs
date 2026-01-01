pub mod directory;
pub mod envelope;

use bytes::Bytes;
use derivative::Derivative;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Derivative)]
#[derivative(Debug)]
/// A generic message type, used across the xirtam ecosystem.
pub struct Message {
    pub kind: String,
    #[derivative(Debug(format_with = "debug_bytes_len"))]
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
    v1_kind!(message_content);
    v1_kind!(direct_message);
    v1_kind!(group_message);
}

fn debug_bytes_len(bytes: &Bytes, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "[{} bytes]", bytes.len())
}
