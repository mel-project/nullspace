use derivative::Derivative;
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::hash::Hash;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{Bytes as SerdeBytes, FromInto, IfIsHumanReadable, serde_as};
use smol_str::SmolStr;

use crate::event::EventPayload;

/// A fragment root, which summarizes a bunch of fragments into a single artifact. This is something that can be sent in messages to represent attachments, for example.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FragmentRoot {
    pub filename: SmolStr,
    pub mime: SmolStr,
    pub children: Vec<(Hash, u64)>,
    pub content_key: AeadKey,
}

/// A fragment node, which contains pointers to other fragment nodes and/or leaves.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FragmentNode {
    pub children: Vec<(Hash, u64)>,
}

/// A fragment leaf, which must contain a single piece of data.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative)]
#[derivative(Debug)]
pub struct FragmentLeaf {
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, SerdeBytes>")]
    pub nonce: [u8; 24],
    #[derivative(Debug(format_with = "crate::debug_bytes_len"))]
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    pub data: Bytes,
}

/// Either a fragment node or leaf.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Fragment {
    Node(FragmentNode),
    Leaf(FragmentLeaf),
}

impl FragmentRoot {
    pub fn total_size(&self) -> u64 {
        self.children.iter().map(|(_, size)| *size).sum()
    }
}

impl FragmentNode {
    pub fn total_size(&self) -> u64 {
        self.children.iter().map(|(_, size)| *size).sum()
    }
}

impl EventPayload for FragmentRoot {
    fn mime() -> &'static str {
        "application/vnd.nullspace.v1.attachment"
    }
}
