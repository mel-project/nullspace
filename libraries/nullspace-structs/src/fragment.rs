use std::borrow::Cow;

use derivative::Derivative;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{FromInto, IfIsHumanReadable, serde_as};
use smol_str::SmolStr;

/// A fragment root, which summarizes a bunch of fragments into a single artifact. This is something that can be sent in messages to represent attachments, for example.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FragmentRoot {
    pub filename: SmolStr,
    pub mime: SmolStr,
    pub total_size: u64,
    pub pointers: Vec<Hash>,
}

/// A fragment node, which contains pointers to other fragment nodes and/or leaves.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FragmentNode {
    pub size: u64,
    pub pointers: Vec<Hash>,
}

/// A fragment leaf, which must contain a single piece of data.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative)]
#[derivative(Debug)]
pub struct FragmentLeaf<'a> {
    #[derivative(Debug(format_with = "crate::debug_bytes_len"))]
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    pub data: Cow<'a, [u8]>,
}

/// Either a fragment node or leaf.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Fragment<'a> {
    Node(FragmentNode),
    Leaf(FragmentLeaf<'a>),
}

impl<'a> Fragment<'a> {
    pub fn to_static(self) -> Fragment<'static> {
        match self {
            Fragment::Node(node) => Fragment::Node(node),
            Fragment::Leaf(leaf) => Fragment::Leaf(FragmentLeaf {
                data: Cow::Owned(leaf.data.into_owned()),
            }),
        }
    }
}

const CHUNK_SIZE_BYTES: usize = 256 * 1024;
const MAX_FANOUT: usize = 4096;

/// A helper function to divide up a whole file into fragments.
pub fn file_into_fragments<'a>(
    filename: &str,
    mime: &str,
    data: &'a [u8],
) -> (FragmentRoot, Vec<Fragment<'a>>) {
    if data.is_empty() {
        return (
            FragmentRoot {
                filename: SmolStr::new(filename),
                mime: SmolStr::new(mime),
                total_size: 0,
                pointers: Vec::new(),
            },
            Vec::new(),
        );
    }

    struct ChildRef {
        hash: Hash,
        size: u64,
    }

    let mut fragments = Vec::new();
    let mut current_level = Vec::new();

    for chunk in data.chunks(CHUNK_SIZE_BYTES) {
        let leaf = FragmentLeaf {
            data: Cow::Borrowed(chunk),
        };
        let hash = leaf.bcs_hash();
        current_level.push(ChildRef {
            hash,
            size: chunk.len() as u64,
        });
        fragments.push(Fragment::Leaf(leaf));
    }

    while current_level.len() > MAX_FANOUT {
        let mut next_level = Vec::new();
        for group in current_level.chunks(MAX_FANOUT) {
            let pointers: Vec<Hash> = group.iter().map(|child| child.hash).collect();
            let size = group.iter().map(|child| child.size).sum();
            let node = FragmentNode { size, pointers };
            let hash = node.bcs_hash();
            next_level.push(ChildRef { hash, size });
            fragments.push(Fragment::Node(node));
        }
        current_level = next_level;
    }

    let root = FragmentRoot {
        filename: SmolStr::new(filename),
        mime: SmolStr::new(mime),
        total_size: data.len() as u64,
        pointers: current_level.into_iter().map(|child| child.hash).collect(),
    };

    (root, fragments)
}
