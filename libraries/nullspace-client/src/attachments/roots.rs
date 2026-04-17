use std::path::PathBuf;

use nullspace_structs::fragment::Attachment;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttachmentStatus {
    pub frag_root: Attachment,
    pub saved_to: Option<PathBuf>,
}
