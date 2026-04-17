mod download;
mod images;
mod roots;
mod upload;

use std::sync::Arc;

pub use download::{
    attachment_download, attachment_download_oneshot, attachment_download_oneshot_with_progress,
    attachment_status,
};
pub use roots::AttachmentStatus;
pub use upload::{attachment_upload, attachment_upload_path, image_attachment_upload};

pub type TransferProgressCallback = Arc<dyn Fn(u64, u64) + Send + Sync + 'static>;
