use arboard::Clipboard;
use image::codecs::png::PngEncoder;
use image::{ColorType, ImageEncoder};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct PasteImage {
    pub png_bytes: Vec<u8>,
    pub width: usize,
    pub height: usize,
    pub uri: String,
}

pub fn read_clipboard_image() -> Result<PasteImage, String> {
    let mut clipboard = Clipboard::new().map_err(|err| format!("clipboard error: {err}"))?;
    let image = clipboard
        .get_image()
        .map_err(|_| "clipboard has no image".to_string())?;
    let width = image.width;
    let height = image.height;
    let bytes = image.bytes.into_owned();
    let mut png_bytes = Vec::new();
    let encoder = PngEncoder::new(&mut png_bytes);
    encoder
        .write_image(
            bytes.as_slice(),
            width as u32,
            height as u32,
            ColorType::Rgba8.into(),
        )
        .map_err(|err| format!("failed to encode clipboard image: {err}"))?;
    let uri = format!("bytes://paste-image-{}", unix_nanos());
    Ok(PasteImage {
        png_bytes,
        width,
        height,
        uri,
    })
}

pub fn persist_paste_image(image: &PasteImage) -> Result<PathBuf, String> {
    let path = temp_paste_path();
    fs::write(&path, &image.png_bytes).map_err(|err| format!("failed to write pasted image: {err}"))?;
    Ok(path)
}

fn temp_paste_path() -> PathBuf {
    let name = format!("nullspace-paste-{}.png", unix_nanos());
    std::env::temp_dir().join(name)
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
