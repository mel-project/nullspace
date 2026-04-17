use fast_image_resize as fr;
use fast_thumbhash::rgba_to_thumb_hash_b91;

const IMAGE_MAX_DIMENSION: u32 = 2000;
const IMAGE_TARGET_SIZE_BYTES: usize = 500_000;
const IMAGE_WEBP_QUALITY: f32 = 70.0;
const THUMBHASH_MAX_DIMENSION: u32 = 100;

pub struct PreparedImage {
    pub webp_bytes: Vec<u8>,
    pub thumbhash: String,
    pub width: u32,
    pub height: u32,
}

pub fn prepare_webp_and_thumbhash(source_bytes: &[u8]) -> anyhow::Result<PreparedImage> {
    let decoded = image::load_from_memory(source_bytes)?;
    let (src_w, src_h) = (decoded.width(), decoded.height());
    if src_w == 0 || src_h == 0 {
        return Err(anyhow::anyhow!("image has invalid dimensions"));
    }

    // Use native pixel format to avoid a full-resolution RGBA conversion.
    let (src_buf, pixel_type) = match decoded {
        image::DynamicImage::ImageRgb8(img) => (img.into_raw(), fr::PixelType::U8x3),
        image::DynamicImage::ImageRgba8(img) => (img.into_raw(), fr::PixelType::U8x4),
        other => (other.into_rgba8().into_raw(), fr::PixelType::U8x4),
    };

    // Linearize the source image once, then reuse for all resize iterations.
    let mut src_image = fr::images::Image::from_vec_u8(src_w, src_h, src_buf, pixel_type)
        .map_err(|err| anyhow::anyhow!("failed to prepare source image: {err}"))?;
    let srgb_mapper = fr::create_srgb_mapper();
    srgb_mapper
        .forward_map_inplace(&mut src_image)
        .map_err(|err| anyhow::anyhow!("failed to linearize source image: {err}"))?;

    let (mut width, mut height) = fit_within(src_w, src_h, IMAGE_MAX_DIMENSION);
    tracing::debug!(
        width,
        height,
        quality = IMAGE_WEBP_QUALITY,
        "image upload compression parameters"
    );

    loop {
        let resized = resize_linear(&src_image, &srgb_mapper, width, height)?;
        let webp_bytes = encode_webp(pixel_type, &resized, width, height)?;
        if webp_bytes.len() <= IMAGE_TARGET_SIZE_BYTES || (width == 1 && height == 1) {
            let thumbhash = make_thumbhash_b91(pixel_type, &resized, width, height)?;
            return Ok(PreparedImage {
                webp_bytes,
                thumbhash,
                width: src_w,
                height: src_h,
            });
        }
        width = (width / 2).max(1);
        height = (height / 2).max(1);
    }
}

fn fit_within(width: u32, height: u32, max_side: u32) -> (u32, u32) {
    let longest = width.max(height);
    if longest <= max_side {
        return (width, height);
    }
    let scale = max_side as f64 / longest as f64;
    let new_w = ((width as f64) * scale).round().max(1.0) as u32;
    let new_h = ((height as f64) * scale).round().max(1.0) as u32;
    (new_w, new_h)
}

fn resize_linear(
    src: &fr::images::Image,
    srgb_mapper: &fr::PixelComponentMapper,
    dst_w: u32,
    dst_h: u32,
) -> anyhow::Result<fr::images::Image<'static>> {
    if src.width() == dst_w && src.height() == dst_h {
        let mut out = src.copy();
        srgb_mapper
            .backward_map_inplace(&mut out)
            .map_err(|err| anyhow::anyhow!("failed to convert from linear: {err}"))?;
        return Ok(out);
    }
    let mut dst = fr::images::Image::new(dst_w, dst_h, src.pixel_type());
    let options =
        fr::ResizeOptions::new().resize_alg(fr::ResizeAlg::Convolution(fr::FilterType::Lanczos3));
    let mut resizer = fr::Resizer::new();
    resizer
        .resize(src, &mut dst, Some(&options))
        .map_err(|err| anyhow::anyhow!("failed to resize image: {err}"))?;
    srgb_mapper
        .backward_map_inplace(&mut dst)
        .map_err(|err| anyhow::anyhow!("failed to convert from linear: {err}"))?;
    Ok(dst)
}

fn encode_webp(
    pixel_type: fr::PixelType,
    image: &fr::images::Image,
    width: u32,
    height: u32,
) -> anyhow::Result<Vec<u8>> {
    let encoder = match pixel_type {
        fr::PixelType::U8x3 => webp::Encoder::from_rgb(image.buffer(), width, height),
        _ => webp::Encoder::from_rgba(image.buffer(), width, height),
    };
    Ok(encoder.encode(IMAGE_WEBP_QUALITY).to_vec())
}

fn make_thumbhash_b91(
    pixel_type: fr::PixelType,
    image: &fr::images::Image,
    width: u32,
    height: u32,
) -> anyhow::Result<String> {
    let (thumb_w, thumb_h) = fit_within(width, height, THUMBHASH_MAX_DIMENSION);
    // Thumbhash needs RGBA. Convert only this small image.
    let rgba_buf = if thumb_w == width && thumb_h == height {
        to_rgba_buf(pixel_type, image.buffer())
    } else {
        // Re-linearize the (already sRGB) resized image for a second resize.
        let srgb_mapper = fr::create_srgb_mapper();
        let mut src =
            fr::images::Image::from_vec_u8(width, height, image.buffer().to_vec(), pixel_type)
                .map_err(|err| anyhow::anyhow!("failed to prepare thumbhash source: {err}"))?;
        srgb_mapper.forward_map_inplace(&mut src).ok();
        let preview = resize_linear(&src, &srgb_mapper, thumb_w, thumb_h)?;
        to_rgba_buf(pixel_type, preview.buffer())
    };
    Ok(rgba_to_thumb_hash_b91(
        thumb_w as usize,
        thumb_h as usize,
        &rgba_buf,
    ))
}

fn to_rgba_buf(pixel_type: fr::PixelType, buf: &[u8]) -> Vec<u8> {
    match pixel_type {
        fr::PixelType::U8x4 => buf.to_vec(),
        _ => {
            let mut rgba = Vec::with_capacity(buf.len() / 3 * 4);
            for chunk in buf.chunks_exact(3) {
                rgba.extend_from_slice(chunk);
                rgba.push(255);
            }
            rgba
        }
    }
}
