use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::thread::available_parallelism;
use std::time::{Duration, Instant};

use eframe::egui::{Response, Widget};

use fast_thumbhash::thumb_hash_from_b91;
use image::GenericImageView;
use moka::sync::Cache;
use smol::lock::Semaphore;

use crate::utils::hooks::{CustomHooksExt, SlotState};

#[derive(Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    filename: PathBuf,
    max_texel_box: u32,
    preserve_aspect_ratio: bool,
}

static IMAGE_CACHE: LazyLock<Cache<CacheKey, eframe::egui::TextureHandle>> =
    LazyLock::new(|| Cache::builder().max_capacity(100).build());

/// Stores any texture for a given file path, regardless of target size.
/// Used as a fast fallback: if the exact size isn't ready yet but we have
/// a previously-rendered version, we can display it hardware-scaled while
/// the Lanczos3 resize runs in the background.
static ANY_CACHE: LazyLock<Cache<PathBuf, eframe::egui::TextureHandle>> =
    LazyLock::new(|| Cache::builder().max_capacity(100).build());

pub struct SmoothImage<'a> {
    filename: &'a Path,
    thumbhash: Option<&'a str>,
    max_size: eframe::egui::Vec2,
    corner_radius: eframe::egui::CornerRadius,
    preserve_aspect_ratio: bool,
    aspect_ratio: Option<f32>,
    sense: eframe::egui::Sense,
}

impl<'a> SmoothImage<'a> {
    pub fn new(filename: &'a Path) -> Self {
        Self {
            filename,
            thumbhash: None,
            max_size: eframe::egui::Vec2::splat(100.0),
            corner_radius: eframe::egui::CornerRadius::ZERO,
            preserve_aspect_ratio: true,
            aspect_ratio: None,
            sense: eframe::egui::Sense::empty(),
        }
    }

    pub fn fit_to_size(self, max_size: eframe::egui::Vec2) -> Self {
        Self { max_size, ..self }
    }

    pub fn corner_radius(self, corner_radius: eframe::egui::CornerRadius) -> Self {
        Self {
            corner_radius,
            ..self
        }
    }

    pub fn preserve_aspect_ratio(self, preserve_aspect_ratio: bool) -> Self {
        Self {
            preserve_aspect_ratio,
            ..self
        }
    }

    pub fn sense(self, sense: eframe::egui::Sense) -> Self {
        Self { sense, ..self }
    }

    pub fn thumbhash(self, thumbhash: Option<&'a str>) -> Self {
        Self { thumbhash, ..self }
    }

    pub fn aspect_ratio(self, aspect_ratio: f32) -> Self {
        Self {
            aspect_ratio: Some(aspect_ratio),
            ..self
        }
    }
}

impl Widget for SmoothImage<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let pixels_per_point = ui.ctx().pixels_per_point();
        let max_texel_box = max_texel_box(pixels_per_point, self.max_size);
        let cache_key = CacheKey {
            filename: self.filename.to_path_buf(),
            max_texel_box: max_texel_box[0] * max_texel_box[1],
            preserve_aspect_ratio: self.preserve_aspect_ratio,
        };

        // Fast path: exact-size texture is already cached.
        if let Some(texture) = IMAGE_CACHE.get(&cache_key) {
            let ui_size = texture_size_points(pixels_per_point, texture.size());
            let (rect, response) = ui.allocate_exact_size(ui_size, self.sense);
            eframe::egui::Image::from_texture(&texture)
                .corner_radius(self.corner_radius)
                .texture_options(eframe::egui::TextureOptions::NEAREST)
                .paint_at(ui, rect);
            return response;
        }
        ui.ctx().request_repaint();

        // Look up any previously-rendered texture for this file (possibly a
        // different target size).  We can show it hardware-scaled as a
        // placeholder while the Lanczos3 resize runs in the background.
        let stale_texture = ANY_CACHE.get(&self.filename.to_path_buf());

        let resize =
            ui.use_async_slot::<Result<eframe::egui::TextureHandle, String>>(cache_key.clone());

        let texture = match resize.poll() {
            SlotState::Done(Ok(texture)) => Some(texture),
            SlotState::Done(Err(err)) => {
                let ui_size =
                    fallback_ui_size(self.max_size, self.preserve_aspect_ratio, self.aspect_ratio);
                let (rect, response) = ui.allocate_exact_size(ui_size, self.sense);
                paint_error(ui, rect, &err);
                return response;
            }
            SlotState::Idle | SlotState::Busy => None,
        };

        // Determine the display size.  Prefer the exact texture's size, then
        // derive aspect ratio from a stale texture if available, then fall
        // back to the caller-supplied hint / square.
        let ui_size = texture
            .as_ref()
            .map(|t| texture_size_points(pixels_per_point, t.size()))
            .or_else(|| {
                stale_texture.as_ref().and_then(|t| {
                    if !self.preserve_aspect_ratio {
                        return None; // use fallback (max_size)
                    }
                    let [w, h] = t.size();
                    let stale_size = eframe::egui::Vec2::new(w as f32, h as f32);
                    Some(scale_to_fit(stale_size, self.max_size))
                })
            })
            .unwrap_or_else(|| {
                fallback_ui_size(self.max_size, self.preserve_aspect_ratio, self.aspect_ratio)
            });
        let (rect, response) = ui.allocate_exact_size(ui_size, self.sense);

        if let Some(texture) = texture {
            eframe::egui::Image::from_texture(&texture)
                .corner_radius(self.corner_radius)
                .texture_options(eframe::egui::TextureOptions::NEAREST)
                .paint_at(ui, rect);
        } else {
            // Show the best placeholder we have: a stale texture (hardware-
            // scaled), or a thumbhash / solid colour.
            let debounce;
            if let Some(stale) = &stale_texture {
                eframe::egui::Image::from_texture(stale)
                    .corner_radius(self.corner_radius)
                    .texture_options(eframe::egui::TextureOptions::NEAREST)
                    .fit_to_exact_size(rect.size())
                    .paint_at(ui, rect);
                debounce = true;
            } else {
                tracing::debug!(th = debug(&self.thumbhash), "printing loading state!");
                paint_loading(ui, rect, self.corner_radius, self.thumbhash);
                debounce = false;
            }

            if resize.is_idle() {
                let ctx = ui.ctx().clone();
                let id = ui.id();
                let filename = self.filename.to_path_buf();
                let cache_key = cache_key.clone();
                let preserve_aspect_ratio = self.preserve_aspect_ratio;
                resize.start(async move {
                    // debounce a bit
                    if debounce {
                        smol::Timer::after(Duration::from_millis(50)).await;
                    }
                    // limit concurrency
                    static SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| {
                        Semaphore::new((available_parallelism().unwrap().get() / 2).max(1))
                    });
                    let _guard = SEMAPHORE.acquire().await;
                    smol::unblock(move || {
                        let bytes = std::fs::read(&filename).map_err(|e| e.to_string())?;
                        let decoded = image::load_from_memory(&bytes).map_err(|e| e.to_string())?;
                        let texel_size = target_texel_size(
                            max_texel_box,
                            decoded.dimensions(),
                            preserve_aspect_ratio,
                        );
                        let texture = make_texture(&ctx, decoded, texel_size, id)?;
                        IMAGE_CACHE.insert(cache_key, texture.clone());
                        ANY_CACHE.insert(filename, texture.clone());

                        Ok(texture)
                    })
                    .await
                });
            }
        }

        response
    }
}

fn max_texel_box(pixels_per_point: f32, max_size_points: eframe::egui::Vec2) -> [u32; 2] {
    let w = (max_size_points.x * pixels_per_point)
        .round()
        .max(1.0)
        .min(u32::MAX as f32) as u32;
    let h = (max_size_points.y * pixels_per_point)
        .round()
        .max(1.0)
        .min(u32::MAX as f32) as u32;
    [w, h]
}

fn fallback_ui_size(
    max_size: eframe::egui::Vec2,
    preserve_aspect_ratio: bool,
    aspect_ratio: Option<f32>,
) -> eframe::egui::Vec2 {
    if preserve_aspect_ratio {
        let source = match aspect_ratio {
            Some(ar) if ar.is_finite() && ar > 0.0 => eframe::egui::Vec2::new(ar, 1.0),
            _ => eframe::egui::Vec2::splat(1.0),
        };
        scale_to_fit(source, max_size)
    } else {
        max_size
    }
}

fn target_texel_size(
    max_texel_box: [u32; 2],
    decoded_dimensions: (u32, u32),
    preserve_aspect_ratio: bool,
) -> [u32; 2] {
    let (src_w, src_h) = decoded_dimensions;
    if src_w == 0 || src_h == 0 {
        return [1, 1];
    }
    if preserve_aspect_ratio {
        let src = eframe::egui::Vec2::new(src_w as f32, src_h as f32);
        let available = eframe::egui::Vec2::new(max_texel_box[0] as f32, max_texel_box[1] as f32);
        let scaled = scale_to_fit(src, available);
        let w = scaled.x.round().max(1.0).min(max_texel_box[0] as f32) as u32;
        let h = scaled.y.round().max(1.0).min(max_texel_box[1] as f32) as u32;
        [w, h]
    } else {
        [max_texel_box[0].max(1), max_texel_box[1].max(1)]
    }
}

fn scale_to_fit(
    image_size: eframe::egui::Vec2,
    available_size: eframe::egui::Vec2,
) -> eframe::egui::Vec2 {
    let ratio_x = available_size.x / image_size.x;
    let ratio_y = available_size.y / image_size.y;
    let ratio = if ratio_x < ratio_y { ratio_x } else { ratio_y };
    let ratio = if ratio.is_finite() { ratio } else { 1.0 };
    image_size * ratio
}

fn texture_size_points(pixels_per_point: f32, texel_size: [usize; 2]) -> eframe::egui::Vec2 {
    eframe::egui::Vec2::new(texel_size[0] as f32, texel_size[1] as f32) / pixels_per_point
}

fn make_texture(
    ctx: &eframe::egui::Context,
    decoded: image::DynamicImage,
    texel_size: [u32; 2],
    id: eframe::egui::Id,
) -> Result<eframe::egui::TextureHandle, String> {
    let start = Instant::now();
    let (src_w, src_h) = decoded.dimensions();

    // Use the native pixel format directly—avoids a full-resolution RGBA conversion.
    let (src_buf, pixel_type, has_alpha) = match decoded {
        image::DynamicImage::ImageRgb8(img) => {
            (img.into_raw(), fast_image_resize::PixelType::U8x3, false)
        }
        image::DynamicImage::ImageRgba8(img) => {
            (img.into_raw(), fast_image_resize::PixelType::U8x4, true)
        }
        other => (
            other.into_rgba8().into_raw(),
            fast_image_resize::PixelType::U8x4,
            true,
        ),
    };

    let mut src_image =
        fast_image_resize::images::Image::from_vec_u8(src_w, src_h, src_buf, pixel_type)
            .map_err(|e| format!("failed to prepare source image for resize: {e}"))?;
    let srgb_mapper = fast_image_resize::create_srgb_mapper();
    srgb_mapper
        .forward_map_inplace(&mut src_image)
        .map_err(|e| format!("failed to convert source image from sRGB to linear RGB: {e}"))?;
    let mut dst_image =
        fast_image_resize::images::Image::new(texel_size[0], texel_size[1], pixel_type);
    let options = fast_image_resize::ResizeOptions::new().resize_alg(
        fast_image_resize::ResizeAlg::Convolution(fast_image_resize::FilterType::Lanczos3),
    );
    let mut resizer = fast_image_resize::Resizer::new();
    resizer
        .resize(&src_image, &mut dst_image, Some(&options))
        .map_err(|e| format!("failed to resize image: {e}"))?;
    srgb_mapper
        .backward_map_inplace(&mut dst_image)
        .map_err(|e| format!("failed to convert resized image from linear RGB to sRGB: {e}"))?;

    let size = [texel_size[0] as usize, texel_size[1] as usize];
    let color_image = if has_alpha {
        eframe::egui::ColorImage::from_rgba_unmultiplied(size, dst_image.buffer())
    } else {
        eframe::egui::ColorImage::from_rgb(size, dst_image.buffer())
    };
    tracing::trace!(texel_size=?texel_size, elapsed=debug(start.elapsed()), "finished processing image");

    Ok(ctx.load_texture(
        format!("smooth_image_{:?}_{}x{}", id, texel_size[0], texel_size[1]),
        color_image,
        eframe::egui::TextureOptions::NEAREST,
    ))
}

fn paint_loading(
    ui: &mut eframe::egui::Ui,
    rect: eframe::egui::Rect,
    corner_radius: eframe::egui::CornerRadius,
    thumbhash: Option<&str>,
) {
    if let Some(encoded) = thumbhash
        && let Ok((w, h, rgba)) = thumb_hash_from_b91(encoded)
    {
        let image = eframe::egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba);
        let texture = ui.ctx().load_texture(
            format!("smooth_thumbhash_{encoded}"),
            image,
            eframe::egui::TextureOptions::LINEAR,
        );
        eframe::egui::Image::from_texture(&texture)
            .corner_radius(corner_radius)
            .texture_options(eframe::egui::TextureOptions::LINEAR)
            .fit_to_exact_size(rect.size())
            .paint_at(ui, rect);
        return;
    }
    ui.painter()
        .rect_filled(rect, corner_radius, eframe::egui::Color32::LIGHT_GRAY);
    // eframe::egui::Spinner::new().paint_at(ui, rect);
}

fn paint_error(ui: &mut eframe::egui::Ui, rect: eframe::egui::Rect, err: &str) {
    ui.painter().rect_filled(
        rect,
        eframe::egui::CornerRadius::ZERO,
        eframe::egui::Color32::from_rgb(80, 20, 20),
    );
    ui.painter().text(
        rect.center(),
        eframe::egui::Align2::CENTER_CENTER,
        "Image error",
        eframe::egui::TextStyle::Body.resolve(ui.style()),
        eframe::egui::Color32::LIGHT_RED,
    );

    let mut message = err.lines().next().unwrap_or(err).to_string();
    if message.len() > 80 {
        message.truncate(77);
        message.push_str("...");
    }
    ui.painter().text(
        rect.center() + eframe::egui::vec2(0.0, 16.0),
        eframe::egui::Align2::CENTER_CENTER,
        message,
        eframe::egui::TextStyle::Small.resolve(ui.style()),
        eframe::egui::Color32::LIGHT_RED,
    );
}
