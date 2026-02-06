use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use eframe::egui::{Response, Widget};
use egui_hooks::UseHookExt;
use image::GenericImageView;
use moka::sync::Cache;
use poll_promise::Promise;

use crate::promises::PromiseSlot;

#[derive(Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    filename: PathBuf,
    max_texel_box: [u32; 2],
}

static IMAGE_CACHE: LazyLock<Cache<CacheKey, eframe::egui::TextureHandle>> = LazyLock::new(|| {
    Cache::builder()
        .time_to_idle(Duration::from_secs(3600))
        .build()
});

pub struct SmoothImage<'a> {
    filename: &'a Path,
    max_size: eframe::egui::Vec2,
    corner_radius: eframe::egui::CornerRadius,
    preserve_aspect_ratio: bool,
    sense: eframe::egui::Sense,
}

impl<'a> SmoothImage<'a> {
    pub fn new(filename: &'a Path) -> Self {
        Self {
            filename,
            max_size: eframe::egui::Vec2::splat(100.0),
            corner_radius: eframe::egui::CornerRadius::ZERO,
            preserve_aspect_ratio: true,
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
}

impl Widget for SmoothImage<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let pixels_per_point = ui.ctx().pixels_per_point();
        let max_texel_box = max_texel_box(pixels_per_point, self.max_size);
        let cache_key = CacheKey {
            filename: self.filename.to_path_buf(),
            max_texel_box,
        };

        if let Some(texture) = IMAGE_CACHE.get(&cache_key) {
            let ui_size = texture_size_points(pixels_per_point, texture.size());
            let (rect, response) = ui.allocate_exact_size(ui_size, self.sense);
            eframe::egui::Image::from_texture(&texture)
                .corner_radius(self.corner_radius)
                .paint_at(ui, rect);
            return response;
        }

        let promise = ui.use_state(
            PromiseSlot::<Result<eframe::egui::TextureHandle, String>>::new,
            (),
        );

        if promise.is_idle() {
            let ctx = ui.ctx().clone();
            let id = ui.id();
            let filename = self.filename.to_path_buf();
            let cache_key = cache_key.clone();
            let spawned = Promise::spawn_thread("smooth_image", move || {
                let bytes = std::fs::read(filename).map_err(|e| e.to_string())?;
                let decoded = image::load_from_memory(&bytes).map_err(|e| e.to_string())?;
                let texel_size = target_texel_size(
                    max_texel_box,
                    decoded.dimensions(),
                    self.preserve_aspect_ratio,
                );
                let texture = make_texture(&ctx, decoded, texel_size, id)?;
                IMAGE_CACHE.insert(cache_key, texture.clone());
                ctx.request_repaint();
                Ok(texture)
            });
            promise.start(spawned);
        }

        let texture = match promise.poll() {
            Some(Ok(texture)) => Some(texture),
            Some(Err(err)) => {
                let ui_size = fallback_ui_size(self.max_size, self.preserve_aspect_ratio);
                let (rect, response) = ui.allocate_exact_size(ui_size, self.sense);
                paint_error(ui, rect, &err);
                return response;
            }
            None => None,
        };

        let ui_size = texture
            .as_ref()
            .map(|t| texture_size_points(pixels_per_point, t.size()))
            .unwrap_or_else(|| fallback_ui_size(self.max_size, self.preserve_aspect_ratio));
        let (rect, response) = ui.allocate_exact_size(ui_size, self.sense);

        if let Some(texture) = texture {
            eframe::egui::Image::from_texture(&texture)
                .corner_radius(self.corner_radius)
                .texture_options(eframe::egui::TextureOptions::NEAREST)
                .paint_at(ui, rect);
        } else {
            ui.ctx().request_repaint();
            paint_loading(ui, rect, self.corner_radius);
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
) -> eframe::egui::Vec2 {
    if preserve_aspect_ratio {
        scale_to_fit(eframe::egui::Vec2::splat(24.0), max_size)
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
    let resized = decoded.resize_exact(
        texel_size[0],
        texel_size[1],
        image::imageops::FilterType::Triangle,
    );
    let rgba = resized.to_rgba8();

    let mut pixels = Vec::with_capacity(texel_size[0] as usize * texel_size[1] as usize);
    for p in rgba.pixels() {
        pixels.push(eframe::egui::Color32::from_rgba_unmultiplied(
            p[0], p[1], p[2], p[3],
        ));
    }

    let color_image =
        eframe::egui::ColorImage::new([texel_size[0] as usize, texel_size[1] as usize], pixels);

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
) {
    ui.painter()
        .rect_filled(rect, corner_radius, eframe::egui::Color32::LIGHT_GRAY);
    eframe::egui::Spinner::new().paint_at(ui, rect);
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
