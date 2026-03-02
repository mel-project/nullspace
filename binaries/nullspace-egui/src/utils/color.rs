#![allow(dead_code)]

use egui::Color32;
use nullspace_crypt::hash::Hash;
use nullspace_structs::username::UserName;

pub fn username_color(username: &UserName) -> Color32 {
    let hash = Hash::digest(username.as_str().as_bytes());
    let bytes = hash.to_bytes();
    let hue = (u16::from_le_bytes([bytes[0], bytes[1]]) % 360) as f32 / 360.0;
    let hsva = egui::ecolor::Hsva::new(hue, 0.65, 0.55, 1.0);
    let [r, g, b] = hsva.to_srgb();
    Color32::from_rgb(r, g, b)
}

#[derive(Clone, Copy)]
struct HslStop {
    shade: u16,
    hue_deg: f32,
    saturation: f32,
    lightness: f32,
}

const PRIMARY_STOPS: [HslStop; 3] = [
    HslStop {
        shade: 100,
        hue_deg: 212.0,
        saturation: 0.84,
        lightness: 0.88,
    },
    HslStop {
        shade: 500,
        hue_deg: 221.0,
        saturation: 0.83,
        lightness: 0.57,
    },
    HslStop {
        shade: 900,
        hue_deg: 228.0,
        saturation: 0.69,
        lightness: 0.17,
    },
];

const SUCCESS_STOPS: [HslStop; 3] = [
    HslStop {
        shade: 100,
        hue_deg: 142.0,
        saturation: 0.63,
        lightness: 0.88,
    },
    HslStop {
        shade: 500,
        hue_deg: 146.0,
        saturation: 0.65,
        lightness: 0.43,
    },
    HslStop {
        shade: 900,
        hue_deg: 152.0,
        saturation: 0.67,
        lightness: 0.14,
    },
];

const WARNING_STOPS: [HslStop; 3] = [
    HslStop {
        shade: 100,
        hue_deg: 44.0,
        saturation: 0.98,
        lightness: 0.85,
    },
    HslStop {
        shade: 500,
        hue_deg: 39.0,
        saturation: 0.92,
        lightness: 0.50,
    },
    HslStop {
        shade: 900,
        hue_deg: 27.0,
        saturation: 0.80,
        lightness: 0.16,
    },
];

const DANGER_STOPS: [HslStop; 3] = [
    HslStop {
        shade: 100,
        hue_deg: 349.0,
        saturation: 0.88,
        lightness: 0.88,
    },
    HslStop {
        shade: 500,
        hue_deg: 356.0,
        saturation: 0.83,
        lightness: 0.56,
    },
    HslStop {
        shade: 900,
        hue_deg: 4.0,
        saturation: 0.77,
        lightness: 0.18,
    },
];

const NEUTRAL_STOPS: [HslStop; 3] = [
    HslStop {
        shade: 100,
        hue_deg: 220.0,
        saturation: 0.14,
        lightness: 0.91,
    },
    HslStop {
        shade: 500,
        hue_deg: 220.0,
        saturation: 0.09,
        lightness: 0.55,
    },
    HslStop {
        shade: 900,
        hue_deg: 220.0,
        saturation: 0.10,
        lightness: 0.18,
    },
];

pub fn primary(shade: u16) -> Color32 {
    color_from_stops(shade, &PRIMARY_STOPS)
}

pub fn success(shade: u16) -> Color32 {
    color_from_stops(shade, &SUCCESS_STOPS)
}

pub fn warning(shade: u16) -> Color32 {
    color_from_stops(shade, &WARNING_STOPS)
}

pub fn danger(shade: u16) -> Color32 {
    color_from_stops(shade, &DANGER_STOPS)
}

pub fn neutral(shade: u16) -> Color32 {
    color_from_stops(shade, &NEUTRAL_STOPS)
}

fn color_from_stops(shade: u16, stops: &[HslStop]) -> Color32 {
    let hsl = interpolate_hsl(shade, stops);
    hsl_to_color32(hsl.hue_deg, hsl.saturation, hsl.lightness)
}

fn interpolate_hsl(shade: u16, stops: &[HslStop]) -> HslStop {
    if shade <= stops[0].shade {
        return stops[0];
    }
    if shade >= stops[stops.len() - 1].shade {
        return stops[stops.len() - 1];
    }

    for i in 0..stops.len() - 1 {
        let a = stops[i];
        let b = stops[i + 1];
        if shade <= b.shade {
            let t = (shade - a.shade) as f32 / (b.shade - a.shade) as f32;
            return HslStop {
                shade,
                hue_deg: lerp_hue_deg(a.hue_deg, b.hue_deg, t),
                saturation: lerp(a.saturation, b.saturation, t),
                lightness: lerp(a.lightness, b.lightness, t),
            };
        }
    }

    stops[stops.len() - 1]
}

fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

fn lerp_hue_deg(a: f32, b: f32, t: f32) -> f32 {
    let delta = (b - a + 540.0).rem_euclid(360.0) - 180.0;
    (a + delta * t).rem_euclid(360.0)
}

fn hsl_to_color32(hue_deg: f32, saturation: f32, lightness: f32) -> Color32 {
    let h = hue_deg.rem_euclid(360.0) / 360.0;
    let s_hsl = saturation.clamp(0.0, 1.0);
    let l = lightness.clamp(0.0, 1.0);

    // Convert HSL to HSV so we can use egui's built-in HSVA -> sRGB path.
    let v = l + s_hsl * l.min(1.0 - l);
    let s_hsv = if v <= f32::EPSILON {
        0.0
    } else {
        2.0 * (1.0 - l / v)
    };
    let hsva = egui::ecolor::Hsva::new(h, s_hsv.clamp(0.0, 1.0), v.clamp(0.0, 1.0), 1.0);
    let [r, g, b] = hsva.to_srgb();
    Color32::from_rgb(r, g, b)
}
