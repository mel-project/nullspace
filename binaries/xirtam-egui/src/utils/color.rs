use egui::Color32;
use xirtam_crypt::hash::Hash;
use xirtam_structs::handle::Handle;

pub fn handle_color(handle: &Handle) -> Color32 {
    let hash = Hash::digest(handle.as_str().as_bytes());
    let bytes = hash.to_bytes();
    let hue = (u16::from_le_bytes([bytes[0], bytes[1]]) % 360) as f32 / 360.0;
    let hsva = egui::ecolor::Hsva::new(hue, 0.65, 0.55, 1.0);
    let [r, g, b] = hsva.to_srgb();
    Color32::from_rgb(r, g, b)
}
