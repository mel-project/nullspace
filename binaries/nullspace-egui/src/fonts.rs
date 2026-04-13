use std::{borrow::Cow, sync::Arc};

use egui::{FontData, FontDefinitions, FontFamily};
use font_kit::{
    family_name::FamilyName,
    handle::Handle,
    properties::{Properties, Style as FontStyle, Weight},
    source::SystemSource,
};

const REGULAR_FONT_NAME: &str = "ns_sans_regular";
const BOLD_FONT_NAME: &str = "ns_sans_bold";
const ITALIC_FONT_NAME: &str = "ns_sans_italic";
const BOLD_ITALIC_FONT_NAME: &str = "ns_sans_bold_italic";

const NOTO_SANS_SCALE: f32 = 1.0;
const SYSTEM_FONT_SCALE: f32 = 1.0;

const SYSTEM_SANS_REGULAR_FONT_NAME: &str = "ns_system_sans_regular";
const SYSTEM_SANS_BOLD_FONT_NAME: &str = "ns_system_sans_bold";
const SYSTEM_SANS_ITALIC_FONT_NAME: &str = "ns_system_sans_italic";
const SYSTEM_SANS_BOLD_ITALIC_FONT_NAME: &str = "ns_system_sans_bold_italic";

const SYSTEM_CJK_REGULAR_FONT_NAME: &str = "ns_system_cjk_regular";
const SYSTEM_CJK_BOLD_FONT_NAME: &str = "ns_system_cjk_bold";
const SYSTEM_CJK_ITALIC_FONT_NAME: &str = "ns_system_cjk_italic";
const SYSTEM_CJK_BOLD_ITALIC_FONT_NAME: &str = "ns_system_cjk_bold_italic";

#[cfg(target_os = "linux")]
const SANS_FAMILY_CANDIDATES: &[&str] = &[
    "Noto Sans",
    "Cantarell",
    "DejaVu Sans",
    "Liberation Sans",
    "Ubuntu",
];
#[cfg(target_os = "linux")]
const CJK_FAMILY_CANDIDATES: &[&str] = &["Noto Sans CJK SC", "Noto Sans SC", "Source Han Sans CN"];

#[cfg(target_os = "macos")]
const SANS_FAMILY_CANDIDATES: &[&str] = &["Helvetica Neue", "Helvetica", "Arial"];
#[cfg(target_os = "macos")]
const CJK_FAMILY_CANDIDATES: &[&str] = &["PingFang SC", "Hiragino Sans GB", "Arial Unicode MS"];

#[cfg(target_os = "windows")]
const SANS_FAMILY_CANDIDATES: &[&str] = &["Segoe UI", "Arial", "Tahoma"];
#[cfg(target_os = "windows")]
const CJK_FAMILY_CANDIDATES: &[&str] = &["Microsoft YaHei UI", "Microsoft YaHei", "SimSun"];

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const SANS_FAMILY_CANDIDATES: &[&str] = &["Noto Sans", "DejaVu Sans", "Liberation Sans", "Arial"];
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const CJK_FAMILY_CANDIDATES: &[&str] = &["Noto Sans CJK SC", "Noto Sans SC", "Source Han Sans CN"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FontVariant {
    Regular,
    Bold,
    Italic,
    BoldItalic,
}

impl FontVariant {
    pub fn family(self) -> FontFamily {
        FontFamily::Name(font_name(self).into())
    }
}

pub fn load_fonts(mut fonts: FontDefinitions) -> FontDefinitions {
    let default_proportional = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();

    insert_embedded_font(
        &mut fonts,
        REGULAR_FONT_NAME,
        include_bytes!("fonts/NotoSansNerdFontPropo-Regular.ttf"),
    );
    insert_embedded_font(
        &mut fonts,
        BOLD_FONT_NAME,
        include_bytes!("fonts/NotoSansNerdFontPropo-Bold.ttf"),
    );
    insert_embedded_font(
        &mut fonts,
        ITALIC_FONT_NAME,
        include_bytes!("fonts/NotoSansNerdFontPropo-Italic.ttf"),
    );
    insert_embedded_font(
        &mut fonts,
        BOLD_ITALIC_FONT_NAME,
        include_bytes!("fonts/NotoSansNerdFontPropo-BoldItalic.ttf"),
    );

    insert_system_variant(
        &mut fonts,
        SYSTEM_SANS_REGULAR_FONT_NAME,
        SANS_FAMILY_CANDIDATES,
        FontVariant::Regular,
    );
    insert_system_variant(
        &mut fonts,
        SYSTEM_SANS_BOLD_FONT_NAME,
        SANS_FAMILY_CANDIDATES,
        FontVariant::Bold,
    );
    insert_system_variant(
        &mut fonts,
        SYSTEM_SANS_ITALIC_FONT_NAME,
        SANS_FAMILY_CANDIDATES,
        FontVariant::Italic,
    );
    insert_system_variant(
        &mut fonts,
        SYSTEM_SANS_BOLD_ITALIC_FONT_NAME,
        SANS_FAMILY_CANDIDATES,
        FontVariant::BoldItalic,
    );

    insert_system_variant(
        &mut fonts,
        SYSTEM_CJK_REGULAR_FONT_NAME,
        CJK_FAMILY_CANDIDATES,
        FontVariant::Regular,
    );
    insert_system_variant(
        &mut fonts,
        SYSTEM_CJK_BOLD_FONT_NAME,
        CJK_FAMILY_CANDIDATES,
        FontVariant::Bold,
    );
    insert_system_variant(
        &mut fonts,
        SYSTEM_CJK_ITALIC_FONT_NAME,
        CJK_FAMILY_CANDIDATES,
        FontVariant::Italic,
    );
    insert_system_variant(
        &mut fonts,
        SYSTEM_CJK_BOLD_ITALIC_FONT_NAME,
        CJK_FAMILY_CANDIDATES,
        FontVariant::BoldItalic,
    );

    fonts.families.insert(
        FontVariant::Regular.family(),
        family_stack(&fonts, &default_proportional, FontVariant::Regular),
    );
    fonts.families.insert(
        FontVariant::Bold.family(),
        family_stack(&fonts, &default_proportional, FontVariant::Bold),
    );
    fonts.families.insert(
        FontVariant::Italic.family(),
        family_stack(&fonts, &default_proportional, FontVariant::Italic),
    );
    fonts.families.insert(
        FontVariant::BoldItalic.family(),
        family_stack(&fonts, &default_proportional, FontVariant::BoldItalic),
    );

    fonts.families.insert(
        FontFamily::Proportional,
        family_stack(&fonts, &default_proportional, FontVariant::Regular),
    );

    fonts
}

fn font_name(variant: FontVariant) -> &'static str {
    match variant {
        FontVariant::Regular => REGULAR_FONT_NAME,
        FontVariant::Bold => BOLD_FONT_NAME,
        FontVariant::Italic => ITALIC_FONT_NAME,
        FontVariant::BoldItalic => BOLD_ITALIC_FONT_NAME,
    }
}

fn system_sans_font_name(variant: FontVariant) -> &'static str {
    match variant {
        FontVariant::Regular => SYSTEM_SANS_REGULAR_FONT_NAME,
        FontVariant::Bold => SYSTEM_SANS_BOLD_FONT_NAME,
        FontVariant::Italic => SYSTEM_SANS_ITALIC_FONT_NAME,
        FontVariant::BoldItalic => SYSTEM_SANS_BOLD_ITALIC_FONT_NAME,
    }
}

fn system_cjk_font_name(variant: FontVariant) -> &'static str {
    match variant {
        FontVariant::Regular => SYSTEM_CJK_REGULAR_FONT_NAME,
        FontVariant::Bold => SYSTEM_CJK_BOLD_FONT_NAME,
        FontVariant::Italic => SYSTEM_CJK_ITALIC_FONT_NAME,
        FontVariant::BoldItalic => SYSTEM_CJK_BOLD_ITALIC_FONT_NAME,
    }
}

fn family_stack(
    fonts: &FontDefinitions,
    default_proportional: &[String],
    variant: FontVariant,
) -> Vec<String> {
    let mut stack = Vec::new();
    push_if_present(&mut stack, fonts, font_name(variant));
    push_if_present(&mut stack, fonts, system_sans_font_name(variant));
    push_if_present(&mut stack, fonts, system_cjk_font_name(variant));

    for font_name in default_proportional {
        push_if_present(&mut stack, fonts, font_name);
    }

    stack
}

fn push_if_present(stack: &mut Vec<String>, fonts: &FontDefinitions, font_name: &str) {
    if fonts.font_data.contains_key(font_name) && !stack.iter().any(|item| item == font_name) {
        stack.push(font_name.to_owned());
    }
}

fn insert_embedded_font(fonts: &mut FontDefinitions, font_name: &str, bytes: &'static [u8]) {
    fonts.font_data.insert(
        font_name.to_owned(),
        Arc::new(FontData::from_static(bytes).tweak(egui::FontTweak {
            scale: NOTO_SANS_SCALE,
            ..Default::default()
        })),
    );
}

fn insert_system_variant(
    fonts: &mut FontDefinitions,
    font_name: &str,
    family_names: &[&str],
    variant: FontVariant,
) {
    if let Some(font_data) = load_system_font_variant(family_names, variant) {
        fonts
            .font_data
            .insert(font_name.to_owned(), Arc::new(font_data));
    }
}

fn load_system_font_variant(family_names: &[&str], variant: FontVariant) -> Option<FontData> {
    let system_source = SystemSource::new();

    for &family_name in family_names {
        for properties in property_preferences(variant) {
            match system_source
                .select_best_match(&[FamilyName::Title(family_name.to_owned())], &properties)
            {
                Ok(handle) => {
                    tracing::debug!(family_name, ?properties, "loaded system font candidate");
                    if let Some(font_data) = font_data_from_handle(handle) {
                        return Some(font_data);
                    }
                }
                Err(error) => {
                    tracing::trace!(
                        family_name,
                        ?properties,
                        ?error,
                        "system font candidate unavailable"
                    );
                }
            }
        }
    }

    None
}

fn property_preferences(variant: FontVariant) -> Vec<Properties> {
    match variant {
        FontVariant::Regular => vec![make_properties(FontStyle::Normal, Weight::NORMAL)],
        FontVariant::Bold => vec![
            make_properties(FontStyle::Normal, Weight::BOLD),
            make_properties(FontStyle::Normal, Weight::SEMIBOLD),
            make_properties(FontStyle::Normal, Weight::NORMAL),
        ],
        FontVariant::Italic => vec![
            make_properties(FontStyle::Italic, Weight::NORMAL),
            make_properties(FontStyle::Oblique, Weight::NORMAL),
            make_properties(FontStyle::Normal, Weight::NORMAL),
        ],
        FontVariant::BoldItalic => vec![
            make_properties(FontStyle::Italic, Weight::BOLD),
            make_properties(FontStyle::Oblique, Weight::BOLD),
            make_properties(FontStyle::Italic, Weight::SEMIBOLD),
            make_properties(FontStyle::Oblique, Weight::SEMIBOLD),
            make_properties(FontStyle::Italic, Weight::NORMAL),
            make_properties(FontStyle::Oblique, Weight::NORMAL),
            make_properties(FontStyle::Normal, Weight::BOLD),
            make_properties(FontStyle::Normal, Weight::NORMAL),
        ],
    }
}

fn make_properties(style: FontStyle, weight: Weight) -> Properties {
    let mut properties = Properties::new();
    properties.style(style).weight(weight);
    properties
}

fn font_data_from_handle(handle: Handle) -> Option<FontData> {
    match handle {
        Handle::Memory { bytes, font_index } => Some(FontData {
            font: Cow::Owned((*bytes).clone()),
            index: font_index,
            tweak: egui::FontTweak {
                scale: SYSTEM_FONT_SCALE,
                ..Default::default()
            },
        }),
        Handle::Path { path, font_index } => match std::fs::read(&path) {
            Ok(bytes) => Some(FontData {
                font: Cow::Owned(bytes),
                index: font_index,
                tweak: egui::FontTweak {
                    scale: SYSTEM_FONT_SCALE,
                    ..Default::default()
                },
            }),
            Err(error) => {
                tracing::debug!(?path, ?error, "failed to read system font");
                None
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_fonts_registers_variant_families() {
        let fonts = load_fonts(FontDefinitions::default());

        for variant in [
            FontVariant::Regular,
            FontVariant::Bold,
            FontVariant::Italic,
            FontVariant::BoldItalic,
        ] {
            let stack = fonts
                .families
                .get(&variant.family())
                .expect("variant family should be registered");
            assert_eq!(stack.first().map(String::as_str), Some(font_name(variant)));
        }

        let proportional = fonts
            .families
            .get(&FontFamily::Proportional)
            .expect("proportional family should exist");
        assert_eq!(
            proportional.first().map(String::as_str),
            Some(REGULAR_FONT_NAME)
        );
    }

    #[test]
    fn load_fonts_preserves_default_monospace_stack() {
        let default_fonts = FontDefinitions::default();
        let default_monospace = default_fonts
            .families
            .get(&FontFamily::Monospace)
            .cloned()
            .expect("default monospace family should exist");

        let fonts = load_fonts(default_fonts);
        let monospace = fonts
            .families
            .get(&FontFamily::Monospace)
            .expect("monospace family should exist");

        assert_eq!(monospace, &default_monospace);
    }

    #[test]
    fn bold_italic_preferences_degrade_in_expected_order() {
        let preferences = property_preferences(FontVariant::BoldItalic);
        let actual: Vec<_> = preferences
            .iter()
            .map(|properties| (properties.style, properties.weight))
            .collect();

        assert_eq!(
            actual,
            vec![
                (FontStyle::Italic, Weight::BOLD),
                (FontStyle::Oblique, Weight::BOLD),
                (FontStyle::Italic, Weight::SEMIBOLD),
                (FontStyle::Oblique, Weight::SEMIBOLD),
                (FontStyle::Italic, Weight::NORMAL),
                (FontStyle::Oblique, Weight::NORMAL),
                (FontStyle::Normal, Weight::BOLD),
                (FontStyle::Normal, Weight::NORMAL),
            ]
        );
    }
}
