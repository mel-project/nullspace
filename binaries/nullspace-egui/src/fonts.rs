use std::{collections::HashMap, sync::Arc};

use egui::{FontData, FontDefinitions, FontFamily};
use font_kit::{
    family_name::FamilyName, handle::Handle, properties::Properties, source::SystemSource,
};

/// Attempt to load a system font by any of the given `family_names`, returning the first match.
fn load_font_family(family_names: &[&str]) -> Option<Vec<u8>> {
    let system_source = SystemSource::new();

    for &name in family_names {
        match system_source
            .select_best_match(&[FamilyName::Title(name.to_string())], &Properties::new())
        {
            Ok(h) => match &h {
                Handle::Memory { bytes, .. } => {
                    tracing::debug!("Loaded {name} from memory.");
                    return Some(bytes.to_vec());
                }
                Handle::Path { path, .. } => {
                    tracing::info!("Loaded {name} from path: {:?}", path);
                    if let Ok(data) = std::fs::read(path) {
                        return Some(data);
                    }
                }
            },
            Err(e) => tracing::error!("Could not load {}: {:?}", name, e),
        }
    }

    None
}

pub fn load_fonts(mut fonts: FontDefinitions) -> FontDefinitions {
    fonts.font_data.insert(
        "main".to_string(),
        egui::FontData::from_static(include_bytes!("fonts/FantasqueSansMNerdFont-Regular.ttf"))
            .into(),
    );
    fonts.font_data.insert(
        "main_bold".to_string(),
        egui::FontData::from_static(include_bytes!("fonts/FantasqueSansMNerdFont-Bold.ttf")).into(),
    );
    fonts.font_data.insert(
        "main_italic".to_string(),
        egui::FontData::from_static(include_bytes!("fonts/FantasqueSansMNerdFont-Italic.ttf"))
            .into(),
    );
    fonts.font_data.insert(
        "main_bold_italic".to_string(),
        egui::FontData::from_static(include_bytes!(
            "fonts/FantasqueSansMNerdFont-BoldItalic.ttf"
        ))
        .into(),
    );
    fonts.families.insert(
        egui::FontFamily::Name("main".into()),
        vec!["main".to_string()],
    );
    fonts.families.insert(
        egui::FontFamily::Name("main_bold".into()),
        vec!["main_bold".to_string()],
    );
    fonts.families.insert(
        egui::FontFamily::Name("main_italic".into()),
        vec!["main_italic".to_string()],
    );
    fonts.families.insert(
        egui::FontFamily::Name("main_bold_italic".into()),
        vec!["main_bold_italic".to_string()],
    );

    // we keep the existing font as a fallback
    let mut existing_fonts = fonts
        .families
        .get(&egui::FontFamily::Proportional)
        .unwrap()
        .clone();
    existing_fonts.insert(0, "main".into());
    fonts
        .families
        .insert(egui::FontFamily::Proportional, existing_fonts);

    fonts
        .families
        .insert(egui::FontFamily::Monospace, vec!["main".to_string()]);

    let mut fontdb = HashMap::new();
    fontdb.insert(
        "simplified_chinese",
        vec!["Noto Sans CJK SC", "Noto Sans SC", "Source Han Sans CN"],
    );
    for (region, font_names) in fontdb {
        if let Some(font_data) = load_font_family(&font_names) {
            tracing::info!("Inserting font {region}");
            fonts
                .font_data
                .insert(region.to_owned(), Arc::new(FontData::from_owned(font_data)));

            fonts
                .families
                .get_mut(&FontFamily::Proportional)
                .unwrap()
                .push(region.to_owned());
        }
    }

    fonts
}
