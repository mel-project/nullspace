use egui::ThemePreference as EguiThemePreference;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvoRowStyle {
    Text,
    Friendly,
}

impl ConvoRowStyle {
    pub fn label(self) -> &'static str {
        match self {
            Self::Text => "Text",
            Self::Friendly => "Friendly",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppTheme {
    Light,
    Dark,
    #[default]
    Auto,
}

impl AppTheme {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto",
            Self::Light => "Light",
            Self::Dark => "Dark",
        }
    }

    pub fn to_egui(self) -> EguiThemePreference {
        match self {
            Self::Auto => EguiThemePreference::System,
            Self::Light => EguiThemePreference::Light,
            Self::Dark => EguiThemePreference::Dark,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefData {
    pub theme: AppTheme,
    pub zoom_percent: u16,
    pub max_auto_image_download_bytes: Option<u64>,
    pub convo_row_style: ConvoRowStyle,
}

impl Default for PrefData {
    fn default() -> Self {
        Self {
            theme: AppTheme::Auto,
            zoom_percent: 100,
            max_auto_image_download_bytes: Some(1_000_000),
            convo_row_style: ConvoRowStyle::Friendly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AppTheme, PrefData};

    #[test]
    fn prefs_default_to_auto_theme() {
        assert_eq!(PrefData::default().theme, AppTheme::Auto);
    }

    #[test]
    fn missing_theme_deserializes_as_auto() {
        let prefs: PrefData =
            serde_json::from_str(r#"{"zoom_percent":125,"convo_row_style":"text"}"#).unwrap();
        assert_eq!(prefs.theme, AppTheme::Auto);
    }

    #[test]
    fn theme_serializes_as_snake_case() {
        assert_eq!(serde_json::to_string(&AppTheme::Auto).unwrap(), "\"auto\"");
        assert_eq!(
            serde_json::to_string(&AppTheme::Light).unwrap(),
            "\"light\""
        );
        assert_eq!(serde_json::to_string(&AppTheme::Dark).unwrap(), "\"dark\"");
    }

    #[test]
    fn theme_maps_to_egui_preference() {
        assert_eq!(AppTheme::Auto.to_egui(), egui::ThemePreference::System);
        assert_eq!(AppTheme::Light.to_egui(), egui::ThemePreference::Light);
        assert_eq!(AppTheme::Dark.to_egui(), egui::ThemePreference::Dark);
    }
}
