//! The app's own preferences, in `gui.json` next to the profiles.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// `None`: the core's default (`Downloads/lemonwire`).
    pub download_dir: Option<PathBuf>,
    pub upload_kib: Option<u32>,
    pub download_kib: Option<u32>,
    pub port: u16,
    pub upnp: bool,
    pub theme: Theme,
    /// The profile shown last time.
    pub profile: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        let engine = lemonwire_client_core::EngineSettings::default();
        Self {
            download_dir: None,
            upload_kib: None,
            download_kib: None,
            port: engine.port,
            upnp: engine.upnp,
            theme: Theme::System,
            profile: None,
        }
    }
}

impl Settings {
    fn path(config_root: &Path) -> PathBuf {
        config_root.join("gui.json")
    }

    pub fn load(config_root: &Path) -> Self {
        std::fs::read(Self::path(config_root))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, config_root: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(config_root)?;
        let json = serde_json::to_vec_pretty(self).expect("settings serialise");
        let path = Self::path(config_root);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let dir = std::env::temp_dir().join(format!("lw-gui-settings-{}", std::process::id()));
        assert_eq!(Settings::load(&dir), Settings::default());
        let s = Settings {
            upload_kib: Some(500),
            theme: Theme::Dark,
            ..Settings::default()
        };
        s.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir), s);
        // Unknown or missing fields don't lose the rest.
        std::fs::write(dir.join("gui.json"), r#"{"port": 7000, "later": true}"#).unwrap();
        assert_eq!(Settings::load(&dir).port, 7000);
        assert!(Settings::load(&dir).upnp);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
