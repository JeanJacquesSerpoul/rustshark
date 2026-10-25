//! Persistance des réglages et des profils d'analyse (JSON, sans secrets).

use std::path::{Path, PathBuf};

use rustshark_shared::{AnalysisProfile, AppSettings};
use serde::de::DeserializeOwned;
use serde::Serialize;

fn load<T: DeserializeOwned + Default>(path: &Path) -> T {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    // Écriture atomique : fichier temporaire puis renommage.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

pub struct Config {
    dir: PathBuf,
}

impl Config {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn settings_path(&self) -> PathBuf {
        self.dir.join("settings.json")
    }

    fn profiles_path(&self) -> PathBuf {
        self.dir.join("profiles.json")
    }

    pub fn load_settings(&self) -> AppSettings {
        load(&self.settings_path())
    }

    pub fn save_settings(&self, s: &AppSettings) -> Result<(), String> {
        save(&self.settings_path(), s)
    }

    pub fn load_profiles(&self) -> Vec<AnalysisProfile> {
        load(&self.profiles_path())
    }

    pub fn save_profiles(&self, p: &[AnalysisProfile]) -> Result<(), String> {
        save(&self.profiles_path(), &p)
    }
}
