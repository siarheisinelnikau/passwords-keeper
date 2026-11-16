use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    #[default]
    En,
    Ru,
    Fr,
    De,
    Es,
    It,
}
impl Language {
    pub const ALL: [Self; 6] = [Self::En, Self::Ru, Self::Fr, Self::De, Self::Es, Self::It];
    pub fn index(self) -> usize {
        match self {
            Self::En => 0,
            Self::Ru => 1,
            Self::Fr => 2,
            Self::De => 3,
            Self::Es => 4,
            Self::It => 5,
        }
    }
    pub fn name(self) -> &'static str {
        [
            "English",
            "Русский",
            "Français",
            "Deutsch",
            "Español",
            "Italiano",
        ][self.index()]
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub dark: bool,
    pub language: Language,
    pub reduced_motion: bool,
    pub startup_updates: bool,
    pub idle_minutes: u32,
    pub clipboard_seconds: u32,
    pub recent: Vec<PathBuf>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            dark: true,
            language: Language::En,
            reduced_motion: false,
            startup_updates: true,
            idle_minutes: 5,
            clipboard_seconds: 30,
            recent: Vec::new(),
        }
    }
}
impl Settings {
    pub fn path() -> PathBuf {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("PasswordsKeeper")
            .join("settings.json")
    }
    pub fn load(path: &Path) -> Self {
        let read = || -> std::io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            fs::File::open(path)?
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            Ok(bytes)
        };
        let mut prefs = read()
            .ok()
            .filter(|v| v.len() < 64 * 1024)
            .and_then(|v| serde_json::from_slice::<Self>(&v).ok())
            .unwrap_or_default();
        prefs.idle_minutes = prefs.idle_minutes.clamp(1, 60);
        prefs.clipboard_seconds = prefs.clipboard_seconds.clamp(5, 120);
        prefs.recent.truncate(8);
        prefs
    }
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("Missing preferences directory"))?;
        fs::create_dir_all(parent)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|e| e.error)?;
        Ok(())
    }
    pub fn remember(&mut self, path: PathBuf) {
        self.recent.retain(|p| p != &path);
        self.recent.insert(0, path);
        self.recent.truncate(8);
    }
}
