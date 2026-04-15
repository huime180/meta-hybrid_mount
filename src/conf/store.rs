// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    conf::schema::{Config, DefaultMode, HymoFsConfig, ModuleRules, OverlayMode},
    defs,
};

#[derive(Debug, Serialize, Deserialize)]
struct MainConfigFile {
    moduledir: PathBuf,
    mountsource: String,
    partitions: Vec<String>,
    overlay_mode: OverlayMode,
    disable_umount: bool,
    allow_umount_coexistence: bool,
    enable_overlay_fallback: bool,
    default_mode: DefaultMode,
    rules: HashMap<String, ModuleRules>,
}

impl From<&Config> for MainConfigFile {
    fn from(value: &Config) -> Self {
        Self {
            moduledir: value.moduledir.clone(),
            mountsource: value.mountsource.clone(),
            partitions: value.partitions.clone(),
            overlay_mode: value.overlay_mode.clone(),
            disable_umount: value.disable_umount,
            allow_umount_coexistence: value.allow_umount_coexistence,
            enable_overlay_fallback: value.enable_overlay_fallback,
            default_mode: value.default_mode.clone(),
            rules: value.rules.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct LegacyWrappedHymofsConfig {
    #[serde(default)]
    hymofs: HymoFsConfig,
}

fn hymofs_sidecar_path_for(main_path: &Path) -> PathBuf {
    main_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("hymofs.toml")
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create config directory")?;
    }
    Ok(())
}

fn load_hymofs_config_file(path: &Path) -> Result<HymoFsConfig> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read HymoFS config file {}", path.display()))?;

    if content.trim().is_empty() {
        return Ok(HymoFsConfig::default());
    }

    toml::from_str::<HymoFsConfig>(&content)
        .or_else(|_| {
            toml::from_str::<LegacyWrappedHymofsConfig>(&content).map(|wrapped| wrapped.hymofs)
        })
        .with_context(|| format!("failed to parse HymoFS config file {}", path.display()))
}

fn save_hymofs_config_file(path: &Path, config: &HymoFsConfig) -> Result<()> {
    let content = toml::to_string_pretty(config).context("failed to serialize HymoFS config")?;
    ensure_parent_dir(path)?;
    fs::write(path, content)
        .with_context(|| format!("failed to write HymoFS config file {}", path.display()))?;
    Ok(())
}

fn load_split_config(
    main_path: &Path,
    hymofs_path: &Path,
    allow_missing_main: bool,
) -> Result<Config> {
    let mut config = if main_path.exists() {
        let content = fs::read_to_string(main_path)
            .with_context(|| format!("failed to read config file {}", main_path.display()))?;
        toml::from_str::<Config>(&content)
            .with_context(|| format!("failed to parse config file {}", main_path.display()))?
    } else if allow_missing_main {
        Config::default()
    } else {
        let _ = fs::read_to_string(main_path)
            .with_context(|| format!("failed to read config file {}", main_path.display()))?;
        unreachable!("read_to_string should have returned an error for missing config file");
    };

    if hymofs_path.exists() {
        config.hymofs = HymoFsConfig::from_file(hymofs_path)?;
    }

    Ok(config)
}

impl Config {
    pub fn load_optional_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let main_path = path.as_ref();
        let hymofs_path = hymofs_sidecar_path_for(main_path);
        load_split_config(main_path, &hymofs_path, true)
    }

    pub fn load_default() -> Result<Self> {
        load_split_config(
            Path::new(defs::CONFIG_FILE),
            Path::new(defs::HYMOFS_CONFIG_FILE),
            true,
        )
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let main_path = path.as_ref();
        let hymofs_path = hymofs_sidecar_path_for(main_path);
        let content = toml::to_string_pretty(&MainConfigFile::from(self))
            .context("failed to serialize main config")?;

        ensure_parent_dir(main_path)?;
        fs::write(main_path, content)
            .with_context(|| format!("failed to write config file {}", main_path.display()))?;
        save_hymofs_config_file(&hymofs_path, &self.hymofs)?;
        Ok(())
    }
}

impl HymoFsConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        load_hymofs_config_file(path.as_ref())
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        save_hymofs_config_file(path.as_ref(), self)?;
        Ok(())
    }
}

pub fn hymofs_config_path_for<P: AsRef<Path>>(main_path: P) -> PathBuf {
    hymofs_sidecar_path_for(main_path.as_ref())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{Config, HymoFsConfig, hymofs_config_path_for, load_split_config};

    #[test]
    fn save_to_file_splits_hymofs_into_sidecar() {
        let dir = tempdir().expect("failed to create temp dir");
        let main_path = dir.path().join("config.toml");
        let hymofs_path = hymofs_config_path_for(&main_path);

        let mut config = Config::default();
        config.hymofs.enabled = false;
        config.hymofs.uname_release = "6.1.0-hymo".to_string();

        config
            .save_to_file(&main_path)
            .expect("failed to save split config");

        let main_content = fs::read_to_string(&main_path).expect("failed to read main config");
        let hymofs_content =
            fs::read_to_string(&hymofs_path).expect("failed to read hymofs sidecar");

        assert!(!main_content.contains("[hymofs]"));
        assert!(!main_content.contains("uname_release"));
        assert!(hymofs_content.contains("uname_release = \"6.1.0-hymo\""));
        assert!(hymofs_content.contains("enabled = false"));
    }

    #[test]
    fn load_split_config_uses_sidecar_when_main_is_missing() {
        let dir = tempdir().expect("failed to create temp dir");
        let main_path = dir.path().join("config.toml");
        let hymofs_path = dir.path().join("hymofs.toml");

        HymoFsConfig {
            enabled: false,
            uname_version: "#1 sidecar".to_string(),
            ..HymoFsConfig::default()
        }
        .save_to_file(&hymofs_path)
        .expect("failed to save hymofs sidecar");

        let config = load_split_config(&main_path, &hymofs_path, true)
            .expect("failed to load split config with missing main");

        assert!(!config.hymofs.enabled);
        assert_eq!(config.hymofs.uname_version, "#1 sidecar");
    }

    #[test]
    fn load_split_config_prefers_sidecar_over_legacy_inline_hymofs() {
        let dir = tempdir().expect("failed to create temp dir");
        let main_path = dir.path().join("config.toml");
        let hymofs_path = dir.path().join("hymofs.toml");

        fs::write(
            &main_path,
            "moduledir = \"/data/adb/modules\"\n[hymofs]\nenabled = false\nuname_release = \"legacy\"\n",
        )
        .expect("failed to write main config");
        fs::write(
            &hymofs_path,
            "enabled = true\nuname_release = \"sidecar\"\n",
        )
        .expect("failed to write sidecar");

        let config = load_split_config(&main_path, &hymofs_path, false)
            .expect("failed to load merged config");

        assert!(config.hymofs.enabled);
        assert_eq!(config.hymofs.uname_release, "sidecar");
    }
}
