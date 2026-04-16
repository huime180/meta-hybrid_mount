// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::{
    conf::schema::{Config, HymoFsConfig},
    defs,
};

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

    let value: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse HymoFS config file {}", path.display()))?;

    if value.get("hymofs").is_some() {
        toml::from_str::<LegacyWrappedHymofsConfig>(&content)
            .map(|wrapped| wrapped.hymofs)
            .with_context(|| format!("failed to parse wrapped HymoFS config {}", path.display()))
    } else {
        toml::from_str::<HymoFsConfig>(&content)
            .with_context(|| format!("failed to parse HymoFS config file {}", path.display()))
    }
}

fn load_merged_config(main_path: &Path, allow_missing_main: bool) -> Result<Config> {
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

    let hymofs_path = hymofs_sidecar_path_for(main_path);
    if hymofs_path.exists() {
        config.hymofs = HymoFsConfig::from_file(&hymofs_path)?;
    }

    Ok(config)
}

fn remove_legacy_sidecar_if_present(main_path: &Path) -> Result<()> {
    let hymofs_path = hymofs_sidecar_path_for(main_path);
    match fs::remove_file(&hymofs_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| {
            format!(
                "failed to remove legacy HymoFS config {}",
                hymofs_path.display()
            )
        }),
    }
}

impl Config {
    pub fn load_optional_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        load_merged_config(path.as_ref(), true)
    }

    pub fn load_default() -> Result<Self> {
        load_merged_config(Path::new(defs::CONFIG_FILE), true)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let main_path = path.as_ref();
        let content = toml::to_string_pretty(self).context("failed to serialize config")?;

        ensure_parent_dir(main_path)?;
        fs::write(main_path, content)
            .with_context(|| format!("failed to write config file {}", main_path.display()))?;
        remove_legacy_sidecar_if_present(main_path)?;
        Ok(())
    }
}

impl HymoFsConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        load_hymofs_config_file(path.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{Config, HymoFsConfig, load_merged_config};

    #[test]
    fn save_to_file_writes_hymofs_inline_and_removes_sidecar() {
        let dir = tempdir().expect("failed to create temp dir");
        let main_path = dir.path().join("config.toml");
        let hymofs_path = dir.path().join("hymofs.toml");

        fs::write(&hymofs_path, "enabled = true\n").expect("failed to seed old hymofs sidecar");

        let mut config = Config::default();
        config.hymofs.enabled = false;
        config.hymofs.uname_release = "6.1.0-hymo".to_string();

        config
            .save_to_file(&main_path)
            .expect("failed to save merged config");

        let main_content = fs::read_to_string(&main_path).expect("failed to read main config");

        assert!(main_content.contains("[hymofs]"));
        assert!(main_content.contains("uname_release = \"6.1.0-hymo\""));
        assert!(main_content.contains("enabled = false"));
        assert!(!hymofs_path.exists());
    }

    #[test]
    fn load_merged_config_uses_sidecar_when_main_is_missing() {
        let dir = tempdir().expect("failed to create temp dir");
        let main_path = dir.path().join("config.toml");
        let hymofs_path = dir.path().join("hymofs.toml");

        fs::write(
            &hymofs_path,
            "enabled = false\nuname_version = \"#1 sidecar\"\n",
        )
        .expect("failed to write hymofs sidecar");

        let config = load_merged_config(&main_path, true)
            .expect("failed to load merged config with missing main");

        assert!(!config.hymofs.enabled);
        assert_eq!(config.hymofs.uname_version, "#1 sidecar");
    }

    #[test]
    fn load_merged_config_prefers_sidecar_over_inline_hymofs() {
        let dir = tempdir().expect("failed to create temp dir");
        let main_path = dir.path().join("config.toml");
        let hymofs_path = dir.path().join("hymofs.toml");

        fs::write(
            &main_path,
            "moduledir = \"/data/adb/modules\"\n[hymofs]\nenabled = false\nuname_release = \"inline\"\n",
        )
        .expect("failed to write main config");
        fs::write(
            &hymofs_path,
            "enabled = true\nuname_release = \"sidecar\"\n",
        )
        .expect("failed to write sidecar");

        let config = load_merged_config(&main_path, false).expect("failed to load merged config");

        assert!(config.hymofs.enabled);
        assert_eq!(config.hymofs.uname_release, "sidecar");
    }

    #[test]
    fn hymofs_config_can_still_parse_wrapped_legacy_file() {
        let dir = tempdir().expect("failed to create temp dir");
        let hymofs_path = dir.path().join("hymofs.toml");

        fs::write(&hymofs_path, "[hymofs]\nenabled = true\n")
            .expect("failed to write wrapped hymofs config");

        let config =
            HymoFsConfig::from_file(&hymofs_path).expect("failed to parse wrapped hymofs config");

        assert!(config.enabled);
    }
}
