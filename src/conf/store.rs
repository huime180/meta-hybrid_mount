// Copyright (C) 2026 YuzakiKokuban <heibanbaize@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    conf::{
        cli::Cli,
        loader,
        schema::{Config, HymoFsConfig, OverlayMode},
    },
    defs,
    domain::{DefaultMode, ModuleRules},
};

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create config directory")?;
    }
    Ok(())
}

fn load_merged_config(main_path: &Path, allow_missing_main: bool) -> Result<Config> {
    Ok(if main_path.exists() {
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
    })
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
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigOverrides {
    pub moduledir: Option<PathBuf>,
    pub mountsource: Option<String>,
    pub partitions: Vec<String>,
}

impl ConfigOverrides {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            moduledir: cli.moduledir.clone(),
            mountsource: cli.mountsource.clone(),
            partitions: cli.partitions.clone(),
        }
    }

    pub fn apply_to(&self, config: &mut Config) {
        config.merge_with_cli(
            self.moduledir.clone(),
            self.mountsource.clone(),
            self.partitions.clone(),
        );
    }
}

#[derive(Debug, Clone)]
pub struct ConfigSession {
    path: PathBuf,
    persisted: Config,
    overrides: ConfigOverrides,
}

impl ConfigSession {
    pub fn load_from_cli(cli: &Cli) -> Result<Self> {
        Ok(Self {
            path: cli
                .config
                .clone()
                .unwrap_or_else(|| PathBuf::from(defs::CONFIG_FILE)),
            persisted: loader::load_config(cli)?,
            overrides: ConfigOverrides::from_cli(cli),
        })
    }

    pub fn persisted_mut(&mut self) -> &mut Config {
        &mut self.persisted
    }

    pub fn effective(&self) -> Config {
        let mut config = self.persisted.clone();
        self.overrides.apply_to(&mut config);
        config
    }

    pub fn save(&self) -> Result<PathBuf> {
        self.persisted
            .save_to_file(&self.path)
            .with_context(|| format!("Failed to save config file to {}", self.path.display()))?;
        Ok(self.path.clone())
    }

    pub fn apply_patch(&mut self, patch: ConfigPatch) {
        patch.apply_to(&mut self.persisted);
    }

    pub fn save_module_rules(&mut self, module_id: &str, rules: ModuleRules) {
        self.persisted.rules.insert(module_id.to_string(), rules);
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConfigPatch {
    pub moduledir: Option<PathBuf>,
    pub mountsource: Option<String>,
    pub partitions: Option<Vec<String>>,
    pub overlay_mode: Option<OverlayMode>,
    pub disable_umount: Option<bool>,
    pub enable_overlay_fallback: Option<bool>,
    pub default_mode: Option<DefaultMode>,
    pub hymofs: Option<HymoFsConfig>,
    pub rules: Option<HashMap<String, ModuleRules>>,
}

impl ConfigPatch {
    pub fn apply_to(self, config: &mut Config) {
        if let Some(moduledir) = self.moduledir {
            config.moduledir = moduledir;
        }

        if let Some(mountsource) = self.mountsource {
            config.mountsource = mountsource;
        }

        if let Some(partitions) = self.partitions {
            config.partitions = partitions;
        }

        if let Some(overlay_mode) = self.overlay_mode {
            config.overlay_mode = overlay_mode;
        }

        if let Some(disable_umount) = self.disable_umount {
            config.disable_umount = disable_umount;
        }

        if let Some(enable_overlay_fallback) = self.enable_overlay_fallback {
            config.enable_overlay_fallback = enable_overlay_fallback;
        }

        if let Some(default_mode) = self.default_mode {
            config.default_mode = default_mode;
        }

        if let Some(hymofs) = self.hymofs {
            config.hymofs = hymofs;
        }

        if let Some(rules) = self.rules {
            config.rules = rules;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn config_session_keeps_cli_overrides_out_of_persisted_config() {
        let tempdir = tempdir().expect("tempdir");
        let config_path = tempdir.path().join("config.toml");

        let seed = Config {
            moduledir: PathBuf::from("/data/adb/modules"),
            mountsource: "KSU".to_string(),
            partitions: vec!["system".to_string()],
            ..Default::default()
        };
        seed.save_to_file(&config_path).expect("seed config");

        let cli = Cli {
            config: Some(config_path.clone()),
            moduledir: Some(PathBuf::from("/tmp/override-modules")),
            mountsource: Some("APatch".to_string()),
            partitions: vec!["vendor".to_string()],
            command: None,
        };

        let mut session = ConfigSession::load_from_cli(&cli).expect("load session");
        let effective = session.effective();
        assert_eq!(effective.moduledir, PathBuf::from("/tmp/override-modules"));
        assert_eq!(effective.mountsource, "APatch");
        assert_eq!(effective.partitions, vec!["vendor".to_string()]);

        session.persisted_mut().disable_umount = true;
        session.save().expect("save config");

        let persisted = Config::load_optional_from_file(&config_path).expect("reload config");
        assert_eq!(persisted.moduledir, PathBuf::from("/data/adb/modules"));
        assert_eq!(persisted.mountsource, "KSU");
        assert_eq!(persisted.partitions, vec!["system".to_string()]);
        assert!(persisted.disable_umount);
    }
}
