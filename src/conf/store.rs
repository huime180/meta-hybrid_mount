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
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use crate::{
    conf::{cli::Cli, loader, schema::Config},
    defs,
};

fn migrate_legacy_kasumi_lkm_dir(config: &mut Config) {
    let legacy_lkm_dir = Path::new(defs::HYBRID_MOUNT_MODULE_DIR).join("hymofs_lkm");
    if config.kasumi.lkm_dir == legacy_lkm_dir {
        crate::scoped_log!(
            info,
            "conf:store:load_merged",
            "migrated legacy Kasumi LKM dir: from={}, to={}",
            legacy_lkm_dir.display(),
            defs::KASUMI_LKM_DIR
        );
        config.kasumi.lkm_dir = PathBuf::from(defs::KASUMI_LKM_DIR);
    }
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create config directory")?;
    }
    Ok(())
}

fn load_merged_config(main_path: &Path, allow_missing_main: bool) -> Result<Config> {
    crate::scoped_log!(
        debug,
        "conf:store:load_merged",
        "start: path={}, allow_missing_main={}",
        main_path.display(),
        allow_missing_main
    );

    let mut config = if main_path.exists() {
        let content = fs::read_to_string(main_path)
            .with_context(|| format!("failed to read config file {}", main_path.display()))?;
        toml::from_str::<Config>(&content)
            .with_context(|| format!("failed to parse config file {}", main_path.display()))?
    } else if allow_missing_main {
        crate::scoped_log!(
            debug,
            "conf:store:load_merged",
            "fallback: reason=config_missing, path={}",
            main_path.display()
        );
        Config::default()
    } else {
        crate::scoped_log!(
            error,
            "conf:store:load_merged",
            "failed: reason=config_missing, path={}",
            main_path.display()
        );
        bail!("config file not found: {}", main_path.display());
    };

    migrate_legacy_kasumi_lkm_dir(&mut config);

    crate::scoped_log!(
        debug,
        "conf:store:load_merged",
        "complete: path={}",
        main_path.display()
    );

    Ok(config)
}

impl Config {
    pub fn load_optional_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        load_merged_config(path.as_ref(), true)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let main_path = path.as_ref();
        let mut config = self.clone();
        migrate_legacy_kasumi_lkm_dir(&mut config);
        let content = toml::to_string_pretty(&config).context("failed to serialize config")?;

        ensure_parent_dir(main_path)?;
        fs::write(main_path, content)
            .with_context(|| format!("failed to write config file {}", main_path.display()))?;
        Ok(())
    }
}

pub struct ConfigSession;

impl ConfigSession {
    pub fn load_persisted(cli: &Cli) -> Result<Config> {
        loader::load_config(cli)
    }
}
