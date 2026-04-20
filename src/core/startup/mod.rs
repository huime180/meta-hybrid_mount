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

mod recovery;

use anyhow::{Context, Result};

use crate::{
    conf::{cli::Cli, config::Config, loader},
    defs, sys, utils,
};

fn load_final_config(cli: &Cli) -> Result<Config> {
    let mut config = loader::load_config(cli)?;
    config.merge_with_cli(
        cli.moduledir.clone(),
        cli.mountsource.clone(),
        cli.partitions.clone(),
    );
    Ok(config)
}

pub fn run(cli: &Cli) -> Result<()> {
    sys::fs::ensure_dir_exists(defs::RUN_DIR)
        .with_context(|| format!("Failed to create run directory: {}", defs::RUN_DIR))?;

    let config = load_final_config(cli)?;

    utils::init_logging().context("Failed to initialize logging")?;
    crate::scoped_log!(info, "startup", "init: daemon=hybrid-mount");

    if let Ok(version) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        crate::scoped_log!(debug, "startup", "kernel: version={}", version.trim());
    }

    utils::check_ksu();

    if config.hymofs.enabled {
        match sys::lkm::autoload_if_needed(&config.hymofs) {
            Ok(true) => {
                crate::scoped_log!(
                    info,
                    "startup",
                    "hymofs lkm autoload: loaded=true, dir={}",
                    config.hymofs.lkm_dir.display()
                );
            }
            Ok(false) => {
                crate::scoped_log!(
                    debug,
                    "startup",
                    "hymofs lkm autoload: loaded=false, reason=not_needed"
                );
            }
            Err(err) => {
                crate::scoped_log!(
                    warn,
                    "startup",
                    "hymofs lkm autoload failed: error={:#}",
                    err
                );
            }
        }
    } else {
        crate::scoped_log!(debug, "startup", "hymofs disabled: skip_lkm_autoload=true");
    }

    if config.disable_umount {
        crate::scoped_log!(warn, "startup", "config: disable_umount=true");
    }

    recovery::run(config)
}
