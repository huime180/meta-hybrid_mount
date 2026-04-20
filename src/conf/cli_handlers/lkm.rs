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

use anyhow::{Context, Result};

use super::shared::{load_effective_config, update_config_for_cli};
use crate::{
    conf::cli::Cli,
    core::api,
    sys::{hymofs, lkm},
};

pub fn handle_lkm_status(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    let payload = api::build_lkm_payload(&config);
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("Failed to serialize LKM status")?
    );
    Ok(())
}

pub fn handle_lkm_load(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    lkm::load(&config.hymofs)?;
    hymofs::invalidate_status_cache();
    println!("HymoFS LKM loaded.");
    Ok(())
}

pub fn handle_lkm_unload(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    lkm::unload(&config.hymofs)?;
    hymofs::invalidate_status_cache();
    println!("HymoFS LKM unloaded.");
    Ok(())
}

pub fn handle_lkm_set_autoload(cli: &Cli, enabled: bool) -> Result<()> {
    let (path, _) = update_config_for_cli(cli, |config| {
        config.hymofs.lkm_autoload = enabled;
    })?;
    println!(
        "HymoFS LKM autoload {} in {}.",
        if enabled { "enabled" } else { "disabled" },
        path.display()
    );
    Ok(())
}

pub fn handle_lkm_set_kmi(cli: &Cli, kmi: &str) -> Result<()> {
    let (path, _) = update_config_for_cli(cli, |config| {
        config.hymofs.lkm_kmi_override = kmi.to_string();
    })?;
    println!(
        "HymoFS LKM KMI override set to {} in {}.",
        kmi,
        path.display()
    );
    Ok(())
}

pub fn handle_lkm_clear_kmi(cli: &Cli) -> Result<()> {
    let (path, _) = update_config_for_cli(cli, |config| {
        config.hymofs.lkm_kmi_override.clear();
    })?;
    println!("HymoFS LKM KMI override cleared in {}.", path.display());
    Ok(())
}
