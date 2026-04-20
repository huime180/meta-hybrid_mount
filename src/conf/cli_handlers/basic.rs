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

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::shared::{decode_hex_json, load_effective_config};
use crate::{
    conf::{
        cli::Cli,
        config::{self, Config},
    },
    core::{inventory::listing as modules, runtime_state::RuntimeState},
    defs, utils,
};

pub fn handle_gen_config(output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "Config already exists at {}. Use --force to overwrite.",
            output.display()
        );
    }

    Config::default()
        .save_to_file(output)
        .with_context(|| format!("Failed to save generated config to {}", output.display()))
}

pub fn handle_show_config(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    let json = serde_json::to_string(&config).context("Failed to serialize config to JSON")?;
    println!("{}", json);
    Ok(())
}

pub fn handle_save_config(payload: &str) -> Result<()> {
    let config: Config = decode_hex_json(payload, "config")?;

    config
        .save_to_file(defs::CONFIG_FILE)
        .context("Failed to save config file")?;

    println!("Configuration saved successfully.");
    Ok(())
}

pub fn handle_save_module_rules(module_id: &str, payload: &str) -> Result<()> {
    utils::validate_module_id(module_id)?;
    let new_rules: config::ModuleRules = decode_hex_json(payload, "module rules")?;
    let mut config = Config::load_default().unwrap_or_default();

    config.rules.insert(module_id.to_string(), new_rules);
    config
        .save_to_file(defs::CONFIG_FILE)
        .context("Failed to update config file with new rules")?;

    println!("Module rules saved for {} into config.toml", module_id);
    Ok(())
}

pub fn handle_modules(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    modules::print_list(&config).context("Failed to list modules")
}

pub fn handle_state() -> Result<()> {
    let state = RuntimeState::load().context("Failed to load runtime state")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&state).context("Failed to serialize runtime state")?
    );
    Ok(())
}

pub fn handle_logs(lines: usize) -> Result<()> {
    if !Path::new(defs::DAEMON_LOG_FILE).exists() {
        println!("No daemon log has been written yet.");
        return Ok(());
    }

    let content = std::fs::read_to_string(defs::DAEMON_LOG_FILE)
        .with_context(|| format!("Failed to read daemon log file {}", defs::DAEMON_LOG_FILE))?;
    let mut selected: Vec<&str> = content.lines().rev().take(lines).collect();
    selected.reverse();

    for line in selected {
        println!("{line}");
    }

    Ok(())
}
