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

use super::shared::{decode_hex_json, load_config_session, load_effective_config};
use crate::{
    conf::{
        cli::Cli,
        config::{self, Config},
        store::ConfigPatch,
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

pub fn handle_save_config(cli: &Cli, payload: &str) -> Result<()> {
    let patch: ConfigPatch = decode_hex_json(payload, "config")?;
    let mut session = load_config_session(cli)?;
    session.apply_patch(patch);
    let path = session.save().context("Failed to save config file")?;

    println!("Configuration saved successfully to {}.", path.display());
    Ok(())
}

pub fn handle_save_module_rules(cli: &Cli, module_id: &str, payload: &str) -> Result<()> {
    utils::validate_module_id(module_id)?;
    let new_rules: config::ModuleRules = decode_hex_json(payload, "module rules")?;
    let mut session = load_config_session(cli)?;
    session.save_module_rules(module_id, new_rules);
    let path = session
        .save()
        .context("Failed to update config file with new rules")?;

    println!(
        "Module rules saved for {} into {}",
        module_id,
        path.display()
    );
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf};

    use tempfile::tempdir;

    use super::*;
    use crate::{
        conf::{
            cli::Cli,
            schema::{HymoFsConfig, OverlayMode},
        },
        domain::{DefaultMode, ModuleRules, MountMode},
    };

    #[test]
    fn save_config_respects_custom_path_and_preserves_unsent_fields() {
        let tempdir = tempdir().expect("tempdir");
        let config_path = tempdir.path().join("config.toml");

        let config = Config {
            moduledir: PathBuf::from("/data/adb/modules"),
            mountsource: "KSU".to_string(),
            partitions: vec!["system".to_string()],
            overlay_mode: OverlayMode::Ext4,
            default_mode: DefaultMode::Magic,
            hymofs: HymoFsConfig {
                enabled: true,
                ..Default::default()
            },
            rules: HashMap::from([(
                "demo".to_string(),
                ModuleRules {
                    default_mode: MountMode::Magic,
                    paths: HashMap::new(),
                },
            )]),
            ..Default::default()
        };
        config.save_to_file(&config_path).expect("seed config");

        let patch = ConfigPatch {
            moduledir: Some(PathBuf::from("/data/adb/custom_modules")),
            mountsource: None,
            partitions: Some(Vec::new()),
            overlay_mode: Some(OverlayMode::Tmpfs),
            disable_umount: Some(true),
            enable_overlay_fallback: Some(true),
            default_mode: None,
            hymofs: None,
            rules: None,
        };
        let payload = serde_json::to_string(&patch).expect("serialize patch");
        let hex_payload = payload
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let cli = Cli {
            config: Some(config_path.clone()),
            moduledir: None,
            mountsource: None,
            partitions: Vec::new(),
            command: None,
        };

        handle_save_config(&cli, &hex_payload).expect("save patch");

        let saved = Config::load_optional_from_file(&config_path).expect("load saved config");
        assert_eq!(saved.moduledir, PathBuf::from("/data/adb/custom_modules"));
        assert_eq!(saved.partitions, Vec::<String>::new());
        assert_eq!(saved.overlay_mode, OverlayMode::Tmpfs);
        assert!(saved.disable_umount);
        assert!(saved.enable_overlay_fallback);
        assert_eq!(saved.default_mode, DefaultMode::Magic);
        assert!(saved.hymofs.enabled);
        assert_eq!(
            saved
                .rules
                .get("demo")
                .map(|rules| rules.default_mode.clone()),
            Some(MountMode::Magic)
        );
    }

    #[test]
    fn save_module_rules_respects_custom_path() {
        let tempdir = tempdir().expect("tempdir");
        let config_path = tempdir.path().join("custom.toml");
        Config::default()
            .save_to_file(&config_path)
            .expect("seed config");

        let cli = Cli {
            config: Some(config_path.clone()),
            moduledir: None,
            mountsource: None,
            partitions: Vec::new(),
            command: None,
        };

        let rules = ModuleRules {
            default_mode: MountMode::Overlay,
            paths: HashMap::from([("system/bin/demo".to_string(), MountMode::Magic)]),
        };
        let payload = serde_json::to_string(&rules).expect("serialize rules");
        let hex_payload = payload
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        handle_save_module_rules(&cli, "demo", &hex_payload).expect("save module rules");

        let saved = Config::load_optional_from_file(&config_path).expect("load saved config");
        let saved_rules = saved.rules.get("demo").expect("module rules saved");
        assert_eq!(saved_rules.default_mode, rules.default_mode);
        assert_eq!(saved_rules.paths, rules.paths);
    }
}
