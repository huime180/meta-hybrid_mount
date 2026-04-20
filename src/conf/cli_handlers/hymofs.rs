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
use serde_json::json;

use super::shared::{
    apply_live_if_possible, apply_live_runtime_sync, clear_pathbuf, detect_rule_file_type,
    load_effective_config, print_config_apply_result, require_live_hymofs, update_config_for_cli,
};
use crate::{
    conf::{
        cli::Cli,
        schema::{HymoKstatRuleConfig, HymoMapsRuleConfig},
    },
    core::{api, runtime_state::RuntimeState},
    mount::hymofs as hymofs_mount,
    sys::hymofs,
};

pub fn handle_hymofs_status(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    let runtime_state = RuntimeState::load().unwrap_or_default();
    let hymofs_info = hymofs_mount::collect_runtime_info(&config);

    let output = json!({
        "status": hymofs_info.status,
        "available": hymofs_info.available,
        "protocol_version": hymofs_info.protocol_version,
        "feature_bits": hymofs_info.feature_bits,
        "feature_names": hymofs_info.feature_names,
        "hooks": hymofs_info.hooks,
        "rule_count": hymofs_info.rule_count,
        "user_hide_rule_count": hymofs_info.user_hide_rule_count,
        "mirror_path": hymofs_info.mirror_path,
        "lkm": api::build_lkm_payload(&config),
        "config": &config.hymofs,
        "runtime": {
            "snapshot": &runtime_state.hymofs,
            "hymofs_modules": &runtime_state.hymofs_modules,
            "active_mounts": &runtime_state.active_mounts,
            "log_file": &runtime_state.log_file,
        }
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).context("Failed to serialize HymoFS status")?
    );
    Ok(())
}

pub fn handle_hymofs_list(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    let payload = if config.hymofs.enabled && hymofs_mount::can_operate(&config) {
        api::parse_hymofs_rule_listing(&hymofs::get_active_rules()?)
    } else {
        Vec::new()
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("Failed to serialize HymoFS rules")?
    );
    Ok(())
}

pub fn handle_hymofs_version(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    let state = RuntimeState::load().unwrap_or_default();
    let payload = api::build_hymofs_version_payload(&config, &state);
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("Failed to serialize HymoFS version")?
    );
    Ok(())
}

pub fn handle_hymofs_features() -> Result<()> {
    let output = api::build_features_payload();
    println!(
        "{}",
        serde_json::to_string_pretty(&output).context("Failed to serialize HymoFS features")?
    );
    Ok(())
}

pub fn handle_hymofs_hooks() -> Result<()> {
    println!("{}", hymofs_mount::hook_lines()?.join("\n"));
    Ok(())
}

pub fn handle_hymofs_clear() -> Result<()> {
    hymofs::clear_rules()?;
    println!("HymoFS rules cleared.");
    Ok(())
}

pub fn handle_hymofs_release_connection() -> Result<()> {
    hymofs::release_connection();
    println!("Released cached HymoFS client connection.");
    Ok(())
}

pub fn handle_hymofs_invalidate_cache() -> Result<()> {
    hymofs::invalidate_status_cache();
    println!("Invalidated cached HymoFS status.");
    Ok(())
}

pub fn handle_hymofs_fix_mounts() -> Result<()> {
    hymofs::fix_mounts()?;
    println!("HymoFS mount ordering fixed.");
    Ok(())
}

pub fn handle_hymofs_set_enabled(cli: &Cli, enabled: bool) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.enabled = enabled;
    })?;
    let applied = apply_live_if_possible(&config, "set_enabled", || {
        if enabled {
            hymofs_mount::sync_runtime_config(&config)?;
            hymofs::set_enabled(true)?;
        } else {
            hymofs_mount::clear_runtime_best_effort();
        }
        Ok(())
    })?;
    hymofs::invalidate_status_cache();
    print_config_apply_result(
        &path,
        if enabled {
            "HymoFS enabled state"
        } else {
            "HymoFS disabled state"
        },
        applied,
    );
    Ok(())
}

pub fn handle_hymofs_set_hidexattr(cli: &Cli, enabled: bool) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.enable_hidexattr = enabled;
    })?;
    let applied = apply_live_runtime_sync(&config, "set_hidexattr")?;
    print_config_apply_result(&path, "HymoFS hidexattr setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_mirror(cli: &Cli, path_value: &Path) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.mirror_path = path_value.to_path_buf();
    })?;
    let applied = apply_live_runtime_sync(&config, "set_mirror_path")?;
    print_config_apply_result(&path, "HymoFS mirror path", applied);
    Ok(())
}

pub fn handle_hymofs_set_debug(cli: &Cli, enabled: bool) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.enable_kernel_debug = enabled;
    })?;
    let applied = apply_live_runtime_sync(&config, "set_debug")?;
    print_config_apply_result(&path, "HymoFS kernel debug setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_stealth(cli: &Cli, enabled: bool) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.enable_stealth = enabled;
    })?;
    let applied = apply_live_runtime_sync(&config, "set_stealth")?;
    print_config_apply_result(&path, "HymoFS stealth setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_ignore_protocol_mismatch(cli: &Cli, enabled: bool) -> Result<()> {
    let (path, _) = update_config_for_cli(cli, |config| {
        config.hymofs.ignore_protocol_mismatch = enabled;
    })?;
    hymofs::invalidate_status_cache();
    println!(
        "HymoFS protocol mismatch policy saved to {}. Ignore mismatch is now {}.",
        path.display(),
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

pub fn handle_hymofs_set_mount_hide(
    cli: &Cli,
    enabled: bool,
    path_pattern: Option<&Path>,
) -> Result<()> {
    let (save_path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.enable_mount_hide = enabled;
        config.hymofs.mount_hide.enabled = enabled;
        if enabled {
            if let Some(path_pattern) = path_pattern {
                config.hymofs.mount_hide.path_pattern = path_pattern.to_path_buf();
            }
        } else {
            clear_pathbuf(&mut config.hymofs.mount_hide.path_pattern);
        }
    })?;
    let applied = apply_live_runtime_sync(&config, "set_mount_hide")?;
    print_config_apply_result(&save_path, "HymoFS mount_hide setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_maps_spoof(cli: &Cli, enabled: bool) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.enable_maps_spoof = enabled;
    })?;
    let applied = apply_live_runtime_sync(&config, "set_maps_spoof")?;
    print_config_apply_result(&path, "HymoFS maps_spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_statfs_spoof(
    cli: &Cli,
    enabled: bool,
    path_value: Option<&Path>,
    spoof_f_type: Option<u64>,
) -> Result<()> {
    let (save_path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.enable_statfs_spoof = enabled;
        config.hymofs.statfs_spoof.enabled = enabled;
        if enabled {
            if let Some(path) = path_value {
                config.hymofs.statfs_spoof.path = path.to_path_buf();
            }
            if let Some(spoof_f_type) = spoof_f_type {
                config.hymofs.statfs_spoof.spoof_f_type = spoof_f_type;
            }
        } else {
            clear_pathbuf(&mut config.hymofs.statfs_spoof.path);
            config.hymofs.statfs_spoof.spoof_f_type = 0;
        }
    })?;
    let applied = apply_live_runtime_sync(&config, "set_statfs_spoof")?;
    print_config_apply_result(&save_path, "HymoFS statfs_spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_uname(
    cli: &Cli,
    sysname: Option<&str>,
    nodename: Option<&str>,
    release: Option<&str>,
    version: Option<&str>,
    machine: Option<&str>,
    domainname: Option<&str>,
) -> Result<()> {
    if sysname.is_none()
        && nodename.is_none()
        && release.is_none()
        && version.is_none()
        && machine.is_none()
        && domainname.is_none()
    {
        bail!("No uname fields were provided. Use `hymofs uname clear` to clear spoofing.");
    }

    let (path, config) = update_config_for_cli(cli, |config| {
        if let Some(value) = sysname {
            config.hymofs.uname.sysname = value.to_string();
        }
        if let Some(value) = nodename {
            config.hymofs.uname.nodename = value.to_string();
        }
        if let Some(value) = release {
            config.hymofs.uname.release = value.to_string();
        }
        if let Some(value) = version {
            config.hymofs.uname.version = value.to_string();
        }
        if let Some(value) = machine {
            config.hymofs.uname.machine = value.to_string();
        }
        if let Some(value) = domainname {
            config.hymofs.uname.domainname = value.to_string();
        }
    })?;
    let applied = apply_live_runtime_sync(&config, "set_uname")?;
    print_config_apply_result(&path, "HymoFS uname spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_clear_uname(cli: &Cli) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.uname = Default::default();
    })?;
    let applied = apply_live_runtime_sync(&config, "clear_uname")?;
    print_config_apply_result(&path, "HymoFS uname spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_cmdline(cli: &Cli, value: &str) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.cmdline_value = value.to_string();
    })?;
    let applied = apply_live_runtime_sync(&config, "set_cmdline")?;
    print_config_apply_result(&path, "HymoFS cmdline spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_clear_cmdline(cli: &Cli) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.cmdline_value.clear();
    })?;
    let applied = apply_live_runtime_sync(&config, "clear_cmdline")?;
    print_config_apply_result(&path, "HymoFS cmdline spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_hide_uids(cli: &Cli, uids: &[u32]) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.hide_uids = uids.to_vec();
    })?;
    let applied = apply_live_runtime_sync(&config, "set_hide_uids")?;
    print_config_apply_result(&path, "HymoFS hide_uids setting", applied);
    Ok(())
}

pub fn handle_hymofs_clear_hide_uids(cli: &Cli) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.hide_uids.clear();
    })?;
    let applied = apply_live_runtime_sync(&config, "clear_hide_uids")?;
    print_config_apply_result(&path, "HymoFS hide_uids setting", applied);
    Ok(())
}

pub fn handle_hymofs_add_maps_rule(
    cli: &Cli,
    target_ino: u64,
    target_dev: u64,
    spoofed_ino: u64,
    spoofed_dev: u64,
    path: &Path,
) -> Result<()> {
    let new_rule = HymoMapsRuleConfig {
        target_ino,
        target_dev,
        spoofed_ino,
        spoofed_dev,
        spoofed_pathname: path.to_path_buf(),
    };

    let (path_out, config) = update_config_for_cli(cli, |config| {
        if let Some(existing) = config
            .hymofs
            .maps_rules
            .iter_mut()
            .find(|rule| rule.target_ino == target_ino && rule.target_dev == target_dev)
        {
            *existing = new_rule.clone();
        } else {
            config.hymofs.maps_rules.push(new_rule.clone());
        }
    })?;
    let applied = apply_live_runtime_sync(&config, "add_maps_rule")?;
    print_config_apply_result(&path_out, "HymoFS maps rule", applied);
    Ok(())
}

pub fn handle_hymofs_clear_maps_rules(cli: &Cli) -> Result<()> {
    let (path, config) = update_config_for_cli(cli, |config| {
        config.hymofs.maps_rules.clear();
    })?;
    let applied = apply_live_runtime_sync(&config, "clear_maps_rules")?;
    print_config_apply_result(&path, "HymoFS maps rules", applied);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn handle_hymofs_upsert_kstat_rule(
    cli: &Cli,
    target_ino: u64,
    target_path: &Path,
    spoofed_ino: u64,
    spoofed_dev: u64,
    spoofed_nlink: u32,
    spoofed_size: i64,
    spoofed_atime_sec: i64,
    spoofed_atime_nsec: i64,
    spoofed_mtime_sec: i64,
    spoofed_mtime_nsec: i64,
    spoofed_ctime_sec: i64,
    spoofed_ctime_nsec: i64,
    spoofed_blksize: u64,
    spoofed_blocks: u64,
    is_static: bool,
) -> Result<()> {
    let new_rule = HymoKstatRuleConfig {
        target_ino,
        target_pathname: target_path.to_path_buf(),
        spoofed_ino,
        spoofed_dev,
        spoofed_nlink,
        spoofed_size,
        spoofed_atime_sec,
        spoofed_atime_nsec,
        spoofed_mtime_sec,
        spoofed_mtime_nsec,
        spoofed_ctime_sec,
        spoofed_ctime_nsec,
        spoofed_blksize,
        spoofed_blocks,
        is_static,
    };

    let (path, config) = update_config_for_cli(cli, |config| {
        if let Some(existing) = config
            .hymofs
            .kstat_rules
            .iter_mut()
            .find(|rule| rule.target_ino == target_ino && rule.target_pathname == target_path)
        {
            *existing = new_rule.clone();
        } else {
            config.hymofs.kstat_rules.push(new_rule.clone());
        }
    })?;
    let applied = apply_live_runtime_sync(&config, "upsert_kstat_rule")?;
    print_config_apply_result(&path, "HymoFS kstat rule", applied);
    Ok(())
}

pub fn handle_hymofs_clear_kstat_rules_config(cli: &Cli) -> Result<()> {
    let (path, _) = update_config_for_cli(cli, |config| {
        config.hymofs.kstat_rules.clear();
    })?;
    println!(
        "HymoFS kstat rules were removed from {}. Existing kernel kstat spoof rules may persist until the LKM is reloaded.",
        path.display()
    );
    Ok(())
}

pub fn handle_hymofs_rule_add(
    cli: &Cli,
    target: &Path,
    source: &Path,
    file_type: Option<i32>,
) -> Result<()> {
    let config = load_effective_config(cli)?;
    require_live_hymofs(&config, "add HymoFS rule")?;
    let file_type = match file_type {
        Some(value) => value,
        None => detect_rule_file_type(source)?,
    };
    hymofs::add_rule(target, source, file_type)?;
    println!(
        "HymoFS ADD rule applied: target={}, source={}, file_type={}",
        target.display(),
        source.display(),
        file_type
    );
    Ok(())
}

pub fn handle_hymofs_rule_merge(cli: &Cli, target: &Path, source: &Path) -> Result<()> {
    let config = load_effective_config(cli)?;
    require_live_hymofs(&config, "add HymoFS merge rule")?;
    hymofs::add_merge_rule(target, source)?;
    println!(
        "HymoFS MERGE rule applied: target={}, source={}",
        target.display(),
        source.display()
    );
    Ok(())
}

pub fn handle_hymofs_rule_hide(cli: &Cli, path: &Path) -> Result<()> {
    let config = load_effective_config(cli)?;
    require_live_hymofs(&config, "add HymoFS hide rule")?;
    hymofs::hide_path(path)?;
    println!("HymoFS HIDE rule applied: {}", path.display());
    Ok(())
}

pub fn handle_hymofs_rule_delete(cli: &Cli, path: &Path) -> Result<()> {
    let config = load_effective_config(cli)?;
    require_live_hymofs(&config, "delete HymoFS rule")?;
    hymofs::delete_rule(path)?;
    println!("HymoFS rule deleted: {}", path.display());
    Ok(())
}

pub fn handle_hymofs_rule_add_dir(cli: &Cli, target_base: &Path, source_dir: &Path) -> Result<()> {
    let config = load_effective_config(cli)?;
    require_live_hymofs(&config, "add HymoFS rules from directory")?;
    hymofs::add_rules_from_directory(target_base, source_dir)?;
    println!(
        "HymoFS directory rules applied: target_base={}, source_dir={}",
        target_base.display(),
        source_dir.display()
    );
    Ok(())
}

pub fn handle_hymofs_rule_remove_dir(
    cli: &Cli,
    target_base: &Path,
    source_dir: &Path,
) -> Result<()> {
    let config = load_effective_config(cli)?;
    require_live_hymofs(&config, "remove HymoFS rules from directory")?;
    hymofs::remove_rules_from_directory(target_base, source_dir)?;
    println!(
        "HymoFS directory rules removed: target_base={}, source_dir={}",
        target_base.display(),
        source_dir.display()
    );
    Ok(())
}
