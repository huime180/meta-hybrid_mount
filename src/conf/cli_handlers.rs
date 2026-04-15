// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::{
    conf::{
        cli::Cli,
        config::{self, Config},
        loader,
        schema::{HymoKstatRuleConfig, HymoMapsRuleConfig},
    },
    core::{api, inventory::listing as modules, runtime_state::RuntimeState, user_hide_rules},
    defs,
    sys::{
        hymofs::{
            self, HymoMapsRule, HymoMountHideArg, HymoSpoofKstat, HymoSpoofUname,
            HymoStatfsSpoofArg,
        },
        lkm,
    },
    utils,
};

fn decode_hex_json<T: DeserializeOwned>(payload: &str, type_name: &str) -> Result<T> {
    if !payload.len().is_multiple_of(2) {
        bail!("Invalid hex payload length for {}", type_name);
    }

    let json_bytes = (0..payload.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&payload[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .with_context(|| format!("Failed to decode hex payload for {}", type_name))?;

    serde_json::from_slice(&json_bytes)
        .with_context(|| format!("Failed to parse {} JSON payload", type_name))
}

fn load_effective_config(cli: &Cli) -> Result<Config> {
    let mut config = loader::load_config(cli)?;
    config.merge_with_cli(
        cli.moduledir.clone(),
        cli.mountsource.clone(),
        cli.partitions.clone(),
    );
    Ok(config)
}

fn config_output_path(cli: &Cli) -> PathBuf {
    cli.config
        .clone()
        .unwrap_or_else(|| PathBuf::from(defs::CONFIG_FILE))
}

fn save_hymofs_config_for_cli(cli: &Cli, config: &Config) -> Result<PathBuf> {
    let main_path = config_output_path(cli);
    let hymofs_path = crate::conf::store::hymofs_config_path_for(&main_path);
    config.hymofs.save_to_file(&hymofs_path).with_context(|| {
        format!(
            "Failed to save HymoFS config file to {}",
            hymofs_path.display()
        )
    })?;
    Ok(hymofs_path)
}

fn apply_live_if_possible<F>(config: &Config, description: &str, operation: F) -> Result<bool>
where
    F: FnOnce() -> Result<()>,
{
    if !hymofs::can_operate(config.hymofs.ignore_protocol_mismatch) {
        crate::scoped_log!(
            warn,
            "cli:hymofs",
            "live apply skipped: operation={}, status={}",
            description,
            hymofs::status_name(hymofs::check_status())
        );
        return Ok(false);
    }

    operation()?;
    Ok(true)
}

fn require_live_hymofs(config: &Config, description: &str) -> Result<()> {
    if hymofs::can_operate(config.hymofs.ignore_protocol_mismatch) {
        return Ok(());
    }

    bail!(
        "HymoFS is not available for {} (status={})",
        description,
        hymofs::status_name(hymofs::check_status())
    );
}

fn print_config_apply_result(path: &Path, what: &str, applied: bool) {
    if applied {
        println!("{what} saved to {} and applied to HymoFS.", path.display());
    } else {
        println!(
            "{what} saved to {}. HymoFS is not currently available, so only the config was updated.",
            path.display()
        );
    }
}

fn to_c_ulong(value: u64, field_name: &str) -> Result<libc::c_ulong> {
    libc::c_ulong::try_from(value)
        .map_err(|_| anyhow::anyhow!("{field_name} value {value} does not fit into c_ulong"))
}

fn to_c_long(value: i64, field_name: &str) -> Result<libc::c_long> {
    libc::c_long::try_from(value)
        .map_err(|_| anyhow::anyhow!("{field_name} value {value} does not fit into c_long"))
}

fn clear_pathbuf(path: &mut PathBuf) {
    *path = PathBuf::new();
}

fn apply_mount_hide_from_config(config: &Config) -> Result<()> {
    let enabled = config.hymofs.enable_mount_hide
        || config.hymofs.enable_hidexattr
        || config.hymofs.mount_hide.enabled
        || !config.hymofs.mount_hide.path_pattern.as_os_str().is_empty();

    if enabled && !config.hymofs.mount_hide.path_pattern.as_os_str().is_empty() {
        let arg =
            HymoMountHideArg::new(true, Some(config.hymofs.mount_hide.path_pattern.as_path()))?;
        hymofs::set_mount_hide_config(&arg)
    } else {
        hymofs::set_mount_hide(enabled)
    }
}

fn apply_statfs_spoof_from_config(config: &Config) -> Result<()> {
    let enabled = config.hymofs.enable_statfs_spoof
        || config.hymofs.enable_hidexattr
        || config.hymofs.statfs_spoof.enabled
        || !config.hymofs.statfs_spoof.path.as_os_str().is_empty()
        || config.hymofs.statfs_spoof.spoof_f_type != 0;

    if enabled
        && (!config.hymofs.statfs_spoof.path.as_os_str().is_empty()
            || config.hymofs.statfs_spoof.spoof_f_type != 0)
    {
        let arg = HymoStatfsSpoofArg::with_path_and_f_type(
            true,
            config.hymofs.statfs_spoof.path.as_path(),
            to_c_ulong(
                config.hymofs.statfs_spoof.spoof_f_type,
                "statfs_spoof.spoof_f_type",
            )?,
        )?;
        hymofs::set_statfs_spoof_config(&arg)
    } else {
        hymofs::set_statfs_spoof(enabled)
    }
}

fn apply_uname_from_config(config: &Config) -> Result<()> {
    let mut uname = HymoSpoofUname::default();
    if !config.hymofs.uname.sysname.is_empty() {
        uname.set_sysname(&config.hymofs.uname.sysname)?;
    }
    if !config.hymofs.uname.nodename.is_empty() {
        uname.set_nodename(&config.hymofs.uname.nodename)?;
    }
    if !config.hymofs.uname.release.is_empty() {
        uname.set_release(&config.hymofs.uname.release)?;
    }
    if !config.hymofs.uname.version.is_empty() {
        uname.set_version(&config.hymofs.uname.version)?;
    }
    if !config.hymofs.uname.machine.is_empty() {
        uname.set_machine(&config.hymofs.uname.machine)?;
    }
    if !config.hymofs.uname.domainname.is_empty() {
        uname.set_domainname(&config.hymofs.uname.domainname)?;
    }
    if !config.hymofs.uname_release.is_empty() {
        uname.set_release(&config.hymofs.uname_release)?;
    }
    if !config.hymofs.uname_version.is_empty() {
        uname.set_version(&config.hymofs.uname_version)?;
    }
    hymofs::set_uname(&uname)
}

fn clear_hymofs_runtime_best_effort() {
    let empty_uname = HymoSpoofUname::default();

    for (name, result) in [
        ("set_enabled(false)", hymofs::set_enabled(false)),
        ("clear_rules", hymofs::clear_rules()),
        ("clear_maps_rules", hymofs::clear_maps_rules()),
        ("set_uname(clear)", hymofs::set_uname(&empty_uname)),
        ("set_cmdline(clear)", hymofs::set_cmdline_str("")),
        ("set_hide_uids(clear)", hymofs::set_hide_uids(&[])),
        ("set_mount_hide(false)", hymofs::set_mount_hide(false)),
        ("set_maps_spoof(false)", hymofs::set_maps_spoof(false)),
        ("set_statfs_spoof(false)", hymofs::set_statfs_spoof(false)),
        ("set_stealth(false)", hymofs::set_stealth(false)),
        ("set_debug(false)", hymofs::set_debug(false)),
    ] {
        if let Err(err) = result {
            crate::scoped_log!(
                debug,
                "cli:hymofs",
                "disable cleanup skipped: operation={}, error={:#}",
                name,
                err
            );
        }
    }

    hymofs::invalidate_status_cache();
}

fn apply_kstat_rule(rule: &HymoKstatRuleConfig) -> Result<()> {
    let mut native_rule = HymoSpoofKstat::new(
        to_c_ulong(rule.target_ino, "target_ino")?,
        &rule.target_pathname,
    )?;
    native_rule.spoofed_ino = to_c_ulong(rule.spoofed_ino, "spoofed_ino")?;
    native_rule.spoofed_dev = to_c_ulong(rule.spoofed_dev, "spoofed_dev")?;
    native_rule.spoofed_nlink = rule.spoofed_nlink;
    native_rule.spoofed_size = rule.spoofed_size;
    native_rule.spoofed_atime_sec = to_c_long(rule.spoofed_atime_sec, "spoofed_atime_sec")?;
    native_rule.spoofed_atime_nsec = to_c_long(rule.spoofed_atime_nsec, "spoofed_atime_nsec")?;
    native_rule.spoofed_mtime_sec = to_c_long(rule.spoofed_mtime_sec, "spoofed_mtime_sec")?;
    native_rule.spoofed_mtime_nsec = to_c_long(rule.spoofed_mtime_nsec, "spoofed_mtime_nsec")?;
    native_rule.spoofed_ctime_sec = to_c_long(rule.spoofed_ctime_sec, "spoofed_ctime_sec")?;
    native_rule.spoofed_ctime_nsec = to_c_long(rule.spoofed_ctime_nsec, "spoofed_ctime_nsec")?;
    native_rule.spoofed_blksize = to_c_ulong(rule.spoofed_blksize, "spoofed_blksize")?;
    native_rule.spoofed_blocks = rule.spoofed_blocks;
    native_rule.is_static = if rule.is_static { 1 } else { 0 };

    match hymofs::update_spoof_kstat(&native_rule) {
        Ok(()) => Ok(()),
        Err(_) => hymofs::add_spoof_kstat(&native_rule),
    }
}

fn detect_rule_file_type(path: &Path) -> Result<i32> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to read source metadata for {}", path.display()))?;
    let file_type = metadata.file_type();

    if file_type.is_char_device() && metadata.rdev() == 0 {
        bail!(
            "source {} is a whiteout node; use `hymofs rule hide` instead",
            path.display()
        );
    }

    if file_type.is_file() {
        Ok(libc::DT_REG as i32)
    } else if file_type.is_symlink() {
        Ok(libc::DT_LNK as i32)
    } else {
        bail!(
            "unsupported source type for rule add: {} (use `merge` or `add-dir` for directories)",
            path.display()
        )
    }
}

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

    let content = fs::read_to_string(defs::DAEMON_LOG_FILE)
        .with_context(|| format!("Failed to read daemon log file {}", defs::DAEMON_LOG_FILE))?;
    let mut selected: Vec<&str> = content.lines().rev().take(lines).collect();
    selected.reverse();

    for line in selected {
        println!("{line}");
    }

    Ok(())
}

pub fn handle_api_system(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    let state = RuntimeState::load().unwrap_or_default();
    let payload = api::build_system_payload(&config, &state);
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("Failed to serialize API system payload")?
    );
    Ok(())
}

pub fn handle_api_storage() -> Result<()> {
    let state = RuntimeState::load().unwrap_or_default();
    let payload = api::build_storage_payload(&state);
    println!(
        "{}",
        serde_json::to_string_pretty(&payload)
            .context("Failed to serialize API storage payload")?
    );
    Ok(())
}

pub fn handle_api_mount_stats() -> Result<()> {
    let state = RuntimeState::load().unwrap_or_default();
    let payload = api::build_mount_stats_payload(&state);
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("Failed to serialize API mount stats")?
    );
    Ok(())
}

pub fn handle_api_partitions(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    let payload = api::build_partitions_payload(&config);
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("Failed to serialize API partitions")?
    );
    Ok(())
}

pub fn handle_api_lkm(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    let payload = api::build_lkm_payload(&config);
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("Failed to serialize API lkm payload")?
    );
    Ok(())
}

pub fn handle_api_features() -> Result<()> {
    let payload = api::build_features_payload();
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("Failed to serialize API features")?
    );
    Ok(())
}

pub fn handle_api_hooks(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    require_live_hymofs(&config, "read HymoFS hooks")?;
    println!("{}", hymofs::get_hooks()?);
    Ok(())
}

pub fn handle_hide_list() -> Result<()> {
    let rules = user_hide_rules::load_user_hide_rules()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&rules).context("Failed to serialize user hide rules")?
    );
    Ok(())
}

pub fn handle_hide_add(cli: &Cli, path: &Path) -> Result<()> {
    let added = user_hide_rules::add_user_hide_rule(path)?;
    if added {
        let config = load_effective_config(cli)?;
        if hymofs::can_operate(config.hymofs.ignore_protocol_mismatch)
            && let Err(err) = hymofs::hide_path(path)
        {
            crate::scoped_log!(
                warn,
                "cli:hide",
                "live apply failed: path={}, error={:#}",
                path.display(),
                err
            );
        }
    }
    if added {
        println!("User hide rule added: {}", path.display());
    } else {
        println!("User hide rule already exists: {}", path.display());
    }
    Ok(())
}

pub fn handle_hide_remove(path: &Path) -> Result<()> {
    let removed = user_hide_rules::remove_user_hide_rule(path)?;
    if removed {
        println!(
            "User hide rule removed from persistent list: {}. Existing kernel hide state may persist until HymoFS rules are rebuilt.",
            path.display()
        );
    } else {
        println!("User hide rule was not present: {}", path.display());
    }
    Ok(())
}

pub fn handle_hide_apply(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    require_live_hymofs(&config, "apply user hide rules")?;
    let (applied, failed) = user_hide_rules::apply_user_hide_rules()?;
    println!("User hide rules applied: {applied} succeeded, {failed} failed.");
    Ok(())
}

pub fn handle_hymofs_status(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    let runtime_state = RuntimeState::load().unwrap_or_default();
    let (status_name, available, protocol_version, feature_bits, feature_names, hooks, rule_count) =
        if config.hymofs.enabled {
            let status = hymofs::check_status();
            let protocol_version = hymofs::get_protocol_version().ok();
            let feature_bits = hymofs::get_features().ok();
            let feature_names = feature_bits.map(hymofs::feature_names).unwrap_or_default();
            let hooks: Vec<String> = hymofs::get_hooks()
                .map(|value| {
                    value
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let rule_count = hymofs::get_active_rules()
                .map(|value| api::parse_hymofs_rule_listing(&value).len())
                .unwrap_or(0);

            (
                hymofs::status_name(status).to_string(),
                status == hymofs::HymoFsStatus::Available,
                protocol_version,
                feature_bits,
                feature_names,
                hooks,
                rule_count,
            )
        } else {
            (
                "disabled".to_string(),
                false,
                None,
                None,
                Vec::new(),
                Vec::new(),
                0,
            )
        };

    let output = json!({
        "status": status_name,
        "available": available,
        "protocol_version": protocol_version,
        "feature_bits": feature_bits,
        "feature_names": feature_names,
        "hooks": hooks,
        "rule_count": rule_count,
        "user_hide_rule_count": user_hide_rules::user_hide_rule_count(),
        "mirror_path": config.hymofs.mirror_path,
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
    let _ = utils::init_logging();
    let config = load_effective_config(cli)?;
    lkm::load(&config.hymofs)?;
    hymofs::invalidate_status_cache();
    println!("HymoFS LKM loaded.");
    Ok(())
}

pub fn handle_lkm_unload(cli: &Cli) -> Result<()> {
    let _ = utils::init_logging();
    let config = load_effective_config(cli)?;
    lkm::unload(&config.hymofs)?;
    hymofs::invalidate_status_cache();
    println!("HymoFS LKM unloaded.");
    Ok(())
}

pub fn handle_lkm_set_autoload(cli: &Cli, enabled: bool) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.lkm_autoload = enabled;
    let path = save_hymofs_config_for_cli(cli, &config)?;
    println!(
        "HymoFS LKM autoload {} in {}.",
        if enabled { "enabled" } else { "disabled" },
        path.display()
    );
    Ok(())
}

pub fn handle_lkm_set_kmi(cli: &Cli, kmi: &str) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.lkm_kmi_override = kmi.to_string();
    let path = save_hymofs_config_for_cli(cli, &config)?;
    println!(
        "HymoFS LKM KMI override set to {} in {}.",
        kmi,
        path.display()
    );
    Ok(())
}

pub fn handle_lkm_clear_kmi(cli: &Cli) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.lkm_kmi_override.clear();
    let path = save_hymofs_config_for_cli(cli, &config)?;
    println!("HymoFS LKM KMI override cleared in {}.", path.display());
    Ok(())
}

pub fn handle_hymofs_list(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    let payload =
        if config.hymofs.enabled && hymofs::check_status() == hymofs::HymoFsStatus::Available {
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
    println!("{}", hymofs::get_hooks()?);
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
    let mut config = load_effective_config(cli)?;
    config.hymofs.enabled = enabled;
    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "set_enabled", || {
        if enabled {
            hymofs::set_mirror_path(&config.hymofs.mirror_path)?;
            hymofs::set_enabled(true)?;
        } else {
            clear_hymofs_runtime_best_effort();
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
    let mut config = load_effective_config(cli)?;
    config.hymofs.enable_hidexattr = enabled;
    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "set_hidexattr", || {
        hymofs::set_stealth(config.hymofs.enable_stealth || enabled)?;
        apply_mount_hide_from_config(&config)?;
        hymofs::set_maps_spoof(config.hymofs.enable_maps_spoof || config.hymofs.enable_hidexattr)?;
        apply_statfs_spoof_from_config(&config)
    })?;
    print_config_apply_result(&path, "HymoFS hidexattr setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_mirror(cli: &Cli, path_value: &Path) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.mirror_path = path_value.to_path_buf();
    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "set_mirror_path", || {
        hymofs::set_mirror_path(path_value)
    })?;
    print_config_apply_result(&path, "HymoFS mirror path", applied);
    Ok(())
}

pub fn handle_hymofs_set_debug(cli: &Cli, enabled: bool) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.enable_kernel_debug = enabled;
    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "set_debug", || hymofs::set_debug(enabled))?;
    print_config_apply_result(&path, "HymoFS kernel debug setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_stealth(cli: &Cli, enabled: bool) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.enable_stealth = enabled;
    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "set_stealth", || hymofs::set_stealth(enabled))?;
    print_config_apply_result(&path, "HymoFS stealth setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_ignore_protocol_mismatch(cli: &Cli, enabled: bool) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.ignore_protocol_mismatch = enabled;
    let path = save_hymofs_config_for_cli(cli, &config)?;
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
    let mut config = load_effective_config(cli)?;
    config.hymofs.enable_mount_hide = enabled;
    config.hymofs.mount_hide.enabled = enabled;
    match (enabled, path_pattern) {
        (_, Some(path_pattern)) => {
            config.hymofs.mount_hide.path_pattern = path_pattern.to_path_buf()
        }
        (false, None) => clear_pathbuf(&mut config.hymofs.mount_hide.path_pattern),
        (true, None) => {}
    }

    let save_path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "set_mount_hide", || {
        apply_mount_hide_from_config(&config)
    })?;
    print_config_apply_result(&save_path, "HymoFS mount_hide setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_maps_spoof(cli: &Cli, enabled: bool) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.enable_maps_spoof = enabled;
    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "set_maps_spoof", || {
        hymofs::set_maps_spoof(enabled)
    })?;
    print_config_apply_result(&path, "HymoFS maps_spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_statfs_spoof(
    cli: &Cli,
    enabled: bool,
    path_value: Option<&Path>,
    spoof_f_type: Option<u64>,
) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.enable_statfs_spoof = enabled;
    config.hymofs.statfs_spoof.enabled = enabled;
    match path_value {
        Some(path) => config.hymofs.statfs_spoof.path = path.to_path_buf(),
        None if !enabled => clear_pathbuf(&mut config.hymofs.statfs_spoof.path),
        None => {}
    }
    if let Some(spoof_f_type) = spoof_f_type {
        config.hymofs.statfs_spoof.spoof_f_type = spoof_f_type;
    } else if !enabled {
        config.hymofs.statfs_spoof.spoof_f_type = 0;
    }

    let save_path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "set_statfs_spoof", || {
        apply_statfs_spoof_from_config(&config)
    })?;
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

    let mut config = load_effective_config(cli)?;
    if let Some(value) = sysname {
        config.hymofs.uname.sysname = value.to_string();
    }
    if let Some(value) = nodename {
        config.hymofs.uname.nodename = value.to_string();
    }
    if let Some(value) = release {
        config.hymofs.uname.release = value.to_string();
        config.hymofs.uname_release = value.to_string();
    }
    if let Some(value) = version {
        config.hymofs.uname.version = value.to_string();
        config.hymofs.uname_version = value.to_string();
    }
    if let Some(value) = machine {
        config.hymofs.uname.machine = value.to_string();
    }
    if let Some(value) = domainname {
        config.hymofs.uname.domainname = value.to_string();
    }

    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied =
        apply_live_if_possible(&config, "set_uname", || apply_uname_from_config(&config))?;
    print_config_apply_result(&path, "HymoFS uname spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_clear_uname(cli: &Cli) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.uname = Default::default();
    config.hymofs.uname_release.clear();
    config.hymofs.uname_version.clear();

    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "clear_uname", || {
        hymofs::set_uname(&HymoSpoofUname::default())
    })?;
    print_config_apply_result(&path, "HymoFS uname spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_cmdline(cli: &Cli, value: &str) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.cmdline_value = value.to_string();

    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied =
        apply_live_if_possible(&config, "set_cmdline", || hymofs::set_cmdline_str(value))?;
    print_config_apply_result(&path, "HymoFS cmdline spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_clear_cmdline(cli: &Cli) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.cmdline_value.clear();

    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "clear_cmdline", || hymofs::set_cmdline_str(""))?;
    print_config_apply_result(&path, "HymoFS cmdline spoof setting", applied);
    Ok(())
}

pub fn handle_hymofs_set_hide_uids(cli: &Cli, uids: &[u32]) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.hide_uids = uids.to_vec();

    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "set_hide_uids", || hymofs::set_hide_uids(uids))?;
    print_config_apply_result(&path, "HymoFS hide_uids setting", applied);
    Ok(())
}

pub fn handle_hymofs_clear_hide_uids(cli: &Cli) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.hide_uids.clear();

    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied =
        apply_live_if_possible(&config, "clear_hide_uids", || hymofs::set_hide_uids(&[]))?;
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
    let mut config = load_effective_config(cli)?;
    let new_rule = HymoMapsRuleConfig {
        target_ino,
        target_dev,
        spoofed_ino,
        spoofed_dev,
        spoofed_pathname: path.to_path_buf(),
    };

    if let Some(existing) = config
        .hymofs
        .maps_rules
        .iter_mut()
        .find(|rule| rule.target_ino == target_ino && rule.target_dev == target_dev)
    {
        *existing = new_rule.clone();
    } else {
        config.hymofs.maps_rules.push(new_rule);
    }

    let path_out = save_hymofs_config_for_cli(cli, &config)?;
    let native_rule = HymoMapsRule::new(
        to_c_ulong(target_ino, "target_ino")?,
        to_c_ulong(target_dev, "target_dev")?,
        to_c_ulong(spoofed_ino, "spoofed_ino")?,
        to_c_ulong(spoofed_dev, "spoofed_dev")?,
        path,
    )?;
    let applied = apply_live_if_possible(&config, "add_maps_rule", || {
        hymofs::add_maps_rule(&native_rule)
    })?;
    print_config_apply_result(&path_out, "HymoFS maps rule", applied);
    Ok(())
}

pub fn handle_hymofs_clear_maps_rules(cli: &Cli) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.maps_rules.clear();

    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied = apply_live_if_possible(&config, "clear_maps_rules", hymofs::clear_maps_rules)?;
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
    let mut config = load_effective_config(cli)?;
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

    let path = save_hymofs_config_for_cli(cli, &config)?;
    let applied =
        apply_live_if_possible(&config, "upsert_kstat_rule", || apply_kstat_rule(&new_rule))?;
    print_config_apply_result(&path, "HymoFS kstat rule", applied);
    Ok(())
}

pub fn handle_hymofs_clear_kstat_rules_config(cli: &Cli) -> Result<()> {
    let mut config = load_effective_config(cli)?;
    config.hymofs.kstat_rules.clear();

    let path = save_hymofs_config_for_cli(cli, &config)?;
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
