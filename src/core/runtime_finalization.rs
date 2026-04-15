// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use anyhow::Result;

use crate::{
    conf::config::Config,
    core::{
        api, module_status,
        ops::{executor::ExecutionResult, planner::MountPlan},
        runtime_state::{HymoFsRuntimeInfo, RuntimeState},
        user_hide_rules,
    },
    defs,
    sys::{
        hymofs::{self, HymoFsStatus},
        lkm,
    },
};

pub fn finalize(
    config: &Config,
    storage_mode: &str,
    mount_point: &Path,
    plan: &MountPlan,
    result: &ExecutionResult,
) -> Result<()> {
    module_status::update_description(
        storage_mode,
        result.overlay_module_ids.len(),
        result.magic_module_ids.len(),
        result.hymofs_module_ids.len(),
    );

    let state = build_runtime_state(config, storage_mode, mount_point, plan, result);
    if let Err(err) = state.save() {
        crate::scoped_log!(warn, "finalize", "save runtime state failed: {:#}", err);
    }

    Ok(())
}

fn build_runtime_state(
    config: &Config,
    storage_mode: &str,
    mount_point: &Path,
    plan: &MountPlan,
    result: &ExecutionResult,
) -> RuntimeState {
    let hymofs = collect_hymofs_runtime_info(config);
    RuntimeState::new(
        storage_mode.to_string(),
        mount_point.to_path_buf(),
        result.overlay_module_ids.clone(),
        result.magic_module_ids.clone(),
        result.hymofs_module_ids.clone(),
        collect_active_mounts(plan),
        result.mount_stats.clone(),
        hymofs,
        defs::DAEMON_LOG_FILE.into(),
    )
}

fn collect_hymofs_runtime_info(config: &Config) -> HymoFsRuntimeInfo {
    if !config.hymofs.enabled {
        return HymoFsRuntimeInfo {
            status: "disabled".to_string(),
            available: false,
            lkm_loaded: lkm::is_loaded(),
            lkm_autoload: config.hymofs.lkm_autoload,
            lkm_kmi_override: config.hymofs.lkm_kmi_override.clone(),
            lkm_current_kmi: lkm::current_kmi(),
            lkm_dir: config.hymofs.lkm_dir.clone(),
            protocol_version: None,
            feature_bits: None,
            feature_names: Vec::new(),
            hooks: Vec::new(),
            rule_count: 0,
            user_hide_rule_count: user_hide_rules::user_hide_rule_count(),
            mirror_path: config.hymofs.mirror_path.clone(),
        };
    }

    let status = hymofs::check_status();
    let protocol_version = hymofs::get_protocol_version().ok();
    let feature_bits = hymofs::get_features().ok();
    let feature_names = feature_bits.map(hymofs::feature_names).unwrap_or_default();
    let hooks = hymofs::get_hooks()
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

    HymoFsRuntimeInfo {
        status: hymofs::status_name(status).to_string(),
        available: status == HymoFsStatus::Available,
        lkm_loaded: lkm::is_loaded(),
        lkm_autoload: config.hymofs.lkm_autoload,
        lkm_kmi_override: config.hymofs.lkm_kmi_override.clone(),
        lkm_current_kmi: lkm::current_kmi(),
        lkm_dir: config.hymofs.lkm_dir.clone(),
        protocol_version,
        feature_bits,
        feature_names,
        hooks,
        rule_count,
        user_hide_rule_count: user_hide_rules::user_hide_rule_count(),
        mirror_path: config.hymofs.mirror_path.clone(),
    }
}

fn collect_active_mounts(plan: &MountPlan) -> Vec<String> {
    let mut active_mounts: Vec<String> = plan
        .overlay_ops
        .iter()
        .map(|op| op.partition_name.clone())
        .collect();

    if !plan.hymofs_module_ids.is_empty() {
        active_mounts.push("hymofs".to_string());
    }

    active_mounts.sort();
    active_mounts.dedup();
    active_mounts
}
