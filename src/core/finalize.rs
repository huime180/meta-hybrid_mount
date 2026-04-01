// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use anyhow::Result;

use crate::core::{
    module_description,
    ops::{executor::ExecutionResult, planner::MountPlan},
    state::RuntimeState,
};

pub fn finalize(
    storage_mode: &str,
    mount_point: &Path,
    plan: &MountPlan,
    result: &ExecutionResult,
) -> Result<()> {
    module_description::update_description(
        storage_mode,
        result.overlay_module_ids.len(),
        result.magic_module_ids.len(),
    );

    let state = build_runtime_state(storage_mode, mount_point, plan, result);
    if let Err(err) = state.save() {
        log::warn!("[stage:finalize] failed to save runtime state: {:#}", err);
    }

    Ok(())
}

fn build_runtime_state(
    storage_mode: &str,
    mount_point: &Path,
    plan: &MountPlan,
    result: &ExecutionResult,
) -> RuntimeState {
    RuntimeState::new(
        storage_mode.to_string(),
        mount_point.to_path_buf(),
        result.overlay_module_ids.clone(),
        result.magic_module_ids.clone(),
        collect_active_mounts(plan),
    )
}

fn collect_active_mounts(plan: &MountPlan) -> Vec<String> {
    let mut active_mounts: Vec<String> = plan
        .overlay_ops
        .iter()
        .map(|op| op.partition_name.clone())
        .collect();

    active_mounts.sort();
    active_mounts.dedup();
    active_mounts
}
