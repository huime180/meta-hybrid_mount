// Copyright (C) 2026 YuzakiKokuban <heibanbaize@gmail.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

use std::path::Path;

use anyhow::Result;

use crate::{
    conf::config::Config,
    core::{
        module_status,
        ops::{executor::ExecutionResult, plan::MountPlan},
        runtime_state::RuntimeState,
    },
    defs,
    mount::hymofs,
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
    _plan: &MountPlan,
    result: &ExecutionResult,
) -> RuntimeState {
    let previous_state = RuntimeState::load().unwrap_or_default();
    let hymofs = hymofs::collect_runtime_info(config);
    let mut state = RuntimeState::new(
        storage_mode.to_string(),
        mount_point.to_path_buf(),
        result.overlay_module_ids.clone(),
        result.magic_module_ids.clone(),
        result.hymofs_module_ids.clone(),
        collect_active_mounts(result),
        result.mount_stats.clone(),
        hymofs,
        defs::DAEMON_LOG_FILE.into(),
    );
    state.mount_error_modules = previous_state.mount_error_modules;
    state.mount_error_reasons = previous_state.mount_error_reasons;
    clear_recovered_mount_errors(&mut state);
    state.skip_mount_modules = collect_skip_mount_modules(config);
    state
}

fn collect_active_mounts(result: &ExecutionResult) -> Vec<String> {
    let mut active_mounts = result.overlay_partitions.clone();

    if result.hymofs_runtime_enabled {
        active_mounts.push("hymofs".to_string());
    }

    active_mounts.sort();
    active_mounts.dedup();
    active_mounts
}

fn collect_skip_mount_modules(config: &Config) -> Vec<String> {
    let mut modules = Vec::new();
    let Ok(entries) = std::fs::read_dir(&config.moduledir) else {
        return modules;
    };

    for entry in entries.flatten() {
        let module_dir = entry.path();
        if !module_dir.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        if crate::core::inventory::is_reserved_module_dir(&id) {
            continue;
        }
        if module_dir.join(defs::SKIP_MOUNT_FILE_NAME).exists() {
            modules.push(id);
        }
    }

    modules.sort();
    modules
}

fn clear_recovered_mount_errors(state: &mut RuntimeState) {
    let mounted: std::collections::HashSet<String> = state
        .mounted_module_ids()
        .into_iter()
        .map(ToString::to_string)
        .collect();
    state
        .mount_error_modules
        .retain(|module_id| !mounted.contains(module_id));
    state
        .mount_error_reasons
        .retain(|module_id, _| !mounted.contains(module_id));
}
