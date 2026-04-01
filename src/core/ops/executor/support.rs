// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use crate::{
    conf::config,
    core::ops::planner::{MountPlan, OverlayOperation},
    mount::magic_mount,
    utils,
};

pub(super) fn overlay_fallback_allowed(config: &config::Config) -> bool {
    config.enable_overlay_fallback
}

pub(super) fn resolve_magic_failure_modules(
    err: &anyhow::Error,
    fallback: &[String],
) -> Vec<String> {
    if let Some(magic_failure) = err.downcast_ref::<magic_mount::MagicMountModuleFailure>()
        && !magic_failure.module_ids.is_empty()
    {
        return magic_failure.module_ids.clone();
    }
    fallback.to_vec()
}

pub(super) fn is_symlink_loop_mount_error(err: &anyhow::Error) -> bool {
    let mut cursor = Some(err.as_ref() as &(dyn std::error::Error + 'static));
    while let Some(current) = cursor {
        let msg = current.to_string();
        if msg.contains("Too many symbolic links") || msg.contains("os error 40") {
            return true;
        }
        cursor = current.source();
    }
    false
}

pub(super) fn collect_involved_modules(op: &OverlayOperation) -> Vec<String> {
    let mut involved_modules: Vec<String> = op
        .lowerdirs
        .iter()
        .filter_map(|p| utils::extract_module_id(p))
        .collect();
    involved_modules.sort();
    involved_modules.dedup();
    involved_modules
}

pub(super) fn collect_overlay_modules_for_magic_fallback(plan: &MountPlan) -> HashSet<String> {
    let mut fallback_ids = HashSet::new();
    for op in &plan.overlay_ops {
        fallback_ids.extend(collect_involved_modules(op));
    }
    fallback_ids
}
