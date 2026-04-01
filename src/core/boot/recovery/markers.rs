// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::defs;

pub(super) struct MarkOutcome {
    pub(super) newly_marked: Vec<String>,
    pub(super) already_marked: Vec<String>,
    pub(super) unknown_modules: Vec<String>,
}

pub(super) fn mark_failed_modules(
    module_ids: &[String],
    module_dirs: &HashMap<String, PathBuf>,
    auto_skipped: &mut HashSet<String>,
) -> Result<MarkOutcome> {
    let mut newly_marked = Vec::new();
    let mut already_marked = Vec::new();
    let mut unknown_modules = Vec::new();

    for module_id in module_ids {
        if auto_skipped.contains(module_id) {
            already_marked.push(module_id.clone());
            continue;
        }
        if let Some(module_dir) = module_dirs.get(module_id) {
            create_skip_mount_marker(module_dir)?;
            auto_skipped.insert(module_id.clone());
            newly_marked.push(module_id.clone());
        } else {
            unknown_modules.push(module_id.clone());
        }
    }

    Ok(MarkOutcome {
        newly_marked,
        already_marked,
        unknown_modules,
    })
}

pub(super) fn list_module_dirs(base: &Path) -> Result<HashMap<String, PathBuf>> {
    let mut modules = HashMap::new();
    if !base.exists() {
        return Ok(modules);
    }

    for entry in std::fs::read_dir(base)?.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        if crate::core::inventory::is_reserved_module_dir(&id) {
            continue;
        }
        modules.insert(id, path);
    }

    Ok(modules)
}

fn create_skip_mount_marker(module_dir: &Path) -> Result<()> {
    let marker = module_dir.join(defs::SKIP_MOUNT_FILE_NAME);
    log::info!(
        "[stage:recovery] creating skip marker at {}",
        marker.display()
    );
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&marker)
        .with_context(|| format!("Failed to create {}", marker.display()))?;
    log::debug!(
        "[stage:recovery] skip marker ready for module dir {}",
        module_dir.display()
    );
    Ok(())
}
