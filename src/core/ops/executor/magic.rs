// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashSet, path::Path};

use anyhow::Result;

use crate::{conf::config, mount::magic_mount};

pub(super) fn mount_magic(
    ids: &HashSet<String>,
    config: &config::Config,
    tempdir: &Path,
) -> Result<Vec<String>> {
    let magic_ws_path = tempdir.join("magic_workspace");

    log::debug!(
        "[executor] mount_magic preparing workspace: {}",
        magic_ws_path.display()
    );

    if !magic_ws_path.exists() {
        std::fs::create_dir_all(&magic_ws_path)?;
    }

    magic_mount::magic_mount(
        &magic_ws_path,
        tempdir,
        &config.mountsource,
        &config.partitions,
        ids.clone(),
        !config.disable_umount,
    )?;

    log::debug!("[executor] mount_magic done: module_count={}", ids.len());

    Ok(ids.iter().cloned().collect())
}
