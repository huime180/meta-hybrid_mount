// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};
use procfs::process::Process;
use rustix::mount::{MountFlags, mount};

use crate::sys::fs::ensure_dir_exists;

pub fn detect_mount_source() -> String {
    if ksu::version().is_some() {
        return "KSU".to_string();
    }
    "APatch".to_string()
}

pub fn is_mounted<P: AsRef<Path>>(path: P) -> bool {
    let Some(path_str) = path.as_ref().to_str() else {
        return false;
    };

    let search = if path_str == "/" {
        "/"
    } else {
        path_str.trim_end_matches('/')
    };

    if let Ok(process) = Process::myself()
        && let Ok(mountinfo) = process.mountinfo()
    {
        return mountinfo
            .into_iter()
            .any(|m| m.mount_point.to_string_lossy() == search);
    }

    false
}

pub fn mount_tmpfs(target: &Path, source: &str) -> Result<()> {
    ensure_dir_exists(target)?;
    mount(
        source,
        target,
        c"tmpfs",
        MountFlags::empty(),
        Some(c"mode=0755"),
    )
    .context("Failed to mount tmpfs")?;
    Ok(())
}

pub fn repair_image(image_path: &Path) -> Result<()> {
    let status = Command::new("e2fsck")
        .args(["-y", "-f"])
        .arg(image_path)
        .status()
        .context("Failed to execute e2fsck")?;

    match status.code() {
        Some(code) if code > 2 => bail!("e2fsck failed with exit code: {}", code),
        None => bail!("e2fsck terminated by signal"),
        _ => {}
    }
    Ok(())
}
