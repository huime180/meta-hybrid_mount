// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::HashSet,
    fs,
    io::ErrorKind,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};
use jwalk::WalkDir;
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::mount::{UnmountFlags, unmount as umount};

use crate::{
    core::storage::backends::Ext4Backend,
    mount::overlayfs::utils as overlay_utils,
    sys::{
        fs::{ensure_dir_exists, lgetfilecon, lsetfilecon},
        nuke,
    },
};

const DEFAULT_SELINUX_CONTEXT: &str = "u:object_r:system_file:s0";

pub(super) fn setup_ext4_image(
    target: &Path,
    img_path: &Path,
    source_paths: &[PathBuf],
) -> Result<Ext4Backend> {
    crate::scoped_log!(trace, "storage:ext4", "backend select: mode=ext4");
    let total_size = calculate_total_size(source_paths)?;
    let min_size = 64 * 1024 * 1024;
    let grow_size = std::cmp::max((total_size as f64 * 1.2) as u64, min_size);

    fs::File::create(img_path)?.set_len(grow_size)?;
    format_ext4_image(img_path)?;
    check_image(img_path)?;
    let _ = lsetfilecon(img_path, "u:object_r:ksu_file:s0");
    ensure_dir_exists(target)?;

    mount_ext4_with_repair(img_path, target)?;
    reset_mount_state(target)?;
    relabel_mount_tree(target);

    Ok(Ext4Backend::new(target))
}

fn calculate_total_size(paths: &[PathBuf]) -> Result<u64> {
    let mut total_size = 0;
    let mut visited_node_map = HashSet::new();
    let mut stack: Vec<PathBuf> = paths.iter().filter(|path| path.exists()).cloned().collect();

    while let Some(current) = stack.pop() {
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
                crate::scoped_log!(
                    warn,
                    "storage:ext4",
                    "size skip: path={}, reason=symlink_loop, error={}",
                    current.display(),
                    err
                );
                continue;
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                crate::scoped_log!(
                    debug,
                    "storage:ext4",
                    "size skip: path={}, reason=not_found",
                    current.display()
                );
                continue;
            }
            Err(err) => return Err(err.into()),
        };

        let file_type = metadata.file_type();
        if file_type.is_file() {
            let dev = metadata.dev();
            let ino = metadata.ino();

            if !visited_node_map.insert((dev, ino)) {
                continue;
            }

            total_size += metadata.blocks() * 512;
        } else if file_type.is_dir() {
            match current.read_dir() {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        stack.push(entry.path());
                    }
                }
                Err(_) => {
                    crate::scoped_log!(
                        error,
                        "storage:ext4",
                        "read dir failed: path={}",
                        current.display()
                    )
                }
            }
        } else if file_type.is_symlink() {
            crate::scoped_log!(
                debug,
                "storage:ext4",
                "size skip: path={}, reason=symlink",
                current.display()
            );
        }
    }
    Ok(total_size)
}

fn format_ext4_image(img_path: &Path) -> Result<()> {
    let result = Command::new("mkfs.ext4")
        .arg("-b")
        .arg("1024")
        .arg("-i")
        .arg("4096")
        .arg(img_path)
        .stdout(std::process::Stdio::piped())
        .output()?;

    ensure!(result.status.success(), "Failed to format ext4 image");
    Ok(())
}

fn check_image(img_path: &Path) -> Result<()> {
    let path_str = img_path.to_str().context("Invalid path string")?;
    let status = Command::new("e2fsck")
        .args(["-yf", path_str])
        .status()
        .with_context(|| format!("Failed to exec e2fsck {}", img_path.display()))?;

    let code = status
        .code()
        .context("e2fsck exited without an exit code (terminated by signal)")?;

    ensure!(
        (0..=3).contains(&code),
        "e2fsck failed for {} with exit code {}",
        img_path.display(),
        code
    );
    Ok(())
}

fn mount_ext4_with_repair(img_path: &Path, target: &Path) -> Result<()> {
    if overlay_utils::mount_ext4(img_path, target).is_err() {
        if crate::sys::mount::repair_image(img_path).is_ok() {
            overlay_utils::mount_ext4(img_path, target)?;
        } else {
            bail!("Failed to repair modules.img");
        }
    }
    Ok(())
}

fn reset_mount_state(target: &Path) -> Result<()> {
    if nuke::nuke_path(target).is_err() {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        umount(target, UnmountFlags::DETACH)?;
    }
    Ok(())
}

fn live_context_candidates(relative: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut current = if relative.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        Path::new("/").join(relative)
    };

    loop {
        candidates.push(current.clone());

        if current == Path::new("/") {
            break;
        }

        let Some(parent) = current.parent() else {
            break;
        };
        current = if parent.as_os_str().is_empty() {
            PathBuf::from("/")
        } else {
            parent.to_path_buf()
        };
    }

    candidates
}

fn best_effort_live_context(relative: &Path) -> String {
    for candidate in live_context_candidates(relative) {
        if let Ok(context) = lgetfilecon(&candidate) {
            return context;
        }
    }

    DEFAULT_SELINUX_CONTEXT.to_string()
}

fn relabel_mount_tree(target: &Path) {
    for dir_entry in WalkDir::new(target).parallelism(jwalk::Parallelism::Serial) {
        if let Some(path) = dir_entry.ok().map(|dir_entry| dir_entry.path()) {
            let relative = path.strip_prefix(target).unwrap_or(path.as_path());
            let context = best_effort_live_context(relative);
            let _ = lsetfilecon(&path, &context);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::live_context_candidates;

    #[test]
    fn live_context_candidates_walk_exact_path_then_parents() {
        let candidates = live_context_candidates(Path::new("product/overlay/Foo.apk"));

        assert_eq!(
            candidates,
            vec![
                Path::new("/product/overlay/Foo.apk").to_path_buf(),
                Path::new("/product/overlay").to_path_buf(),
                Path::new("/product").to_path_buf(),
                Path::new("/").to_path_buf(),
            ]
        );
    }
}
