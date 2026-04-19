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

use std::{
    collections::HashSet,
    ffi::CString,
    fs::{self, File},
    io::Write,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::fs::ioctl_ficlone;
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::fs::{Gid, Uid, chown};
use walkdir::WalkDir;

use crate::defs;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::sys::fs::{lgetfilecon, lsetfilecon};

#[derive(Debug, Default)]
pub struct SyncDirStats {
    pub has_mount_content: bool,
    pub opaque_dirs: Vec<PathBuf>,
}

fn is_managed_partition_path(relative: &Path, managed_partitions: &[String]) -> bool {
    relative
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .is_some_and(|name| managed_partitions.iter().any(|item| item == name))
}

pub fn atomic_write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, content: C) -> Result<()> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_dir_exists(parent)?;

    let mut tempfile = tempfile::Builder::new()
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "failed to create temp file for atomic write in {}",
                parent.display()
            )
        })?;

    tempfile.write_all(content.as_ref())?;

    fs::rename(tempfile.path(), path).with_context(|| {
        format!(
            "failed to atomically replace {} from {}",
            path.display(),
            tempfile.path().display()
        )
    })?;

    Ok(())
}

pub fn ensure_dir_exists<T: AsRef<Path>>(dir: T) -> Result<()> {
    if !dir.as_ref().exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(())
}

pub fn reflink_or_copy(src: &Path, dest: &Path) -> Result<u64> {
    let src_file = File::open(src)?;
    let dest_file = File::create(dest)?;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if ioctl_ficlone(&dest_file, &src_file).is_ok() {
        let metadata = src_file.metadata()?;
        let len = metadata.len();
        dest_file.set_permissions(metadata.permissions())?;
        return Ok(len);
    }
    drop(dest_file);
    drop(src_file);
    fs::copy(src, dest).map_err(|e| e.into())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn clone_selinux_context(src: &Path, dst: &Path) {
    match lgetfilecon(src).and_then(|con| lsetfilecon(dst, &con)) {
        Ok(()) => {}
        Err(err) => {
            crate::scoped_log!(
                warn,
                "sync",
                "clone selinux context skipped: src={}, dst={}, error={:#}",
                src.display(),
                dst.display(),
                err
            );
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn clone_selinux_context(_src: &Path, _dst: &Path) {}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn clone_ownership(src: &Path, dst: &Path) {
    let metadata = match fs::symlink_metadata(src) {
        Ok(metadata) => metadata,
        Err(err) => {
            crate::scoped_log!(
                warn,
                "sync",
                "clone ownership skipped: src={}, dst={}, error={}",
                src.display(),
                dst.display(),
                err
            );
            return;
        }
    };

    let result = if metadata.file_type().is_symlink() {
        let c_path = match CString::new(dst.as_os_str().as_encoded_bytes()) {
            Ok(path) => path,
            Err(err) => {
                crate::scoped_log!(
                    warn,
                    "sync",
                    "clone ownership skipped: src={}, dst={}, error={}",
                    src.display(),
                    dst.display(),
                    err
                );
                return;
            }
        };

        let rc = unsafe {
            libc::lchown(
                c_path.as_ptr(),
                metadata.uid() as libc::uid_t,
                metadata.gid() as libc::gid_t,
            )
        };

        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    } else {
        chown(
            dst,
            Some(Uid::from_raw(metadata.uid())),
            Some(Gid::from_raw(metadata.gid())),
        )
        .map_err(std::io::Error::from)
    };

    if let Err(err) = result {
        crate::scoped_log!(
            warn,
            "sync",
            "clone ownership skipped: src={}, dst={}, uid={}, gid={}, error={}",
            src.display(),
            dst.display(),
            metadata.uid(),
            metadata.gid(),
            err
        );
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn clone_ownership(_src: &Path, _dst: &Path) {}

fn make_device_node(path: &Path, mode: u32, rdev: u64) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())?;
    let dev = rdev as libc::dev_t;
    unsafe {
        if libc::mknod(c_path.as_ptr(), mode as libc::mode_t, dev) != 0 {
            let err = std::io::Error::last_os_error();
            bail!("mknod failed for {}: {}", path.display(), err);
        }
    }
    Ok(())
}

fn native_cp_r(
    src: &Path,
    dst: &Path,
    relative: &Path,
    managed_partitions: &[String],
    visited: &mut HashSet<(u64, u64)>,
    stats: &mut SyncDirStats,
) -> Result<()> {
    if !dst.exists() {
        if src.is_dir() {
            fs::create_dir_all(dst)?;
        }
        if let Ok(src_meta) = src.metadata() {
            let _ = fs::set_permissions(dst, src_meta.permissions());
        }
        clone_ownership(src, dst);
        clone_selinux_context(src, dst);
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let file_name = entry.file_name();
        if file_name.as_os_str() == defs::REPLACE_DIR_FILE_NAME {
            stats.opaque_dirs.push(dst.to_path_buf());
            continue;
        }
        let dst_path = dst.join(&file_name);
        let next_relative = relative.join(&file_name);

        let ft = entry.file_type()?;
        let metadata = fs::symlink_metadata(&src_path)?;
        let dev = metadata.dev();
        let ino = metadata.ino();

        if !ft.is_dir() && is_managed_partition_path(&next_relative, managed_partitions) {
            stats.has_mount_content = true;
        }

        if ft.is_dir() {
            if !visited.insert((dev, ino)) {
                continue;
            }
            native_cp_r(
                &src_path,
                &dst_path,
                &next_relative,
                managed_partitions,
                visited,
                stats,
            )?;
        } else if ft.is_symlink() {
            if dst_path.exists() {
                fs::remove_file(&dst_path)?;
            }
            let link_target = fs::read_link(&src_path)?;
            symlink(&link_target, &dst_path)?;
            clone_ownership(&src_path, &dst_path);
            clone_selinux_context(&src_path, &dst_path);
        } else if ft.is_char_device() || ft.is_block_device() || ft.is_fifo() {
            if dst_path.exists() {
                fs::remove_file(&dst_path)?;
            }
            let mode = metadata.permissions().mode();
            let rdev = metadata.rdev();
            make_device_node(&dst_path, mode, rdev)?;
            clone_ownership(&src_path, &dst_path);
            clone_selinux_context(&src_path, &dst_path);
        } else {
            reflink_or_copy(&src_path, &dst_path)?;
            clone_ownership(&src_path, &dst_path);
            clone_selinux_context(&src_path, &dst_path);
        }
    }
    Ok(())
}

pub fn sync_dir(src: &Path, dst: &Path, managed_partitions: &[String]) -> Result<SyncDirStats> {
    if !src.exists() {
        return Ok(SyncDirStats::default());
    }
    ensure_dir_exists(dst)?;
    let mut visited = HashSet::new();
    let mut stats = SyncDirStats::default();
    native_cp_r(
        src,
        dst,
        Path::new(""),
        managed_partitions,
        &mut visited,
        &mut stats,
    )
    .with_context(|| {
        format!(
            "Failed to natively sync {} to {}",
            src.display(),
            dst.display()
        )
    })?;
    Ok(stats)
}

pub fn prune_empty_dirs<P: AsRef<Path>>(root: P) -> Result<()> {
    let root = root.as_ref();
    if !root.exists() {
        return Ok(());
    }

    for entry in WalkDir::new(root)
        .min_depth(1)
        .contents_first(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_dir() {
            let path = entry.path();
            if fs::remove_dir(path).is_ok() {}
        }
    }
    Ok(())
}
