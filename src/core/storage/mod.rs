// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

mod backends;
mod ext4;

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use backends::TmpfsBackend;
use rustix::mount::{MountPropagationFlags, UnmountFlags, mount_change, unmount as umount};

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::mount::umount_mgr::send_umountable;
use crate::{core::backend::StorageBackend, defs, sys::mount::is_mounted};

pub struct StorageHandle {
    pub backend: Box<dyn StorageBackend>,
}

impl StorageHandle {
    pub fn new(backend: impl StorageBackend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
        }
    }

    pub fn commit(&mut self, disable_umount: bool) -> Result<()> {
        self.backend.commit(disable_umount)
    }

    pub fn mount_point(&self) -> &Path {
        self.backend.mount_point()
    }

    pub fn mode(&self) -> &str {
        self.backend.mode()
    }
}

pub fn setup(
    mnt_base: &Path,
    moduledir: &Path,
    force_ext4: bool,
    mount_source: &str,
    disable_umount: bool,
) -> Result<StorageHandle> {
    let img_path = PathBuf::from(defs::MODULES_IMG_FILE);

    reset_image_files()?;
    detach_existing_mount(mnt_base);

    if !force_ext4 && try_setup_tmpfs(mnt_base, mount_source)? {
        log::trace!("tmpfs mode is supported");
        finalize_mount_setup(mnt_base, disable_umount);
        return Ok(StorageHandle::new(TmpfsBackend::new(mnt_base)));
    }

    let handle = ext4::setup_ext4_image(mnt_base, &img_path, moduledir)?;
    finalize_mount_setup(mnt_base, disable_umount);

    Ok(StorageHandle::new(handle))
}

fn reset_image_files() -> Result<()> {
    for path in glob::glob(&format!("{}*", defs::MODULES_IMG_FILE))?.flatten() {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

fn detach_existing_mount(mnt_base: &Path) {
    if is_mounted(mnt_base) {
        let _ = umount(mnt_base, UnmountFlags::DETACH);
    }
}

fn finalize_mount_setup(path: &Path, disable_umount: bool) {
    let _ = mount_change(path, MountPropagationFlags::PRIVATE);

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if !disable_umount {
        let _ = send_umountable(path);
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = disable_umount;
}

fn try_setup_tmpfs(target: &Path, mount_source: &str) -> Result<bool> {
    match crate::sys::mount::mount_tmpfs(target, mount_source) {
        Ok(()) => match crate::sys::fs::is_overlay_xattr_supported() {
            Ok(true) => return Ok(true),
            Ok(false) => {
                log::warn!(
                    "tmpfs mounted at {} but overlay xattr is unsupported, fallback to ext4 backend",
                    target.display()
                );
                let _ = umount(target, UnmountFlags::DETACH);
            }
            Err(err) => {
                log::warn!(
                    "tmpfs mounted at {} but failed to probe overlay xattr support: {:#}, fallback to ext4 backend",
                    target.display(),
                    err
                );
                let _ = umount(target, UnmountFlags::DETACH);
            }
        },
        Err(err) => {
            log::warn!(
                "failed to mount tmpfs at {} (source={}): {:#}, fallback to ext4 backend",
                target.display(),
                mount_source,
                err
            );
        }
    }
    Ok(false)
}
