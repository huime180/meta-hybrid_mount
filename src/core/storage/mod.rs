// Copyright (C) 2026 YuzakiKokuban <heibanbaize@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod backends;
mod ext4;

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use backends::TmpfsBackend;
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::mount::{MountPropagationFlags, UnmountFlags, mount_change, unmount as umount};

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::mount::umount_mgr::send_umountable;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::sys::mount::is_mounted;
use crate::{core::backend::StorageBackend, defs};

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
    let source_paths = vec![moduledir.to_path_buf()];
    let img_path = PathBuf::from(defs::MODULES_IMG_FILE);

    setup_with_sources(
        mnt_base,
        &source_paths,
        force_ext4,
        mount_source,
        disable_umount,
        &img_path,
    )
}

pub fn setup_with_sources(
    mnt_base: &Path,
    source_paths: &[PathBuf],
    force_ext4: bool,
    mount_source: &str,
    disable_umount: bool,
    img_path: &Path,
) -> Result<StorageHandle> {
    reset_image_files(img_path)?;
    detach_existing_mount(mnt_base);

    if !force_ext4 && try_setup_tmpfs(mnt_base, mount_source)? {
        crate::scoped_log!(trace, "storage", "backend select: mode=tmpfs");
        finalize_mount_setup(mnt_base, disable_umount);
        return Ok(StorageHandle::new(TmpfsBackend::new(mnt_base)));
    }

    let handle = ext4::setup_ext4_image(mnt_base, img_path, source_paths)?;
    finalize_mount_setup(mnt_base, disable_umount);

    Ok(StorageHandle::new(handle))
}

fn reset_image_files(img_path: &Path) -> Result<()> {
    let pattern = format!("{}*", img_path.display());
    for path in glob::glob(&pattern)?.flatten() {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

fn detach_existing_mount(mnt_base: &Path) {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = mnt_base;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if is_mounted(mnt_base) {
        let _ = umount(mnt_base, UnmountFlags::DETACH);
    }
}

fn finalize_mount_setup(path: &Path, disable_umount: bool) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let _ = mount_change(path, MountPropagationFlags::PRIVATE);

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if !disable_umount {
        let _ = send_umountable(path);
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = (path, disable_umount);
}

fn try_setup_tmpfs(target: &Path, mount_source: &str) -> Result<bool> {
    match crate::sys::mount::mount_tmpfs(target, mount_source) {
        Ok(()) => match crate::sys::fs::is_overlay_xattr_supported() {
            Ok(true) => return Ok(true),
            Ok(false) => {
                crate::scoped_log!(
                    warn,
                    "storage",
                    "tmpfs fallback: path={}, reason=overlay_xattr_unsupported",
                    target.display()
                );
                #[cfg(any(target_os = "linux", target_os = "android"))]
                let _ = umount(target, UnmountFlags::DETACH);
            }
            Err(err) => {
                crate::scoped_log!(
                    warn,
                    "storage",
                    "tmpfs fallback: path={}, reason=overlay_xattr_probe_failed, error={:#}",
                    target.display(),
                    err
                );
                #[cfg(any(target_os = "linux", target_os = "android"))]
                let _ = umount(target, UnmountFlags::DETACH);
            }
        },
        Err(err) => {
            crate::scoped_log!(
                warn,
                "storage",
                "tmpfs mount failed: path={}, source={}, fallback=ext4, error={:#}",
                target.display(),
                mount_source,
                err
            );
        }
    }
    Ok(false)
}
