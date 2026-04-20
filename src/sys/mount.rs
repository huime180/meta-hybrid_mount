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

use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};
#[cfg(any(target_os = "linux", target_os = "android"))]
use procfs::process::Process;
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::mount::{MountFlags, mount};

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::sys::fs::ensure_dir_exists;

pub fn detect_mount_source() -> String {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if ksu::version().is_some() {
            return "KSU".to_string();
        }
    }
    "APatch".to_string()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn is_mounted<P: AsRef<Path>>(path: P) -> bool {
    let Some(path_str) = path.as_ref().to_str() else {
        return false;
    };

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
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
    }

    false
}

#[cfg(any(target_os = "linux", target_os = "android"))]
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

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn mount_tmpfs(_target: &Path, _source: &str) -> Result<()> {
    bail!("tmpfs mounting is only supported on linux/android")
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
