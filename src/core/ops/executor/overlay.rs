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

use super::fallback;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::mount::umount_mgr;
use crate::{
    conf::config,
    core::{hymofs_coordinator::HymofsCoordinator, ops::plan::OverlayOperation},
    defs,
    mount::overlayfs,
};

pub(super) fn mount_overlay(
    op: &OverlayOperation,
    config: &config::Config,
    hymofs: &HymofsCoordinator<'_>,
) -> Result<Vec<String>> {
    let involved_modules = fallback::collect_involved_modules(op);

    crate::scoped_log!(
        debug,
        "executor:overlay",
        "prepare: target={}, partition={}, modules={}",
        op.target,
        op.partition_name,
        if involved_modules.is_empty() {
            "<unknown>".to_string()
        } else {
            involved_modules.join(",")
        }
    );

    let lowerdir_strings: Vec<String> = op
        .lowerdirs
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    let rw_root = Path::new(defs::SYSTEM_RW_DIR);
    let part_rw = rw_root.join(&op.partition_name);
    let upper = part_rw.join("upperdir");
    let work = part_rw.join("workdir");

    let (upper_opt, work_opt) = if upper.exists() && work.exists() {
        (Some(upper), Some(work))
    } else {
        (None, None)
    };

    let mut mount_source = config.mountsource.clone();

    if defs::IGNORE_UNMOUNT_PARTITIONS
        .iter()
        .any(|s| s.trim() == op.target.trim())
    {
        mount_source = "overlay".to_string();
    }

    overlayfs::overlayfs::mount_overlay(
        &op.target,
        &lowerdir_strings,
        work_opt,
        upper_opt,
        &mount_source,
    )?;

    crate::scoped_log!(
        debug,
        "executor:overlay",
        "complete: target={}, mount_source={}",
        op.target,
        mount_source
    );

    hymofs.hide_overlay_xattrs(Path::new(&op.target));

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if !config.disable_umount {
        let _ = umount_mgr::send_umountable(&op.target);
    }

    Ok(involved_modules)
}
