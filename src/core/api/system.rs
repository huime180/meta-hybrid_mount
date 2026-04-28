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

use std::{ffi::CString, fs, os::unix::ffi::OsStrExt, path::PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::{conf::config::Config, core::runtime_state::RuntimeState, partitions};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PartitionInfo {
    pub name: String,
    pub mount_point: String,
    pub fs_type: String,
    pub is_read_only: bool,
    pub exists_as_symlink: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StorageInfo {
    pub path: String,
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MountStatsPayload {
    pub total_mounts: usize,
    pub successful_mounts: usize,
    pub failed_mounts: usize,
    pub tmpfs_created: usize,
    pub files_mounted: usize,
    pub dirs_mounted: usize,
    pub symlinks_created: usize,
    pub overlayfs_mounts: usize,
    pub success_rate: f64,
}

impl From<&crate::core::runtime_state::MountStatistics> for MountStatsPayload {
    fn from(stats: &crate::core::runtime_state::MountStatistics) -> Self {
        Self {
            total_mounts: stats.total_mounts,
            successful_mounts: stats.successful_mounts,
            failed_mounts: stats.failed_mounts,
            tmpfs_created: stats.tmpfs_created,
            files_mounted: stats.files_mounted,
            dirs_mounted: stats.dirs_mounted,
            symlinks_created: stats.symlinks_created,
            overlayfs_mounts: stats.overlayfs_mounts,
            success_rate: stats.success_rate(),
        }
    }
}

#[derive(Debug)]
struct MountEntry {
    mount_point: PathBuf,
    fs_type: String,
    is_read_only: bool,
}

pub fn build_storage_payload(state: &RuntimeState) -> StorageInfo {
    let mount_path = state.mount_point.clone();
    let path_str = mount_path.display().to_string();

    if mount_path.as_os_str().is_empty() || !mount_path.exists() {
        return StorageInfo {
            path: path_str,
            pid: state.pid,
            error: Some("Not mounted".to_string()),
            warning: None,
            size: None,
            used: None,
            avail: None,
            percent: None,
            mode: state
                .storage_mode
                .is_empty()
                .then_some("unknown".to_string())
                .or_else(|| Some(state.storage_mode.clone())),
        };
    }

    match statvfs_usage(&mount_path) {
        Ok((total_bytes, used_bytes, free_bytes, percent)) => StorageInfo {
            path: path_str,
            pid: state.pid,
            error: None,
            warning: (total_bytes == 0).then_some("Zero size detected".to_string()),
            size: Some(format_size(total_bytes)),
            used: Some(format_size(used_bytes)),
            avail: Some(format_size(free_bytes)),
            percent: Some(percent),
            mode: Some(if state.storage_mode.is_empty() {
                "unknown".to_string()
            } else {
                state.storage_mode.clone()
            }),
        },
        Err(err) => StorageInfo {
            path: path_str,
            pid: state.pid,
            error: Some(format!("statvfs failed: {err:#}")),
            warning: None,
            size: None,
            used: None,
            avail: None,
            percent: None,
            mode: Some(if state.storage_mode.is_empty() {
                "unknown".to_string()
            } else {
                state.storage_mode.clone()
            }),
        },
    }
}

pub fn build_mount_stats_payload(state: &RuntimeState) -> MountStatsPayload {
    MountStatsPayload::from(&state.mount_stats)
}

pub fn build_partitions_payload(config: &Config) -> Vec<PartitionInfo> {
    detect_partitions(config).unwrap_or_default()
}

#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn statvfs_usage(path: &std::path::Path) -> Result<(u64, u64, u64, f64)> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("invalid storage path {}", path.display()))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("statvfs failed for {}", path.display()));
    }

    let stats = unsafe { stats.assume_init() };
    let block_size = if stats.f_frsize > 0 {
        stats.f_frsize
    } else {
        stats.f_bsize
    };
    let block_size = u64::from(block_size);
    let total_bytes = u64::from(stats.f_blocks).saturating_mul(block_size);
    let free_bytes = u64::from(stats.f_bavail).saturating_mul(block_size);
    let used_bytes =
        total_bytes.saturating_sub(u64::from(stats.f_bfree).saturating_mul(block_size));
    let percent = if total_bytes > 0 {
        used_bytes as f64 * 100.0 / total_bytes as f64
    } else {
        0.0
    };

    Ok((total_bytes, used_bytes, free_bytes, percent))
}

fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];

    if bytes < 1024 {
        return format!("{bytes}B");
    }

    let mut value = bytes as f64;
    let mut unit_idx = 0usize;
    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }

    if value >= 100.0 || (value - value.round()).abs() < 0.05 {
        format!("{value:.0}{}", UNITS[unit_idx])
    } else {
        format!("{value:.1}{}", UNITS[unit_idx])
    }
}

fn detect_partitions(config: &Config) -> Result<Vec<PartitionInfo>> {
    let mount_entries = read_mount_entries()?;
    let mut partitions = Vec::new();

    for name in partitions::managed_partition_names(&config.moduledir, &config.partitions) {
        let mount_point = PathBuf::from("/").join(&name);
        let metadata = match fs::symlink_metadata(&mount_point) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let exists_as_symlink = metadata.file_type().is_symlink();
        let resolved = if exists_as_symlink {
            fs::canonicalize(&mount_point).unwrap_or_else(|_| mount_point.clone())
        } else {
            mount_point.clone()
        };

        let match_entry = mount_entries
            .iter()
            .find(|entry| entry.mount_point == mount_point || entry.mount_point == resolved);

        partitions.push(PartitionInfo {
            name,
            mount_point: mount_point.display().to_string(),
            fs_type: match_entry
                .map(|entry| entry.fs_type.clone())
                .unwrap_or_default(),
            is_read_only: match_entry.is_some_and(|entry| entry.is_read_only),
            exists_as_symlink,
        });
    }

    Ok(partitions)
}

fn read_mount_entries() -> Result<Vec<MountEntry>> {
    let content =
        fs::read_to_string("/proc/self/mounts").context("failed to read /proc/self/mounts")?;
    let mut entries = Vec::new();

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let _device = parts.next();
        let Some(mount_point) = parts.next() else {
            continue;
        };
        let Some(fs_type) = parts.next() else {
            continue;
        };
        let Some(options) = parts.next() else {
            continue;
        };

        entries.push(MountEntry {
            mount_point: PathBuf::from(mount_point),
            fs_type: fs_type.to_string(),
            is_read_only: options.split(',').any(|option| option == "ro"),
        });
    }

    Ok(entries)
}
