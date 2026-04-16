// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use anyhow::{Result, anyhow};

use crate::{conf::config, defs};

pub(super) fn build_managed_partitions(config: &config::Config) -> HashSet<String> {
    let mut managed_partitions: HashSet<String> = defs::BUILTIN_PARTITIONS
        .iter()
        .map(|partition| partition.to_string())
        .collect();
    managed_partitions.insert("system".to_string());
    managed_partitions.extend(config.partitions.iter().cloned());
    managed_partitions
}

pub(super) fn effective_stealth_enabled(config: &config::Config) -> bool {
    config.hymofs.enable_stealth || config.hymofs.enable_hidexattr
}

pub(super) fn effective_mount_hide_enabled(config: &config::Config) -> bool {
    config.hymofs.enable_mount_hide
        || config.hymofs.enable_hidexattr
        || config.hymofs.mount_hide.enabled
        || !config.hymofs.mount_hide.path_pattern.as_os_str().is_empty()
}

pub(super) fn effective_maps_spoof_enabled(config: &config::Config) -> bool {
    config.hymofs.enable_maps_spoof
        || config.hymofs.enable_hidexattr
        || !config.hymofs.maps_rules.is_empty()
}

pub(super) fn effective_statfs_spoof_enabled(config: &config::Config) -> bool {
    config.hymofs.enable_statfs_spoof
        || config.hymofs.enable_hidexattr
        || config.hymofs.statfs_spoof.enabled
        || !config.hymofs.statfs_spoof.path.as_os_str().is_empty()
        || config.hymofs.statfs_spoof.spoof_f_type != 0
}

pub(super) fn has_uname_spoof_config(config: &config::Config) -> bool {
    !config.hymofs.uname.sysname.is_empty()
        || !config.hymofs.uname.nodename.is_empty()
        || !config.hymofs.uname.release.is_empty()
        || !config.hymofs.uname.version.is_empty()
        || !config.hymofs.uname.machine.is_empty()
        || !config.hymofs.uname.domainname.is_empty()
        || !config.hymofs.uname_release.is_empty()
        || !config.hymofs.uname_version.is_empty()
}

pub(super) fn feature_supported(features: Option<i32>, required_feature: i32) -> bool {
    features
        .map(|bits| bits & required_feature != 0)
        .unwrap_or(false)
}

pub(super) fn to_c_ulong(value: u64, field_name: &str) -> Result<libc::c_ulong> {
    libc::c_ulong::try_from(value)
        .map_err(|_| anyhow!("{field_name} value {value} does not fit into c_ulong"))
}

pub(super) fn to_c_uint(value: u32, _field_name: &str) -> libc::c_uint {
    value
}

pub(super) fn to_c_long(value: i64, field_name: &str) -> Result<libc::c_long> {
    libc::c_long::try_from(value)
        .map_err(|_| anyhow!("{field_name} value {value} does not fit into c_long"))
}
