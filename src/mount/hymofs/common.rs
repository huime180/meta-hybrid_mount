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

use anyhow::{Result, anyhow};

use crate::{conf::config, partitions};

pub(super) fn build_managed_partitions(
    config: &config::Config,
) -> std::collections::HashSet<String> {
    partitions::managed_partition_set(&config.moduledir, &config.partitions)
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
