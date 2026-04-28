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

use const_format::concatcp;

pub const ADB_DIR: &str = "/data/adb";
pub const HYBRID_MOUNT_DIR: &str = concatcp!(ADB_DIR, "/hybrid-mount");
pub const MODULES_DIR: &str = concatcp!(ADB_DIR, "/modules");
pub const HYBRID_MOUNT_MODULE_DIR: &str = concatcp!(MODULES_DIR, "/hybrid_mount");

pub const MODULES_IMG_FILE: &str = concatcp!(HYBRID_MOUNT_DIR, "/modules.img");
pub const KASUMI_IMG_FILE: &str = concatcp!(HYBRID_MOUNT_DIR, "/kasumi.img");
pub const RUN_DIR: &str = concatcp!(HYBRID_MOUNT_DIR, "/run/");
pub const STATE_FILE: &str = concatcp!(RUN_DIR, "daemon_state.json");
pub const SYSTEM_RW_DIR: &str = concatcp!(HYBRID_MOUNT_DIR, "/rw");
pub const CONFIG_FILE: &str = concatcp!(HYBRID_MOUNT_DIR, "/config.toml");
pub const USER_HIDE_RULES_FILE: &str = concatcp!(HYBRID_MOUNT_DIR, "/user_hide_rules.json");
pub const MODULE_PROP_FILE: &str = concatcp!(HYBRID_MOUNT_MODULE_DIR, "/module.prop");
pub const KASUMI_MIRROR_DIR: &str = "/dev/kasumi_mirror";
pub const KASUMI_LKM_DIR: &str = concatcp!(HYBRID_MOUNT_MODULE_DIR, "/kasumi_lkm");
pub const KASUMI_LKM_MODULE_NAME: &str = "kasumi_lkm";

pub const DISABLE_FILE_NAME: &str = "disable";
pub const REMOVE_FILE_NAME: &str = "remove";
pub const MOUNT_ERROR_FILE_NAME: &str = "mount_error";
pub const SKIP_MOUNT_FILE_NAME: &str = "skip_mount";
pub const REPLACE_DIR_FILE_NAME: &str = ".replace";
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const REPLACE_DIR_XATTR: &str = "trusted.overlay.opaque";

pub const IGNORE_UNMOUNT_PARTITIONS: &[&str] = &[
    "/vendor/lib",
    "/vendor/lib64",
    "/system/lib",
    "/system/lib64",
];

pub const MANAGED_PARTITIONS: &[&str] = &[
    "system",
    "vendor",
    "product",
    "system_ext",
    "odm",
    "oem",
    "apex",
];
