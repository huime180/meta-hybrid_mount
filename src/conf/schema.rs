// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashMap, path::PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::defs;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OverlayMode {
    Tmpfs,
    #[default]
    Ext4,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultMode {
    #[default]
    Overlay,
    Magic,
    Hymofs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MountMode {
    #[default]
    Overlay,
    Magic,
    Hymofs,
    Ignore,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleRules {
    #[serde(default)]
    pub default_mode: MountMode,
    #[serde(default)]
    pub paths: HashMap<String, MountMode>,
}

impl ModuleRules {
    pub fn get_mode(&self, relative_path: &str) -> MountMode {
        let mut best_match = None;
        let mut best_len = 0usize;

        for (path, mode) in &self.paths {
            let is_exact = relative_path == path;
            let is_prefix = relative_path.len() > path.len()
                && relative_path.starts_with(path)
                && relative_path.as_bytes().get(path.len()) == Some(&b'/');

            if (is_exact || is_prefix) && path.len() >= best_len {
                best_match = Some(mode.clone());
                best_len = path.len();
            }
        }

        if let Some(mode) = best_match {
            return mode;
        }

        self.default_mode.clone()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HymoMapsRuleConfig {
    #[serde(default)]
    pub target_ino: u64,
    #[serde(default)]
    pub target_dev: u64,
    #[serde(default)]
    pub spoofed_ino: u64,
    #[serde(default)]
    pub spoofed_dev: u64,
    #[serde(default, alias = "path")]
    pub spoofed_pathname: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HymoKstatRuleConfig {
    #[serde(default)]
    pub target_ino: u64,
    #[serde(default, alias = "target_path", alias = "path")]
    pub target_pathname: PathBuf,
    #[serde(default)]
    pub spoofed_ino: u64,
    #[serde(default)]
    pub spoofed_dev: u64,
    #[serde(default)]
    pub spoofed_nlink: u32,
    #[serde(default)]
    pub spoofed_size: i64,
    #[serde(default)]
    pub spoofed_atime_sec: i64,
    #[serde(default)]
    pub spoofed_atime_nsec: i64,
    #[serde(default)]
    pub spoofed_mtime_sec: i64,
    #[serde(default)]
    pub spoofed_mtime_nsec: i64,
    #[serde(default)]
    pub spoofed_ctime_sec: i64,
    #[serde(default)]
    pub spoofed_ctime_nsec: i64,
    #[serde(default)]
    pub spoofed_blksize: u64,
    #[serde(default)]
    pub spoofed_blocks: u64,
    #[serde(default)]
    pub is_static: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HymoUnameConfig {
    #[serde(default)]
    pub sysname: String,
    #[serde(default)]
    pub nodename: String,
    #[serde(default)]
    pub release: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub machine: String,
    #[serde(default)]
    pub domainname: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HymoMountHideConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub path_pattern: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HymoStatfsSpoofConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub path: PathBuf,
    #[serde(default)]
    pub spoof_f_type: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HymoFsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ignore_protocol_mismatch: bool,
    #[serde(default = "default_true")]
    pub lkm_autoload: bool,
    #[serde(default = "default_hymofs_lkm_dir")]
    pub lkm_dir: PathBuf,
    #[serde(default)]
    pub lkm_kmi_override: String,
    #[serde(default = "default_hymofs_mirror_path")]
    pub mirror_path: PathBuf,
    #[serde(default)]
    pub enable_kernel_debug: bool,
    #[serde(default = "default_true")]
    pub enable_stealth: bool,
    #[serde(default, alias = "hidexattr")]
    pub enable_hidexattr: bool,
    #[serde(default)]
    pub enable_mount_hide: bool,
    #[serde(default)]
    pub enable_maps_spoof: bool,
    #[serde(default)]
    pub enable_statfs_spoof: bool,
    #[serde(default)]
    pub mount_hide: HymoMountHideConfig,
    #[serde(default)]
    pub statfs_spoof: HymoStatfsSpoofConfig,
    #[serde(default)]
    pub hide_uids: Vec<u32>,
    #[serde(default)]
    pub uname: HymoUnameConfig,
    #[serde(default)]
    pub uname_release: String,
    #[serde(default)]
    pub uname_version: String,
    #[serde(default, alias = "cmdline")]
    pub cmdline_value: String,
    #[serde(default)]
    pub kstat_rules: Vec<HymoKstatRuleConfig>,
    #[serde(default)]
    pub maps_rules: Vec<HymoMapsRuleConfig>,
}

impl Default for HymoFsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ignore_protocol_mismatch: false,
            lkm_autoload: default_true(),
            lkm_dir: default_hymofs_lkm_dir(),
            lkm_kmi_override: String::new(),
            mirror_path: default_hymofs_mirror_path(),
            enable_kernel_debug: false,
            enable_stealth: default_true(),
            enable_hidexattr: false,
            enable_mount_hide: false,
            enable_maps_spoof: false,
            enable_statfs_spoof: false,
            mount_hide: HymoMountHideConfig::default(),
            statfs_spoof: HymoStatfsSpoofConfig::default(),
            hide_uids: Vec::new(),
            uname: HymoUnameConfig::default(),
            uname_release: String::new(),
            uname_version: String::new(),
            cmdline_value: String::new(),
            kstat_rules: Vec::new(),
            maps_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_moduledir")]
    pub moduledir: PathBuf,
    #[serde(default = "default_mountsource")]
    pub mountsource: String,
    #[serde(default, deserialize_with = "deserialize_partitions_flexible")]
    pub partitions: Vec<String>,
    #[serde(default)]
    pub overlay_mode: OverlayMode,
    #[serde(default)]
    pub disable_umount: bool,
    #[serde(default)]
    pub allow_umount_coexistence: bool,
    #[serde(default)]
    pub enable_overlay_fallback: bool,
    #[serde(default)]
    pub default_mode: DefaultMode,
    #[serde(default)]
    pub hymofs: HymoFsConfig,
    #[serde(default)]
    pub rules: HashMap<String, ModuleRules>,
}

fn default_moduledir() -> PathBuf {
    PathBuf::from(defs::MODULES_DIR)
}

fn default_mountsource() -> String {
    crate::sys::mount::detect_mount_source()
}

fn default_hymofs_mirror_path() -> PathBuf {
    PathBuf::from(defs::HYMOFS_MIRROR_DIR)
}

fn default_hymofs_lkm_dir() -> PathBuf {
    PathBuf::from(defs::HYMOFS_LKM_DIR)
}

fn default_true() -> bool {
    true
}

fn deserialize_partitions_flexible<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Vec(Vec<String>),
    }

    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::Vec(v) => Ok(v),
        StringOrVec::String(s) => Ok(s
            .split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect()),
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            moduledir: default_moduledir(),
            mountsource: default_mountsource(),
            partitions: Vec::new(),
            overlay_mode: OverlayMode::default(),
            disable_umount: false,
            allow_umount_coexistence: false,
            enable_overlay_fallback: false,
            default_mode: DefaultMode::default(),
            hymofs: HymoFsConfig::default(),
            rules: HashMap::new(),
        }
    }
}

impl Config {
    pub fn merge_with_cli(
        &mut self,
        moduledir: Option<PathBuf>,
        mountsource: Option<String>,
        partitions: Vec<String>,
    ) {
        if let Some(dir) = moduledir {
            self.moduledir = dir;
        }

        if let Some(source) = mountsource {
            self.mountsource = source;
        }

        if !partitions.is_empty() {
            self.partitions = partitions;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf};

    use super::{Config, HymoFsConfig, MountMode};
    use crate::defs;

    #[test]
    fn config_default_disables_overlay_fallback() {
        let cfg = Config::default();
        assert!(!cfg.enable_overlay_fallback);
    }

    #[test]
    fn config_can_deserialize_overlay_fallback_switch() {
        let content = r#"
moduledir = "/data/adb/modules"
mountsource = "KSU"
enable_overlay_fallback = true
"#;
        let cfg: Config = toml::from_str(content).expect("failed to parse toml");
        assert!(cfg.enable_overlay_fallback);
    }

    #[test]
    fn module_rules_prefers_longest_prefix_match() {
        let rules = super::ModuleRules {
            default_mode: MountMode::Overlay,
            paths: HashMap::from([
                ("system".to_string(), MountMode::Magic),
                ("system/bin".to_string(), MountMode::Hymofs),
            ]),
        };

        assert_eq!(rules.get_mode("system/bin"), MountMode::Hymofs);
        assert_eq!(rules.get_mode("system/bin/sh"), MountMode::Hymofs);
        assert_eq!(rules.get_mode("system/lib"), MountMode::Magic);
    }

    #[test]
    fn hymofs_config_defaults_to_dev_mirror() {
        let cfg = HymoFsConfig::default();
        assert_eq!(cfg.mirror_path, PathBuf::from(defs::HYMOFS_MIRROR_DIR));
        assert!(cfg.lkm_autoload);
        assert_eq!(cfg.lkm_dir, PathBuf::from(defs::HYMOFS_LKM_DIR));
        assert!(cfg.lkm_kmi_override.is_empty());
        assert!(!cfg.enabled);
        assert!(cfg.enable_stealth);
        assert!(!cfg.enable_hidexattr);
        assert!(!cfg.mount_hide.enabled);
        assert!(cfg.mount_hide.path_pattern.as_os_str().is_empty());
        assert!(!cfg.statfs_spoof.enabled);
        assert!(cfg.statfs_spoof.path.as_os_str().is_empty());
        assert_eq!(cfg.statfs_spoof.spoof_f_type, 0);
        assert!(cfg.hide_uids.is_empty());
        assert!(cfg.uname.sysname.is_empty());
        assert!(cfg.uname_release.is_empty());
        assert!(cfg.uname_version.is_empty());
        assert!(cfg.cmdline_value.is_empty());
        assert!(cfg.kstat_rules.is_empty());
        assert!(cfg.maps_rules.is_empty());
    }

    #[test]
    fn hymofs_config_supports_spoof_and_maps_rule_fields() {
        let content = "[hymofs]\n\
lkm_autoload = false\n\
lkm_dir = \"/data/adb/modules/hybrid_mount/hymofs_lkm\"\n\
lkm_kmi_override = \"android15-6.6\"\n\
uname.sysname = \"Linux\"\n\
uname.machine = \"aarch64\"\n\
uname_release = \"5.15.0-hymo\"\n\
uname_version = \"#1 Hymo\"\n\
cmdline_value = \"androidboot.verifiedbootstate=green\"\n\
enable_hidexattr = true\n\
mount_hide.enabled = true\n\
mount_hide.path_pattern = \"/dev/hymo_mirror\"\n\
statfs_spoof.enabled = true\n\
statfs_spoof.path = \"/system\"\n\
statfs_spoof.spoof_f_type = 2035054128\n\
hide_uids = [1000, 2000]\n\
\n\
[[hymofs.kstat_rules]]\n\
target_ino = 11\n\
target_pathname = \"/system/bin/app_process64\"\n\
spoofed_ino = 22\n\
spoofed_dev = 33\n\
spoofed_nlink = 1\n\
spoofed_size = 4096\n\
spoofed_atime_sec = 10\n\
spoofed_atime_nsec = 11\n\
spoofed_mtime_sec = 12\n\
spoofed_mtime_nsec = 13\n\
spoofed_ctime_sec = 14\n\
spoofed_ctime_nsec = 15\n\
spoofed_blksize = 4096\n\
spoofed_blocks = 8\n\
is_static = true\n\
\n\
[[hymofs.maps_rules]]\n\
target_ino = 100\n\
target_dev = 200\n\
spoofed_ino = 300\n\
spoofed_dev = 400\n\
spoofed_pathname = \"/dev/hymo_mirror/system/bin/sh\"\n";

        let cfg: Config = toml::from_str(content).expect("failed to parse toml");
        assert!(!cfg.hymofs.lkm_autoload);
        assert_eq!(
            cfg.hymofs.lkm_dir,
            PathBuf::from("/data/adb/modules/hybrid_mount/hymofs_lkm")
        );
        assert_eq!(cfg.hymofs.lkm_kmi_override, "android15-6.6");
        assert_eq!(cfg.hymofs.uname.sysname, "Linux");
        assert_eq!(cfg.hymofs.uname.machine, "aarch64");
        assert_eq!(cfg.hymofs.uname_release, "5.15.0-hymo");
        assert_eq!(cfg.hymofs.uname_version, "#1 Hymo");
        assert!(cfg.hymofs.mount_hide.enabled);
        assert_eq!(
            cfg.hymofs.mount_hide.path_pattern,
            PathBuf::from("/dev/hymo_mirror")
        );
        assert!(cfg.hymofs.statfs_spoof.enabled);
        assert_eq!(cfg.hymofs.statfs_spoof.path, PathBuf::from("/system"));
        assert_eq!(cfg.hymofs.statfs_spoof.spoof_f_type, 2035054128);
        assert_eq!(
            cfg.hymofs.cmdline_value,
            "androidboot.verifiedbootstate=green"
        );
        assert!(cfg.hymofs.enable_hidexattr);
        assert_eq!(cfg.hymofs.hide_uids, vec![1000, 2000]);
        assert_eq!(cfg.hymofs.kstat_rules.len(), 1);
        assert_eq!(
            cfg.hymofs.kstat_rules[0].target_pathname,
            PathBuf::from("/system/bin/app_process64")
        );
        assert!(cfg.hymofs.kstat_rules[0].is_static);
        assert_eq!(cfg.hymofs.maps_rules.len(), 1);
        assert_eq!(
            cfg.hymofs.maps_rules[0].spoofed_pathname,
            PathBuf::from("/dev/hymo_mirror/system/bin/sh")
        );
    }
}
