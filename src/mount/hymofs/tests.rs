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
    fs,
    path::{Path, PathBuf},
};

use tempfile::tempdir;

use super::{
    compile::{CompiledRules, compile_rules_with_root, render_compiled_tree},
    runtime::{auxiliary_features_requested, hymofs_runtime_requested, mount_mapping_requested},
};
use crate::{
    conf::{config::Config, schema::HymoMapsRuleConfig},
    core::{
        inventory::Module,
        ops::plan::{HymofsAddRule, HymofsMergeRule, MountPlan},
    },
    domain::{ModuleRules, MountMode},
};

fn make_module(
    source_root: &Path,
    mirror_root: &Path,
    id: &str,
    rules: ModuleRules,
    files: &[&str],
) -> Module {
    let source_module_root = source_root.join(id);
    let mirror_module_root = mirror_root.join(id);

    fs::create_dir_all(&source_module_root).expect("failed to create source module");
    fs::create_dir_all(&mirror_module_root).expect("failed to create mirror module");
    fs::write(source_module_root.join("module.prop"), "name=Test Module\n")
        .expect("failed to write module.prop");

    for file in files {
        let source_file = mirror_module_root.join(file);
        if let Some(parent) = source_file.parent() {
            fs::create_dir_all(parent).expect("failed to create mirror file parent");
        }
        fs::write(&source_file, "test").expect("failed to create mirror file");
    }

    Module {
        id: id.to_string(),
        source_path: source_module_root,
        rules,
    }
}

#[test]
fn hymofs_runtime_requires_mapping_or_explicit_feature() {
    let mut config = Config::default();
    config.hymofs.enable_kernel_debug = false;
    config.hymofs.enable_stealth = false;
    config.hymofs.enable_hidexattr = false;
    config.hymofs.enable_mount_hide = false;
    config.hymofs.enable_maps_spoof = false;
    config.hymofs.enable_statfs_spoof = false;
    let plan = MountPlan::default();

    assert!(!mount_mapping_requested(&plan));
    assert!(!auxiliary_features_requested(&config));
    assert!(!hymofs_runtime_requested(&plan, &config));
}

#[test]
fn hymofs_runtime_turns_on_for_selected_modules() {
    let mut config = Config::default();
    config.hymofs.enabled = true;
    config.hymofs.enable_mount_hide = false;
    config.hymofs.enable_maps_spoof = false;
    config.hymofs.enable_statfs_spoof = false;

    let plan = MountPlan {
        hymofs_module_ids: vec!["demo".to_string()],
        ..MountPlan::default()
    };

    assert!(mount_mapping_requested(&plan));
    assert!(hymofs_runtime_requested(&plan, &config));
}

#[test]
fn hymofs_runtime_turns_on_for_auxiliary_features() {
    let mut config = Config::default();
    config.hymofs.enabled = true;
    config.hymofs.enable_mount_hide = true;

    assert!(auxiliary_features_requested(&config));
    assert!(hymofs_runtime_requested(&MountPlan::default(), &config));
}

#[test]
fn hymofs_runtime_turns_on_for_structured_mount_hide_config() {
    let mut config = Config::default();
    config.hymofs.enabled = true;
    config.hymofs.mount_hide.path_pattern = Path::new("/dev/hymo_mirror").to_path_buf();

    assert!(auxiliary_features_requested(&config));
    assert!(hymofs_runtime_requested(&MountPlan::default(), &config));
}

#[test]
fn hymofs_runtime_turns_on_for_spoof_configuration() {
    let mut config = Config::default();
    config.hymofs.enabled = true;
    config.hymofs.uname_release = "5.15.0-hymo".to_string();

    assert!(auxiliary_features_requested(&config));
    assert!(hymofs_runtime_requested(&MountPlan::default(), &config));
}

#[test]
fn hymofs_runtime_turns_on_for_hide_uids() {
    let mut config = Config::default();
    config.hymofs.enabled = true;
    config.hymofs.hide_uids = vec![1000, 2000];

    assert!(auxiliary_features_requested(&config));
    assert!(hymofs_runtime_requested(&MountPlan::default(), &config));
}

#[test]
fn hymofs_runtime_turns_on_for_kstat_rules() {
    let mut config = Config::default();
    config.hymofs.enabled = true;
    config
        .hymofs
        .kstat_rules
        .push(crate::conf::schema::HymoKstatRuleConfig {
            target_ino: 11,
            target_pathname: Path::new("/system/bin/app_process64").to_path_buf(),
            spoofed_ino: 22,
            spoofed_dev: 33,
            spoofed_nlink: 1,
            spoofed_size: 4096,
            spoofed_atime_sec: 10,
            spoofed_atime_nsec: 11,
            spoofed_mtime_sec: 12,
            spoofed_mtime_nsec: 13,
            spoofed_ctime_sec: 14,
            spoofed_ctime_nsec: 15,
            spoofed_blksize: 4096,
            spoofed_blocks: 8,
            is_static: true,
        });

    assert!(auxiliary_features_requested(&config));
    assert!(hymofs_runtime_requested(&MountPlan::default(), &config));
}

#[test]
fn hymofs_runtime_turns_on_for_extended_uname_fields() {
    let mut config = Config::default();
    config.hymofs.enabled = true;
    config.hymofs.uname.machine = "aarch64".to_string();

    assert!(auxiliary_features_requested(&config));
    assert!(hymofs_runtime_requested(&MountPlan::default(), &config));
}

#[test]
fn hymofs_runtime_turns_on_for_maps_rules() {
    let mut config = Config::default();
    config.hymofs.enabled = true;
    config.hymofs.maps_rules.push(HymoMapsRuleConfig {
        target_ino: 1,
        target_dev: 2,
        spoofed_ino: 3,
        spoofed_dev: 4,
        spoofed_pathname: Path::new("/dev/hymo_mirror/system/bin/sh").to_path_buf(),
    });

    assert!(auxiliary_features_requested(&config));
    assert!(hymofs_runtime_requested(&MountPlan::default(), &config));
}

#[test]
fn hymofs_runtime_turns_on_for_structured_statfs_spoof_config() {
    let mut config = Config::default();
    config.hymofs.enabled = true;
    config.hymofs.statfs_spoof.path = Path::new("/system").to_path_buf();
    config.hymofs.statfs_spoof.spoof_f_type = 0x794c7630;

    assert!(auxiliary_features_requested(&config));
    assert!(hymofs_runtime_requested(&MountPlan::default(), &config));
}

#[test]
fn compile_rules_do_not_merge_partition_root() {
    let temp = tempdir().expect("failed to create temp dir");
    let source_root = temp.path().join("source");
    let mirror_root = temp.path().join("mirror");
    let system_root = temp.path().join("system_root");
    fs::create_dir_all(system_root.join("system/bin")).expect("failed to create fake system bin");
    fs::create_dir_all(system_root.join("system/etc")).expect("failed to create fake system etc");

    let module = make_module(
        &source_root,
        &mirror_root,
        "mod_a",
        ModuleRules {
            default_mode: MountMode::Hymofs,
            ..ModuleRules::default()
        },
        &["system/bin/sh", "system/etc/hosts"],
    );

    let config = Config {
        hymofs: crate::conf::schema::HymoFsConfig {
            mirror_path: mirror_root,
            ..Config::default().hymofs
        },
        ..Config::default()
    };
    let plan = MountPlan {
        hymofs_module_ids: vec!["mod_a".to_string()],
        ..MountPlan::default()
    };

    let compiled = compile_rules_with_root(&[module], &plan, &config, &system_root)
        .expect("compile should succeed");

    assert!(compiled.merge_rules.is_empty());
    assert_eq!(compiled.add_rules.len(), 2);
    assert_eq!(
        compiled
            .add_rules
            .iter()
            .map(|rule| rule.target.as_str())
            .collect::<Vec<_>>(),
        vec!["/system/bin/sh", "/system/etc/hosts"]
    );
    assert_eq!(
        compiled
            .add_rules
            .iter()
            .map(|rule| {
                rule.source
                    .strip_prefix(&config.hymofs.mirror_path)
                    .expect("rule source should be under mirror path")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>(),
        vec!["mod_a/system/bin/sh", "mod_a/system/etc/hosts"]
    );
    assert!(compiled.hide_rules.is_empty());
}

#[test]
fn exact_file_targets_from_multiple_modules_are_preserved() {
    let temp = tempdir().expect("failed to create temp dir");
    let source_root = temp.path().join("source");
    let mirror_root = temp.path().join("mirror");
    let system_root = temp.path().join("system_root");
    fs::create_dir_all(system_root.join("system/bin")).expect("failed to create fake system bin");

    let module_a = make_module(
        &source_root,
        &mirror_root,
        "mod_a",
        ModuleRules {
            default_mode: MountMode::Hymofs,
            ..ModuleRules::default()
        },
        &["system/bin/sh"],
    );
    let module_b = make_module(
        &source_root,
        &mirror_root,
        "mod_b",
        ModuleRules {
            default_mode: MountMode::Hymofs,
            ..ModuleRules::default()
        },
        &["system/bin/ls"],
    );
    let module_c = make_module(
        &source_root,
        &mirror_root,
        "mod_c",
        ModuleRules {
            default_mode: MountMode::Hymofs,
            ..ModuleRules::default()
        },
        &["system/bin/toybox"],
    );

    let config = Config {
        hymofs: crate::conf::schema::HymoFsConfig {
            mirror_path: mirror_root,
            ..Config::default().hymofs
        },
        ..Config::default()
    };
    let plan = MountPlan {
        hymofs_module_ids: vec![
            "mod_a".to_string(),
            "mod_b".to_string(),
            "mod_c".to_string(),
        ],
        ..MountPlan::default()
    };

    let compiled = compile_rules_with_root(
        &[module_a, module_b, module_c],
        &plan,
        &config,
        &system_root,
    )
    .expect("compile should succeed");

    assert!(compiled.merge_rules.is_empty());
    assert_eq!(compiled.add_rules.len(), 3);
    assert!(
        compiled
            .add_rules
            .iter()
            .all(|rule| rule.target.starts_with("/system/bin/"))
    );
    assert!(compiled.hide_rules.is_empty());
}

#[test]
fn compiled_tree_dump_includes_actions_sources_and_modules() {
    let compiled = CompiledRules {
        add_rules: vec![HymofsAddRule {
            target: "/system/bin/sh".to_string(),
            source: PathBuf::from("/dev/hymo_mirror/mod_a/system/bin/sh"),
            file_type: libc::DT_REG as i32,
        }],
        merge_rules: vec![HymofsMergeRule {
            target: "/system/etc".to_string(),
            source: PathBuf::from("/dev/hymo_mirror/mod_b/system/etc"),
        }],
        hide_rules: vec!["/system/xbin/su".to_string()],
    };

    let dump = render_compiled_tree(
        &compiled,
        Path::new("/dev/hymo_mirror"),
        &[PathBuf::from("/system/bin/adbd")],
    )
    .expect("tree dump should be present");

    assert!(dump.contains("/ (Root)"));
    assert!(dump.contains("etc (Directory) [MERGE] [modules=mod_b]"));
    assert!(dump.contains("sh (RegularFile) [ADD] [modules=mod_a]"));
    assert!(dump.contains("su (Hidden) [HIDE]"));
    assert!(dump.contains("adbd (Hidden) [USER_HIDE]"));
    assert!(dump.contains("/dev/hymo_mirror/mod_a/system/bin/sh"));
}
