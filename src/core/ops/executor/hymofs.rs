// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt, fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use walkdir::WalkDir;

use crate::{
    conf::config,
    core::{
        inventory::{Module, MountMode},
        ops::planner::{HymofsAddRule, HymofsMergeRule, MountPlan},
        user_hide_rules,
    },
    defs,
    sys::hymofs::{
        self, HYMO_FEATURE_CMDLINE_SPOOF, HYMO_FEATURE_KSTAT_SPOOF, HYMO_FEATURE_MAPS_SPOOF,
        HYMO_FEATURE_MOUNT_HIDE, HYMO_FEATURE_STATFS_SPOOF, HYMO_FEATURE_UNAME_SPOOF, HymoMapsRule,
        HymoMountHideArg, HymoSpoofKstat, HymoSpoofUname, HymoStatfsSpoofArg,
    },
};

#[derive(Debug, Default)]
struct CompiledRules {
    add_rules: Vec<HymofsAddRule>,
    merge_rules: Vec<HymofsMergeRule>,
    hide_rules: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HymofsTreeFileType {
    Root,
    Directory,
    RegularFile,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
    Hidden,
    Unknown,
}

impl HymofsTreeFileType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Root => "Root",
            Self::Directory => "Directory",
            Self::RegularFile => "RegularFile",
            Self::Symlink => "Symlink",
            Self::BlockDevice => "BlockDevice",
            Self::CharDevice => "CharDevice",
            Self::Fifo => "Fifo",
            Self::Socket => "Socket",
            Self::Hidden => "Hidden",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Clone)]
struct HymofsTreeNode {
    name: String,
    file_type: HymofsTreeFileType,
    children: BTreeMap<String, Self>,
    actions: BTreeSet<&'static str>,
    modules: BTreeSet<String>,
    sources: Vec<PathBuf>,
}

impl fmt::Debug for HymofsTreeNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.debug_tree(f, 0)
    }
}

impl HymofsTreeNode {
    fn new_root() -> Self {
        Self {
            name: "/".to_string(),
            file_type: HymofsTreeFileType::Root,
            children: BTreeMap::default(),
            actions: BTreeSet::default(),
            modules: BTreeSet::default(),
            sources: Vec::new(),
        }
    }

    fn new_directory<S>(name: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            name: name.into(),
            file_type: HymofsTreeFileType::Directory,
            children: BTreeMap::default(),
            actions: BTreeSet::default(),
            modules: BTreeSet::default(),
            sources: Vec::new(),
        }
    }

    fn debug_tree(&self, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
        let indent_str = "  ".repeat(indent);

        write!(
            f,
            "{}{} ({})",
            indent_str,
            self.name,
            self.file_type.as_str()
        )?;

        for action in &self.actions {
            write!(f, " [{}]", action)?;
        }

        if !self.modules.is_empty() {
            write!(
                f,
                " [modules={}]",
                self.modules.iter().cloned().collect::<Vec<_>>().join(",")
            )?;
        }

        if !self.sources.is_empty() {
            write!(
                f,
                " [sources={}]",
                self.sources
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )?;
        }

        writeln!(f)?;

        for child in self.children.values() {
            child.debug_tree(f, indent + 1)?;
        }

        Ok(())
    }

    fn insert_rule(
        &mut self,
        target: &Path,
        leaf_file_type: HymofsTreeFileType,
        action: &'static str,
        source: Option<&Path>,
        module_id: Option<String>,
    ) {
        let components: Vec<String> = target
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();

        if components.is_empty() {
            self.actions.insert(action);
            if let Some(module_id) = module_id {
                self.modules.insert(module_id);
            }
            if let Some(source) = source
                && !self.sources.iter().any(|existing| existing == source)
            {
                self.sources.push(source.to_path_buf());
            }
            return;
        }

        let mut current = self;
        for (index, component) in components.iter().enumerate() {
            let is_leaf = index == components.len() - 1;
            current = current
                .children
                .entry(component.clone())
                .or_insert_with(|| Self::new_directory(component.clone()));

            if !is_leaf {
                current.file_type = HymofsTreeFileType::Directory;
                continue;
            }

            if current.children.is_empty() {
                current.file_type = leaf_file_type;
            } else {
                current.file_type = HymofsTreeFileType::Directory;
            }
            current.actions.insert(action);
            if let Some(module_id) = module_id.as_ref() {
                current.modules.insert(module_id.clone());
            }
            if let Some(source) = source
                && !current.sources.iter().any(|existing| existing == source)
            {
                current.sources.push(source.to_path_buf());
            }
        }
    }
}

fn mount_mapping_requested(plan: &MountPlan) -> bool {
    !plan.hymofs_module_ids.is_empty()
}

fn auxiliary_features_requested(config: &config::Config) -> bool {
    config.hymofs.enable_kernel_debug
        || effective_stealth_enabled(config)
        || effective_mount_hide_enabled(config)
        || effective_maps_spoof_enabled(config)
        || effective_statfs_spoof_enabled(config)
        || has_uname_spoof_config(config)
        || !config.hymofs.cmdline_value.is_empty()
        || !config.hymofs.hide_uids.is_empty()
        || !config.hymofs.kstat_rules.is_empty()
        || user_hide_rules::user_hide_rule_count() > 0
}

fn hymofs_runtime_requested(plan: &MountPlan, config: &config::Config) -> bool {
    config.hymofs.enabled && (mount_mapping_requested(plan) || auxiliary_features_requested(config))
}

fn build_managed_partitions(config: &config::Config) -> HashSet<String> {
    let mut managed_partitions: HashSet<String> = defs::BUILTIN_PARTITIONS
        .iter()
        .map(|partition| partition.to_string())
        .collect();
    managed_partitions.insert("system".to_string());
    managed_partitions.extend(config.partitions.iter().cloned());
    managed_partitions
}

fn effective_stealth_enabled(config: &config::Config) -> bool {
    config.hymofs.enable_stealth || config.hymofs.enable_hidexattr
}

fn effective_mount_hide_enabled(config: &config::Config) -> bool {
    config.hymofs.enable_mount_hide
        || config.hymofs.enable_hidexattr
        || config.hymofs.mount_hide.enabled
        || !config.hymofs.mount_hide.path_pattern.as_os_str().is_empty()
}

fn effective_maps_spoof_enabled(config: &config::Config) -> bool {
    config.hymofs.enable_maps_spoof
        || config.hymofs.enable_hidexattr
        || !config.hymofs.maps_rules.is_empty()
}

fn effective_statfs_spoof_enabled(config: &config::Config) -> bool {
    config.hymofs.enable_statfs_spoof
        || config.hymofs.enable_hidexattr
        || config.hymofs.statfs_spoof.enabled
        || !config.hymofs.statfs_spoof.path.as_os_str().is_empty()
        || config.hymofs.statfs_spoof.spoof_f_type != 0
}

fn has_uname_spoof_config(config: &config::Config) -> bool {
    !config.hymofs.uname.sysname.is_empty()
        || !config.hymofs.uname.nodename.is_empty()
        || !config.hymofs.uname.release.is_empty()
        || !config.hymofs.uname.version.is_empty()
        || !config.hymofs.uname.machine.is_empty()
        || !config.hymofs.uname.domainname.is_empty()
        || !config.hymofs.uname_release.is_empty()
        || !config.hymofs.uname_version.is_empty()
}

fn feature_supported(features: Option<i32>, required_feature: i32) -> bool {
    features
        .map(|bits| bits & required_feature != 0)
        .unwrap_or(true)
}

fn resolve_path_for_hymofs_with_root(system_root: &Path, path: &Path) -> PathBuf {
    let virtual_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new("/").join(path)
    };

    let translated_path = if system_root == Path::new("/") {
        virtual_path.clone()
    } else {
        let relative = virtual_path.strip_prefix("/").unwrap_or(&virtual_path);
        system_root.join(relative)
    };

    // Stay on the non-canonical form when possible (e.g. /system/product
    // instead of /product). The kernel's ADD_MERGE_RULE computes
    // resolved_src via kern_path(LOOKUP_FOLLOW)+d_path internally and
    // populate_injected_list matches both src and resolved_src against
    // both d_absolute_path and d_path forms, so the merge match works on
    // either side. Keeping rules anchored to /system/product avoids
    // touching the original partition, which (empirically) is more
    // fragile to data-loss regressions than /system/product.
    //
    // We only canonicalize the *parent* path (below) when the leaf
    // component doesn't exist yet — that handles brand-new paths while
    // keeping the symlink chain intact for the common case.

    let Some(parent) = translated_path.parent() else {
        return virtual_path;
    };

    let Some(filename) = translated_path.file_name() else {
        return virtual_path;
    };

    let mut current = parent.to_path_buf();
    let mut suffix = Vec::new();

    while current != system_root && !current.exists() {
        if let Some(name) = current.file_name() {
            suffix.push(name.to_os_string());
        }
        if !current.pop() {
            break;
        }
    }

    // Do NOT canonicalize — see comment above. We keep the symlink-prefixed
    // form (e.g. /system/product/overlay) and rely on the kernel's bidirectional
    // match (src vs resolved_src × d_absolute_path vs d_path) to cover both
    // access paths.
    let mut resolved = if current.exists() {
        current
    } else {
        parent.to_path_buf()
    };

    for item in suffix.iter().rev() {
        resolved.push(item);
    }
    resolved.push(filename);

    if system_root == Path::new("/") {
        return resolved;
    }

    if let Ok(relative) = resolved.strip_prefix(system_root) {
        return Path::new("/").join(relative);
    }

    virtual_path
}

fn mirror_module_root(config: &config::Config, module: &Module) -> Result<PathBuf> {
    let module_root = config.hymofs.mirror_path.join(&module.id);
    if module_root.exists() {
        Ok(module_root)
    } else {
        bail!(
            "missing HymoFS mirror content for module {} at {}",
            module.id,
            module_root.display()
        )
    }
}

fn apply_feature_toggle<F>(
    feature_name: &str,
    enabled: bool,
    features: Option<i32>,
    required_feature: i32,
    operation: F,
) where
    F: FnOnce(bool) -> Result<()>,
{
    let supported = feature_supported(features, required_feature);

    if !supported {
        crate::scoped_log!(
            warn,
            "executor:hymofs",
            "feature skip: name={}, enabled={}, reason=unsupported",
            feature_name,
            enabled
        );
        return;
    }

    if let Err(err) = operation(enabled) {
        crate::scoped_log!(
            warn,
            "executor:hymofs",
            "feature apply failed: name={}, enabled={}, error={:#}",
            feature_name,
            enabled,
            err
        );
    }
}

fn get_features() -> Option<i32> {
    match hymofs::get_features() {
        Ok(bits) => Some(bits),
        Err(err) => {
            crate::scoped_log!(
                debug,
                "executor:hymofs",
                "feature query failed: error={:#}",
                err
            );
            None
        }
    }
}

fn log_feature_summary(features: Option<i32>) {
    if let Some(bits) = features {
        let names = hymofs::feature_names(bits);
        crate::scoped_log!(
            info,
            "executor:hymofs",
            "features: bits={}, names={}",
            bits,
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(",")
            }
        );
    }
}

fn apply_runtime_switches(
    config: &config::Config,
    runtime_requested: bool,
    features: Option<i32>,
) -> Result<()> {
    if !runtime_requested {
        return Ok(());
    }

    if config.hymofs.enable_kernel_debug {
        hymofs::set_debug(true)?;
    }

    if effective_stealth_enabled(config) {
        hymofs::set_stealth(true)?;
    }

    let mount_hide_enabled = effective_mount_hide_enabled(config);
    if mount_hide_enabled {
        if feature_supported(features, HYMO_FEATURE_MOUNT_HIDE) {
            let mount_hide_config = if !config.hymofs.mount_hide.path_pattern.as_os_str().is_empty()
            {
                HymoMountHideArg::new(true, Some(config.hymofs.mount_hide.path_pattern.as_path()))?
            } else {
                HymoMountHideArg::new(true, None)?
            };

            if let Err(err) = hymofs::set_mount_hide_config(&mount_hide_config) {
                crate::scoped_log!(
                    warn,
                    "executor:hymofs",
                    "feature apply failed: name=mount_hide, enabled=true, error={:#}",
                    err
                );
            }
        } else {
            crate::scoped_log!(
                warn,
                "executor:hymofs",
                "feature skip: name=mount_hide, enabled=true, reason=unsupported"
            );
        }
    }

    let maps_spoof_enabled = effective_maps_spoof_enabled(config);
    if maps_spoof_enabled {
        apply_feature_toggle(
            "maps_spoof",
            true,
            features,
            HYMO_FEATURE_MAPS_SPOOF,
            hymofs::set_maps_spoof,
        );
    }

    let statfs_spoof_enabled = effective_statfs_spoof_enabled(config);
    if statfs_spoof_enabled {
        if feature_supported(features, HYMO_FEATURE_STATFS_SPOOF) {
            let statfs_config = if !config.hymofs.statfs_spoof.path.as_os_str().is_empty()
                || config.hymofs.statfs_spoof.spoof_f_type != 0
            {
                HymoStatfsSpoofArg::with_path_and_f_type(
                    true,
                    config.hymofs.statfs_spoof.path.as_path(),
                    to_c_ulong(
                        config.hymofs.statfs_spoof.spoof_f_type,
                        "statfs_spoof.spoof_f_type",
                    )?,
                )?
            } else {
                HymoStatfsSpoofArg::new(true)
            };

            if let Err(err) = hymofs::set_statfs_spoof_config(&statfs_config) {
                crate::scoped_log!(
                    warn,
                    "executor:hymofs",
                    "feature apply failed: name=statfs_spoof, enabled=true, error={:#}",
                    err
                );
            }
        } else {
            crate::scoped_log!(
                warn,
                "executor:hymofs",
                "feature skip: name=statfs_spoof, enabled=true, reason=unsupported"
            );
        }
    }

    Ok(())
}

fn build_dtype(path: &Path) -> Result<(i32, bool)> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to read metadata for hymofs source {}",
            path.display()
        )
    })?;
    let file_type = metadata.file_type();

    if file_type.is_char_device() && metadata.rdev() == 0 {
        return Ok((libc::DT_UNKNOWN as i32, true));
    }

    let d_type = if file_type.is_file() {
        libc::DT_REG as i32
    } else if file_type.is_symlink() {
        libc::DT_LNK as i32
    } else if file_type.is_dir() {
        libc::DT_DIR as i32
    } else if file_type.is_block_device() {
        libc::DT_BLK as i32
    } else if file_type.is_char_device() {
        libc::DT_CHR as i32
    } else if file_type.is_fifo() {
        libc::DT_FIFO as i32
    } else if file_type.is_socket() {
        libc::DT_SOCK as i32
    } else {
        libc::DT_UNKNOWN as i32
    };

    Ok((d_type, false))
}

fn tree_file_type_from_dtype(d_type: i32) -> HymofsTreeFileType {
    match d_type {
        x if x == libc::DT_DIR as i32 => HymofsTreeFileType::Directory,
        x if x == libc::DT_REG as i32 => HymofsTreeFileType::RegularFile,
        x if x == libc::DT_LNK as i32 => HymofsTreeFileType::Symlink,
        x if x == libc::DT_BLK as i32 => HymofsTreeFileType::BlockDevice,
        x if x == libc::DT_CHR as i32 => HymofsTreeFileType::CharDevice,
        x if x == libc::DT_FIFO as i32 => HymofsTreeFileType::Fifo,
        x if x == libc::DT_SOCK as i32 => HymofsTreeFileType::Socket,
        _ => HymofsTreeFileType::Unknown,
    }
}

fn extract_module_id_from_source(source: &Path, mirror_path: &Path) -> Option<String> {
    source
        .strip_prefix(Path::new(defs::MODULES_DIR))
        .ok()
        .or_else(|| source.strip_prefix(mirror_path).ok())
        .and_then(|relative| {
            relative.components().find_map(|component| match component {
                Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
                _ => None,
            })
        })
}

fn render_compiled_tree(
    compiled: &CompiledRules,
    mirror_path: &Path,
    user_hide_paths: &[PathBuf],
) -> Option<String> {
    if compiled.add_rules.is_empty()
        && compiled.merge_rules.is_empty()
        && compiled.hide_rules.is_empty()
        && user_hide_paths.is_empty()
    {
        return None;
    }

    let mut root = HymofsTreeNode::new_root();

    for rule in &compiled.merge_rules {
        root.insert_rule(
            Path::new(&rule.target),
            HymofsTreeFileType::Directory,
            "MERGE",
            Some(&rule.source),
            extract_module_id_from_source(&rule.source, mirror_path),
        );
    }

    for rule in &compiled.add_rules {
        root.insert_rule(
            Path::new(&rule.target),
            tree_file_type_from_dtype(rule.file_type),
            "ADD",
            Some(&rule.source),
            extract_module_id_from_source(&rule.source, mirror_path),
        );
    }

    for path in &compiled.hide_rules {
        root.insert_rule(
            Path::new(path),
            HymofsTreeFileType::Hidden,
            "HIDE",
            None,
            None,
        );
    }

    for path in user_hide_paths {
        root.insert_rule(path, HymofsTreeFileType::Hidden, "USER_HIDE", None, None);
    }

    Some(format!("{root:?}"))
}

fn relative_mode(module: &Module, relative: &Path) -> MountMode {
    let relative_str = relative.to_string_lossy();
    module.rules.get_mode(relative_str.as_ref())
}

fn compile_rules(
    modules: &[Module],
    plan: &MountPlan,
    config: &config::Config,
) -> Result<CompiledRules> {
    compile_rules_with_root(modules, plan, config, Path::new("/"))
}

fn compile_rules_with_root(
    modules: &[Module],
    plan: &MountPlan,
    config: &config::Config,
    system_root: &Path,
) -> Result<CompiledRules> {
    let managed_partitions = build_managed_partitions(config);
    let active_ids: HashSet<&str> = plan.hymofs_module_ids.iter().map(String::as_str).collect();
    let mut compiled = CompiledRules::default();
    let mut managed_partition_list: Vec<String> = managed_partitions.into_iter().collect();
    managed_partition_list.sort();

    for module in modules.iter().rev() {
        if !active_ids.contains(module.id.as_str()) {
            continue;
        }

        let module_root = mirror_module_root(config, module)?;
        let mut scanned_partition_roots: HashSet<PathBuf> = HashSet::new();

        for partition_name in &managed_partition_list {
            let partition_root = module_root.join(partition_name);
            if !partition_root.is_dir() {
                continue;
            }
            let normalized_partition_root =
                fs::canonicalize(&partition_root).unwrap_or_else(|_| partition_root.clone());
            if !scanned_partition_roots.insert(normalized_partition_root) {
                crate::scoped_log!(
                    debug,
                    "executor:hymofs",
                    "partition root dedupe: module={}, partition={}, root={}",
                    module.id,
                    partition_name,
                    partition_root.display()
                );
                continue;
            }

            let mut iterator = WalkDir::new(&partition_root)
                .follow_links(false)
                .into_iter();

            while let Some(entry_result) = iterator.next() {
                let entry = match entry_result {
                    Ok(entry) => entry,
                    Err(err) => {
                        crate::scoped_log!(
                            warn,
                            "executor:hymofs",
                            "walk failed: module={}, partition={}, error={}",
                            module.id,
                            partition_name,
                            err
                        );
                        continue;
                    }
                };

                if entry.depth() == 0 {
                    continue;
                }

                let path = entry.path();
                let relative = match path.strip_prefix(&module_root) {
                    Ok(relative) => relative,
                    Err(err) => {
                        crate::scoped_log!(
                            warn,
                            "executor:hymofs",
                            "relative path failed: module={}, path={}, error={}",
                            module.id,
                            path.display(),
                            err
                        );
                        continue;
                    }
                };

                if !matches!(relative_mode(module, relative), MountMode::Hymofs) {
                    continue;
                }

                if path
                    .file_name()
                    .is_some_and(|name| name == defs::REPLACE_DIR_FILE_NAME)
                {
                    continue;
                }

                let resolved_virtual_path =
                    resolve_path_for_hymofs_with_root(system_root, &Path::new("/").join(relative));
                let target_key = resolved_virtual_path.display().to_string();

                if entry.file_type().is_dir() {
                    // Emit ADD_MERGE_RULE whenever the module contributes a
                    // directory whose virtual target already exists on the
                    // real FS. The kernel's hymofs_materialize_merge now
                    // recurses with nested merge_entries (instead of
                    // flattening DT_DIR children into hymo_paths), so the
                    // subdir's real content is preserved while module
                    // contents are injected at each level. We still let
                    // WalkDir walk into module subdirs so that brand-new
                    // paths (no real target yet) fall through to the
                    // per-file ADD_RULE branch below.
                    if resolved_virtual_path.is_dir() {
                        compiled.merge_rules.push(HymofsMergeRule {
                            target: target_key,
                            source: path.to_path_buf(),
                        });
                        iterator.skip_current_dir();
                    }
                    continue;
                }

                if entry.file_type().is_symlink()
                    && resolved_virtual_path.exists()
                    && resolved_virtual_path.is_dir()
                {
                    crate::scoped_log!(
                        warn,
                        "executor:hymofs",
                        "symlink skip: module={}, path={}, reason=directory_target",
                        module.id,
                        resolved_virtual_path.display()
                    );
                    continue;
                }

                let (file_type, hide_only) = build_dtype(path)?;
                if hide_only {
                    compiled.hide_rules.push(target_key);
                    continue;
                }

                compiled.add_rules.push(HymofsAddRule {
                    target: target_key,
                    source: path.to_path_buf(),
                    file_type,
                });
            }
        }
    }

    Ok(compiled)
}

fn to_c_ulong(value: u64, field_name: &str) -> Result<libc::c_ulong> {
    libc::c_ulong::try_from(value)
        .map_err(|_| anyhow!("{field_name} value {value} does not fit into c_ulong"))
}

fn to_c_uint(value: u32, _field_name: &str) -> libc::c_uint {
    value
}

fn to_c_long(value: i64, field_name: &str) -> Result<libc::c_long> {
    libc::c_long::try_from(value)
        .map_err(|_| anyhow!("{field_name} value {value} does not fit into c_long"))
}

fn apply_spoof_settings(config: &config::Config, features: Option<i32>) -> Result<()> {
    let has_uname_config = has_uname_spoof_config(config);
    if feature_supported(features, HYMO_FEATURE_UNAME_SPOOF) && has_uname_config {
        let mut uname = HymoSpoofUname::default();
        if !config.hymofs.uname.sysname.is_empty() {
            uname.set_sysname(&config.hymofs.uname.sysname)?;
        }
        if !config.hymofs.uname.nodename.is_empty() {
            uname.set_nodename(&config.hymofs.uname.nodename)?;
        }
        if !config.hymofs.uname.release.is_empty() {
            uname.set_release(&config.hymofs.uname.release)?;
        }
        if !config.hymofs.uname.version.is_empty() {
            uname.set_version(&config.hymofs.uname.version)?;
        }
        if !config.hymofs.uname.machine.is_empty() {
            uname.set_machine(&config.hymofs.uname.machine)?;
        }
        if !config.hymofs.uname.domainname.is_empty() {
            uname.set_domainname(&config.hymofs.uname.domainname)?;
        }
        if !config.hymofs.uname_release.is_empty() {
            uname.set_release(&config.hymofs.uname_release)?;
        }
        if !config.hymofs.uname_version.is_empty() {
            uname.set_version(&config.hymofs.uname_version)?;
        }
        hymofs::set_uname(&uname)?;
    } else if has_uname_config {
        crate::scoped_log!(
            warn,
            "executor:hymofs",
            "feature skip: name=uname_spoof, reason=unsupported"
        );
    }

    if feature_supported(features, HYMO_FEATURE_CMDLINE_SPOOF)
        && !config.hymofs.cmdline_value.is_empty()
    {
        hymofs::set_cmdline_str(&config.hymofs.cmdline_value)?;
    } else if !config.hymofs.cmdline_value.is_empty() {
        crate::scoped_log!(
            warn,
            "executor:hymofs",
            "feature skip: name=cmdline_spoof, reason=unsupported"
        );
    }

    if !config.hymofs.hide_uids.is_empty()
        && let Err(err) = hymofs::set_hide_uids(&config.hymofs.hide_uids)
    {
        crate::scoped_log!(
            warn,
            "executor:hymofs",
            "hide_uids apply failed: count={}, error={:#}",
            config.hymofs.hide_uids.len(),
            err
        );
    }

    if !config.hymofs.kstat_rules.is_empty() {
        if !feature_supported(features, HYMO_FEATURE_KSTAT_SPOOF) {
            crate::scoped_log!(
                warn,
                "executor:hymofs",
                "feature skip: name=kstat_rules, count={}, reason=unsupported",
                config.hymofs.kstat_rules.len()
            );
        } else {
            for rule in &config.hymofs.kstat_rules {
                let mut native_rule = HymoSpoofKstat::new(
                    to_c_ulong(rule.target_ino, "target_ino")?,
                    &rule.target_pathname,
                )?;
                native_rule.spoofed_ino = to_c_ulong(rule.spoofed_ino, "spoofed_ino")?;
                native_rule.spoofed_dev = to_c_ulong(rule.spoofed_dev, "spoofed_dev")?;
                native_rule.spoofed_nlink = to_c_uint(rule.spoofed_nlink, "spoofed_nlink");
                native_rule.spoofed_size = rule.spoofed_size;
                native_rule.spoofed_atime_sec =
                    to_c_long(rule.spoofed_atime_sec, "spoofed_atime_sec")?;
                native_rule.spoofed_atime_nsec =
                    to_c_long(rule.spoofed_atime_nsec, "spoofed_atime_nsec")?;
                native_rule.spoofed_mtime_sec =
                    to_c_long(rule.spoofed_mtime_sec, "spoofed_mtime_sec")?;
                native_rule.spoofed_mtime_nsec =
                    to_c_long(rule.spoofed_mtime_nsec, "spoofed_mtime_nsec")?;
                native_rule.spoofed_ctime_sec =
                    to_c_long(rule.spoofed_ctime_sec, "spoofed_ctime_sec")?;
                native_rule.spoofed_ctime_nsec =
                    to_c_long(rule.spoofed_ctime_nsec, "spoofed_ctime_nsec")?;
                native_rule.spoofed_blksize = to_c_ulong(rule.spoofed_blksize, "spoofed_blksize")?;
                native_rule.spoofed_blocks = rule.spoofed_blocks;
                native_rule.is_static = if rule.is_static { 1 } else { 0 };

                match hymofs::update_spoof_kstat(&native_rule) {
                    Ok(()) => {}
                    Err(update_err) => {
                        crate::scoped_log!(
                            debug,
                            "executor:hymofs",
                            "kstat update fallback to add: target={}, error={:#}",
                            rule.target_pathname.display(),
                            update_err
                        );
                        hymofs::add_spoof_kstat(&native_rule).with_context(|| {
                            format!(
                                "failed to apply kstat rule for {}",
                                rule.target_pathname.display()
                            )
                        })?;
                    }
                }
            }
        }
    }

    if !config.hymofs.maps_rules.is_empty() {
        if !feature_supported(features, HYMO_FEATURE_MAPS_SPOOF) {
            crate::scoped_log!(
                warn,
                "executor:hymofs",
                "feature skip: name=maps_rules, count={}, reason=unsupported",
                config.hymofs.maps_rules.len()
            );
        } else {
            for rule in &config.hymofs.maps_rules {
                let native_rule = HymoMapsRule::new(
                    to_c_ulong(rule.target_ino, "target_ino")?,
                    to_c_ulong(rule.target_dev, "target_dev")?,
                    to_c_ulong(rule.spoofed_ino, "spoofed_ino")?,
                    to_c_ulong(rule.spoofed_dev, "spoofed_dev")?,
                    &rule.spoofed_pathname,
                )?;
                hymofs::add_maps_rule(&native_rule)?;
            }
        }
    }

    Ok(())
}

pub(super) fn reset_runtime(config: &config::Config) -> Result<bool> {
    if !config.hymofs.enabled {
        return Ok(false);
    }

    let available = hymofs::can_operate(config.hymofs.ignore_protocol_mismatch);
    if !available {
        return Ok(false);
    }

    crate::scoped_log!(
        info,
        "executor:hymofs",
        "reset: mirror_path={}",
        config.hymofs.mirror_path.display()
    );

    hymofs::set_mirror_path(&config.hymofs.mirror_path)?;
    hymofs::set_enabled(false)?;
    hymofs::clear_rules()?;
    if let Err(err) = hymofs::clear_maps_rules() {
        crate::scoped_log!(
            debug,
            "executor:hymofs",
            "maps rule clear skipped: error={:#}",
            err
        );
    }

    let features = get_features();
    log_feature_summary(features);

    if config.hymofs.mirror_path != Path::new(defs::HYMOFS_MIRROR_DIR) {
        crate::scoped_log!(
            info,
            "executor:hymofs",
            "custom mirror active: path={}",
            config.hymofs.mirror_path.display()
        );
    }

    Ok(true)
}

pub(super) fn apply(
    plan: &mut MountPlan,
    modules: &[Module],
    config: &config::Config,
) -> Result<bool> {
    if !config.hymofs.enabled {
        return Ok(false);
    }

    let runtime_requested = hymofs_runtime_requested(plan, config);
    let available = hymofs::can_operate(config.hymofs.ignore_protocol_mismatch);
    if !available {
        if mount_mapping_requested(plan) {
            bail!("HymoFS became unavailable before rule application");
        }
        return Ok(false);
    }

    crate::scoped_log!(
        info,
        "executor:hymofs",
        "apply: mirror_path={}, hymofs_modules={}, runtime_requested={}",
        config.hymofs.mirror_path.display(),
        plan.hymofs_module_ids.len(),
        runtime_requested
    );

    let compiled = if mount_mapping_requested(plan) {
        compile_rules(modules, plan, config)?
    } else {
        CompiledRules::default()
    };
    let user_hide_paths = user_hide_rules::load_user_hide_rules()?;
    let tree_dump = render_compiled_tree(
        &compiled,
        config.hymofs.mirror_path.as_path(),
        &user_hide_paths,
    );

    plan.hymofs_add_rules = compiled.add_rules;
    plan.hymofs_merge_rules = compiled.merge_rules;
    plan.hymofs_hide_rules = compiled.hide_rules;

    if let Some(tree_dump) = tree_dump {
        crate::scoped_log!(debug, "executor:hymofs", "compiled tree: {}", tree_dump);
    }

    hymofs::set_mirror_path(&config.hymofs.mirror_path)?;
    hymofs::clear_rules()?;
    if let Err(err) = hymofs::clear_maps_rules() {
        crate::scoped_log!(
            debug,
            "executor:hymofs",
            "maps rule clear skipped: error={:#}",
            err
        );
    }

    let features = get_features();
    log_feature_summary(features);
    if !runtime_requested {
        hymofs::set_enabled(false)?;
        crate::scoped_log!(
            info,
            "executor:hymofs",
            "apply skipped: reason=no_runtime_request"
        );
        return Ok(false);
    }

    apply_runtime_switches(config, true, features)?;
    apply_spoof_settings(config, features)?;

    for rule in &plan.hymofs_add_rules {
        hymofs::add_rule(Path::new(&rule.target), &rule.source, rule.file_type)?;
    }
    for rule in &plan.hymofs_merge_rules {
        hymofs::add_merge_rule(Path::new(&rule.target), &rule.source)?;
    }
    for path in &plan.hymofs_hide_rules {
        hymofs::hide_path(Path::new(path))?;
    }

    let (user_hide_applied, user_hide_failed) =
        user_hide_rules::apply_user_hide_rules_from_paths(&user_hide_paths)?;

    hymofs::set_enabled(runtime_requested)?;
    if runtime_requested && let Err(err) = hymofs::fix_mounts() {
        crate::scoped_log!(
            debug,
            "executor:hymofs",
            "fix_mounts skipped: error={:#}",
            err
        );
    }

    crate::scoped_log!(
        info,
        "executor:hymofs",
        "apply complete: enabled={}, add_rules={}, merge_rules={}, hide_rules={}, maps_rules={}, kstat_rules={}",
        runtime_requested,
        plan.hymofs_add_rules.len(),
        plan.hymofs_merge_rules.len(),
        plan.hymofs_hide_rules.len(),
        config.hymofs.maps_rules.len(),
        config.hymofs.kstat_rules.len()
    );

    if user_hide_applied > 0 || user_hide_failed > 0 {
        crate::scoped_log!(
            info,
            "executor:hymofs",
            "user hide rules: applied={}, failed={}",
            user_hide_applied,
            user_hide_failed
        );
    }

    if runtime_requested {
        match hymofs::get_hooks() {
            Ok(hooks) => crate::scoped_log!(
                debug,
                "executor:hymofs",
                "hooks: {}",
                hooks
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Err(err) => crate::scoped_log!(
                debug,
                "executor:hymofs",
                "hook query skipped: error={:#}",
                err
            ),
        }
    }

    Ok(runtime_requested)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use tempfile::tempdir;

    use super::{
        CompiledRules, auxiliary_features_requested, compile_rules_with_root,
        hymofs_runtime_requested, mount_mapping_requested, render_compiled_tree,
    };
    use crate::{
        conf::{
            config::{Config, ModuleRules, MountMode},
            schema::HymoMapsRuleConfig,
        },
        core::{inventory::Module, ops::planner::MountPlan},
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
        // Config::default() enables stealth by default; clear every auxiliary
        // feature so this test actually exercises the "no mapping, no feature"
        // path rather than tripping on an unrelated default.
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
        fs::create_dir_all(system_root.join("system/bin"))
            .expect("failed to create fake system bin");
        fs::create_dir_all(system_root.join("system/etc"))
            .expect("failed to create fake system etc");

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
        fs::create_dir_all(system_root.join("system/bin"))
            .expect("failed to create fake system bin");

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
            add_rules: vec![crate::core::ops::planner::HymofsAddRule {
                target: "/system/bin/sh".to_string(),
                source: PathBuf::from("/dev/hymo_mirror/mod_a/system/bin/sh"),
                file_type: libc::DT_REG as i32,
            }],
            merge_rules: vec![crate::core::ops::planner::HymofsMergeRule {
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
}
