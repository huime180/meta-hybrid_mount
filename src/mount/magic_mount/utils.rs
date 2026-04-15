// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::HashSet,
    fs::{self, DirEntry, Metadata, create_dir, create_dir_all, read_link},
    io::{BufRead, BufReader},
    os::unix::fs::{MetadataExt, symlink},
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use rustix::fs::{Gid, Mode, Uid, chmod, chown};
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::mount::mount_bind;

use crate::{
    core::inventory,
    mount::node::Node,
    sys::fs::{lgetfilecon, lsetfilecon},
    utils::validate_module_id,
};

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn mount_bind<P, Q>(_from: P, _to: Q) -> Result<()>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    bail!("bind mount is only supported on linux/android")
}

fn metadata_path<P>(path: P, node: &Node) -> Result<(Metadata, PathBuf)>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    if path.exists() {
        Ok((path.metadata()?, path.to_path_buf()))
    } else if let Some(module_path) = &node.module_path {
        Ok((module_path.metadata()?, module_path.clone()))
    } else {
        bail!("cannot mount root dir {}!", path.display());
    }
}

pub fn tmpfs_skeleton<P>(path: P, work_dir_path: P, node: &Node) -> Result<()>
where
    P: AsRef<Path>,
{
    let (path, work_dir_path) = (path.as_ref(), work_dir_path.as_ref());
    crate::scoped_log!(
        debug,
        "magic:collect",
        "tmpfs skeleton: src={}, dst={}",
        path.display(),
        work_dir_path.display()
    );

    create_dir_all(work_dir_path)?;

    let (metadata, path) = metadata_path(path, node)?;

    chmod(work_dir_path, Mode::from_raw_mode(metadata.mode() as _))?;
    chown(
        work_dir_path,
        Some(Uid::from_raw(metadata.uid())),
        Some(Gid::from_raw(metadata.gid())),
    )?;
    lsetfilecon(work_dir_path, lgetfilecon(path)?.as_str())?;

    Ok(())
}

pub fn mount_mirror<P>(path: P, work_dir_path: P, entry: &DirEntry) -> Result<()>
where
    P: AsRef<Path>,
{
    let path = path.as_ref().join(entry.file_name());
    let work_dir_path = work_dir_path.as_ref().join(entry.file_name());
    let file_type = entry.file_type()?;

    if file_type.is_file() {
        crate::scoped_log!(
            debug,
            "magic:collect",
            "mirror file: src={}, dst={}",
            path.display(),
            work_dir_path.display()
        );
        fs::File::create(&work_dir_path)?;
        mount_bind(&path, &work_dir_path)?;
    } else if file_type.is_dir() {
        crate::scoped_log!(
            debug,
            "magic:collect",
            "mirror dir: src={}, dst={}",
            path.display(),
            work_dir_path.display()
        );
        create_dir(&work_dir_path)?;
        let metadata = entry.metadata()?;
        chmod(&work_dir_path, Mode::from_raw_mode(metadata.mode() as _))?;
        chown(
            &work_dir_path,
            Some(Uid::from_raw(metadata.uid())),
            Some(Gid::from_raw(metadata.gid())),
        )?;
        lsetfilecon(&work_dir_path, lgetfilecon(&path)?.as_str())?;
        for entry_result in path.read_dir()? {
            let entry = match entry_result {
                Ok(entry) => entry,
                Err(err) => {
                    crate::scoped_log!(
                        warn,
                        "magic:collect",
                        "enumerate mirror failed: path={}, error={}",
                        path.display(),
                        err
                    );
                    continue;
                }
            };
            mount_mirror(&path, &work_dir_path, &entry)?;
        }
    } else if file_type.is_symlink() {
        crate::scoped_log!(
            debug,
            "magic:collect",
            "mirror symlink: src={}, dst={}",
            path.display(),
            work_dir_path.display()
        );
        clone_symlink(&path, &work_dir_path)?;
    }

    Ok(())
}

pub fn collect_module_files(
    module_dir: &Path,
    extra_partitions: &[String],
    need_id: HashSet<String>,
) -> Result<Option<Node>> {
    let mut root = Node::new_root("");
    let mut system = Node::new_root("system");
    let module_root = module_dir;
    let mut has_file = HashSet::new();
    let mut partitions = HashSet::new();
    partitions.insert("system".to_string());
    partitions.extend(extra_partitions.iter().cloned());

    crate::scoped_log!(
        debug,
        "magic:collect",
        "start: root={}",
        module_root.display()
    );

    for entry_result in module_root.read_dir()? {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(err) => {
                crate::scoped_log!(
                    warn,
                    "magic:collect",
                    "enumerate root failed: path={}, error={}",
                    module_root.display(),
                    err
                );
                continue;
            }
        };
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let file_name = entry.file_name();
        let Some(id) = file_name.to_str().map(str::to_owned) else {
            crate::scoped_log!(
                warn,
                "magic:collect",
                "skip: reason=non_utf8_module_dir, name={:?}",
                file_name
            );
            continue;
        };
        crate::scoped_log!(debug, "magic:collect", "module inspect: id={}", id);

        if !need_id.contains(&id) {
            crate::scoped_log!(
                debug,
                "magic:collect",
                "module skip: id={}, reason=not_selected",
                id
            );
            continue;
        }

        let module_path = entry.path();
        let prop = module_path.join("module.prop");
        if !prop.is_file() {
            crate::scoped_log!(
                debug,
                "magic:collect",
                "module skip: id={}, reason=missing_module_prop",
                id
            );
            continue;
        }
        if !is_valid_module_prop_id(&prop)? {
            crate::scoped_log!(
                debug,
                "magic:collect",
                "module skip: id={}, reason=invalid_module_id",
                id
            );
            continue;
        }

        if inventory::is_reserved_module_dir(&id) || inventory::has_mount_block_marker(&module_path)
        {
            crate::scoped_log!(
                debug,
                "magic:collect",
                "module skip: id={}, reason=blocked_or_reserved",
                id
            );
            continue;
        }

        let touched_partitions: Vec<String> = partitions
            .iter()
            .filter(|p| module_path.join(p).is_dir())
            .cloned()
            .collect();

        if touched_partitions.is_empty() {
            for p in &partitions {
                crate::scoped_log!(
                    debug,
                    "magic:collect",
                    "partition untouched: module={}, partition={}",
                    id,
                    p
                );
            }
            continue;
        }

        crate::scoped_log!(
            debug,
            "magic:collect",
            "module collect: path={}",
            module_path.display()
        );

        for p in touched_partitions {
            has_file.insert(system.collect_module_files(module_path.join(p))?);
        }
    }

    if has_file.contains(&true) {
        const BUILTIN_PARTITIONS: [(&str, bool); 4] = [
            ("vendor", true),
            ("system_ext", true),
            ("product", true),
            ("odm", false),
        ];

        for (partition, require_symlink) in BUILTIN_PARTITIONS {
            let path_of_root = Path::new("/").join(partition);
            let path_of_system = Path::new("/system").join(partition);
            if path_of_root.is_dir() && (!require_symlink || path_of_system.is_symlink()) {
                let name = partition.to_string();
                if let Some(node) = system.children.remove(&name) {
                    root.children.insert(name, node);
                }
            }
        }

        for partition in extra_partitions {
            if BUILTIN_PARTITIONS.iter().any(|(p, _)| p == partition) {
                continue;
            }
            if partition == "system" {
                continue;
            }

            let path_of_root = Path::new("/").join(partition);
            let path_of_system = Path::new("/system").join(partition);
            let require_symlink = false;

            if path_of_root.is_dir() && (!require_symlink || path_of_system.is_symlink()) {
                let name = partition.clone();
                if let Some(node) = system.children.remove(&name) {
                    crate::scoped_log!(
                        debug,
                        "magic:collect",
                        "attach extra partition: name={}",
                        name
                    );
                    root.children.insert(name, node);
                }
            }
        }

        root.children.insert("system".to_string(), system);
        Ok(Some(root))
    } else {
        Ok(None)
    }
}

fn is_valid_module_prop_id(prop: &Path) -> Result<bool> {
    let file = fs::File::open(prop)?;
    for line_result in BufReader::new(file).lines() {
        let line = match line_result {
            Ok(line) => line,
            Err(e) => {
                crate::scoped_log!(
                    warn,
                    "magic:collect",
                    "read module.prop failed: path={}, error={}",
                    prop.display(),
                    e
                );
                return Ok(false);
            }
        };
        if line.starts_with("id")
            && let Some((_, value)) = line.split_once('=')
        {
            return Ok(validate_module_id(value).is_ok());
        }
    }
    Ok(true)
}

pub fn clone_symlink<S>(src: S, dst: S) -> Result<()>
where
    S: AsRef<Path>,
{
    let src_symlink = read_link(src.as_ref())?;
    symlink(&src_symlink, dst.as_ref())?;
    lsetfilecon(dst.as_ref(), lgetfilecon(src.as_ref())?.as_str())?;
    crate::scoped_log!(
        debug,
        "magic:collect",
        "clone symlink: dst={}, src={}, target={}",
        dst.as_ref().display(),
        src.as_ref().display(),
        src_symlink.display()
    );
    Ok(())
}
