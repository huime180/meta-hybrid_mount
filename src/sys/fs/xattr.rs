// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{fs, path::{Component, Path, PathBuf}};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{io::Read, os::unix::ffi::OsStrExt};

#[cfg(any(target_os = "linux", target_os = "android"))]
use anyhow::Context;
use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "android"))]
use extattr::{Flags as XattrFlags, lgetxattr, llistxattr, lsetxattr};

#[cfg(any(target_os = "linux", target_os = "android"))]
const SELINUX_XATTR: &str = "security.selinux";
#[cfg(any(target_os = "linux", target_os = "android"))]
const OVERLAY_OPAQUE_XATTR: &str = "trusted.overlay.opaque";

#[cfg(any(target_os = "linux", target_os = "android"))]
fn copy_extended_attributes(src: &Path, dst: &Path) -> Result<()> {
    if let Ok(ctx) = lgetfilecon(src) {
        let _ = lsetfilecon(dst, &ctx);
    }

    if let Ok(opaque) = lgetxattr(src, OVERLAY_OPAQUE_XATTR) {
        let _ = lsetxattr(dst, OVERLAY_OPAQUE_XATTR, &opaque, XattrFlags::empty());
    }
    if let Ok(xattrs) = llistxattr(src) {
        for xattr_name in xattrs {
            let name_bytes = xattr_name.as_bytes();
            let name_str = String::from_utf8_lossy(name_bytes);

            if name_str.starts_with("trusted.overlay.")
                && name_str != OVERLAY_OPAQUE_XATTR
                && let Ok(val) = lgetxattr(src, &xattr_name)
            {
                let _ = lsetxattr(dst, &xattr_name, &val, XattrFlags::empty());
            }
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn copy_extended_attributes(_src: &Path, _dst: &Path) -> Result<()> {
    unimplemented!();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_overlay_opaque<P: AsRef<Path>>(path: P) -> Result<()> {
    lsetxattr(
        path.as_ref(),
        OVERLAY_OPAQUE_XATTR,
        b"y",
        XattrFlags::empty(),
    )?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn set_overlay_opaque<P: AsRef<Path>>(_path: P) -> Result<()> {
    unimplemented!();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn lsetfilecon<P: AsRef<Path>>(path: P, con: &str) -> Result<()> {
    if let Err(e) = lsetxattr(
        path.as_ref(),
        SELINUX_XATTR,
        con.as_bytes(),
        XattrFlags::empty(),
    ) {
        let _ = e;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn lsetfilecon<P: AsRef<Path>>(_path: P, _con: &str) -> Result<()> {
    unimplemented!();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn lgetfilecon<P: AsRef<Path>>(path: P) -> Result<String> {
    let con = extattr::lgetxattr(path.as_ref(), SELINUX_XATTR).with_context(|| {
        format!(
            "Failed to get SELinux context for {}",
            path.as_ref().display()
        )
    })?;
    let con_str = String::from_utf8_lossy(&con).trim_matches('\0').to_string();

    Ok(con_str)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn lgetfilecon<P: AsRef<Path>>(_path: P) -> Result<String> {
    unimplemented!();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn is_overlay_xattr_supported() -> Result<bool> {
    use flate2::read::GzDecoder;
    let file = fs::File::open("/proc/config.gz")?;

    let mut config = String::new();
    let mut decoder = GzDecoder::new(file);
    decoder.read_to_string(&mut config)?;

    for i in config.lines() {
        if i.starts_with("#") {
            continue;
        }

        let Some((k, v)) = i.split_once('=') else {
            continue;
        };

        if k.trim() == "CONFIG_TMPFS_XATTR" && v.trim() == "y" {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn is_overlay_xattr_supported() -> Result<bool> {
    unimplemented!();
}

pub fn internal_copy_extended_attributes(src: &Path, dst: &Path) -> Result<()> {
    copy_extended_attributes(src, dst)
}

fn managed_partition_start(relative: &Path, managed_partitions: &[String]) -> Option<usize> {
    let components: Vec<_> = relative.components().collect();
    components.iter().position(|component| {
        let Component::Normal(value) = component else {
            return false;
        };
        let Some(value) = value.to_str() else {
            return false;
        };
        managed_partitions.iter().any(|item| item == value)
    })
}

fn resolve_target_path(path: &Path) -> PathBuf {
    let resolved = match fs::read_link(path) {
        Ok(link_target) => {
            if link_target.is_absolute() {
                link_target
            } else {
                path.parent()
                    .unwrap_or(Path::new("/"))
                    .join(link_target)
            }
        }
        Err(_) => path.to_path_buf(),
    };

    normalize_path(&resolved)
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    let mut saw_root = false;

    for component in path.components() {
        match component {
            Component::RootDir => {
                normalized.push(Path::new("/"));
                saw_root = true;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
                if saw_root && normalized.as_os_str().is_empty() {
                    normalized.push(Path::new("/"));
                }
            }
            Component::Normal(value) => normalized.push(value),
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
        }
    }

    if saw_root && normalized.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        normalized
    }
}

fn resolve_live_target_path_with_root(
    relative: &Path,
    managed_partitions: &[String],
    root: &Path,
) -> Option<PathBuf> {
    let components: Vec<_> = relative.components().collect();
    let start_idx = managed_partition_start(relative, managed_partitions)?;

    let mut current = resolve_target_path(&root.join(components[start_idx].as_os_str()));
    for component in components.iter().skip(start_idx + 1) {
        current = resolve_target_path(&current.join(component.as_os_str()));
    }

    Some(current)
}

fn resolve_target_directory_with_root(
    relative: &Path,
    dst_is_dir: bool,
    managed_partitions: &[String],
    root: &Path,
) -> Option<PathBuf> {
    let target_path = resolve_live_target_path_with_root(relative, managed_partitions, root)?;
    if dst_is_dir {
        return Some(target_path);
    }

    target_path
        .parent()
        .map(|parent| parent.to_path_buf())
        .or_else(|| Some(root.to_path_buf()))
}

fn resolve_live_target_directory_context(
    target_dir: &Path,
) -> Option<(PathBuf, String)> {
    let mut current = target_dir.to_path_buf();
    loop {
        if let Ok(context) = lgetfilecon(&current) {
            return Some((current, context));
        }

        if current == Path::new("/") {
            break;
        }

        let Some(parent) = current.parent() else {
            break;
        };
        current = if parent.as_os_str().is_empty() {
            PathBuf::from("/")
        } else {
            parent.to_path_buf()
        };
    }
    None
}

pub fn apply_best_effort_live_context(
    dst: &Path,
    relative: &Path,
    managed_partitions: &[String],
) -> Result<()> {
    let relative_display = if relative.as_os_str().is_empty() {
        "/".to_string()
    } else {
        relative.display().to_string()
    };
    let dst_is_dir = dst.is_dir();

    let Some(target_dir) =
        resolve_target_directory_with_root(relative, dst_is_dir, managed_partitions, Path::new("/"))
    else {
        if dst_is_dir {
            crate::scoped_log!(
                warn,
                "selinux:context",
                "target resolve failed: relative={}, dst={}",
                relative_display,
                dst.display()
            );
        }
        return Ok(());
    };

    if let Some((source, context)) = resolve_live_target_directory_context(&target_dir) {
        if dst_is_dir {
            crate::scoped_log!(
                info,
                "selinux:context",
                "resolved: relative={}, dst={}, target_dir={}, live_source={}, live_context={}",
                relative_display,
                dst.display(),
                target_dir.display(),
                source.display(),
                context
            );
        }
        let _ = lsetfilecon(dst, &context);
    } else if dst_is_dir {
        crate::scoped_log!(
            warn,
            "selinux:context",
            "context resolve failed: relative={}, dst={}, target_dir={}, live_source=<none>, live_context=<none>",
            relative_display,
            dst.display(),
            target_dir.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::{fs, path::Path};

    use tempfile::tempdir;

    use super::{resolve_live_target_path_with_root, resolve_target_directory_with_root};

    #[test]
    fn resolve_live_target_path_follows_system_vendor_symlink() {
        let root = tempdir().expect("failed to create temp root");
        let rootfs = root.path().join("rootfs");
        fs::create_dir_all(rootfs.join("system")).expect("failed to create /system");
        fs::create_dir_all(rootfs.join("vendor/firmware"))
            .expect("failed to create /vendor/firmware");
        #[cfg(unix)]
        symlink("../vendor", rootfs.join("system/vendor"))
            .expect("failed to create /system/vendor symlink");

        let managed = vec![
            "system".to_string(),
            "product".to_string(),
            "vendor".to_string(),
        ];

        let target = resolve_live_target_path_with_root(
            Path::new("module_a/system/vendor/firmware/gen80000_sqe.fw"),
            &managed,
            &rootfs,
        )
        .expect("target should resolve");

        assert_eq!(
            target,
            rootfs.join("vendor/firmware/gen80000_sqe.fw")
        );
    }

    #[test]
    fn resolve_target_directory_uses_file_parent_for_file_nodes() {
        let root = tempdir().expect("failed to create temp root");
        let rootfs = root.path().join("rootfs");
        fs::create_dir_all(rootfs.join("vendor/etc/permissions"))
            .expect("failed to create target directory");

        let managed = vec![
            "system".to_string(),
            "product".to_string(),
            "vendor".to_string(),
        ];

        let file_target_dir = resolve_target_directory_with_root(
            Path::new("module_a/vendor/etc/permissions/com.test.xml"),
            false,
            &managed,
            &rootfs,
        )
        .expect("file target dir should resolve");
        assert_eq!(file_target_dir, rootfs.join("vendor/etc/permissions"));

        let dir_target_dir = resolve_target_directory_with_root(
            Path::new("module_a/vendor/etc/permissions"),
            true,
            &managed,
            &rootfs,
        )
        .expect("dir target dir should resolve");
        assert_eq!(dir_target_dir, rootfs.join("vendor/etc/permissions"));
    }
}
