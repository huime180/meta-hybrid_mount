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

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::sync::OnceLock;
use std::{
    collections::HashMap,
    fs,
    path::{Component, Path, PathBuf},
};
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
static TMPFS_XATTR_SUPPORTED: OnceLock<bool> = OnceLock::new();

#[derive(Debug, Default)]
pub struct LiveContextCache {
    resolved_paths: HashMap<PathBuf, PathBuf>,
    resolved_contexts: HashMap<PathBuf, Option<(PathBuf, String)>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveContextSourceKind {
    Exact,
    AncestorFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveContextApplyOutcome {
    SkippedUnmanaged,
    MissingTarget,
    MissingSet {
        reason: String,
    },
    MissingContext {
        target_path: PathBuf,
        target_dir: PathBuf,
    },
    Applied {
        source: PathBuf,
        kind: LiveContextSourceKind,
    },
    ApplyFailed {
        source: PathBuf,
        kind: LiveContextSourceKind,
    },
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn copy_extended_attributes(src: &Path, dst: &Path) -> Result<()> {
    if let Ok(ctx) = lgetfilecon(src)
        && let Err(err) = lsetfilecon(dst, &ctx)
    {
        crate::scoped_log!(
            debug,
            "selinux:context",
            "copy context skipped: src={}, dst={}, error={:#}",
            src.display(),
            dst.display(),
            err
        );
    }

    if let Ok(opaque) = lgetxattr(src, OVERLAY_OPAQUE_XATTR)
        && let Err(err) = lsetxattr(dst, OVERLAY_OPAQUE_XATTR, &opaque, XattrFlags::empty())
    {
        crate::scoped_log!(
            debug,
            "xattr",
            "copy opaque xattr skipped: src={}, dst={}, error={}",
            src.display(),
            dst.display(),
            err
        );
    }
    if let Ok(xattrs) = llistxattr(src) {
        for xattr_name in xattrs {
            let name_bytes = xattr_name.as_bytes();
            let name_str = String::from_utf8_lossy(name_bytes);

            if name_str.starts_with("trusted.overlay.")
                && name_str != OVERLAY_OPAQUE_XATTR
                && let Ok(val) = lgetxattr(src, &xattr_name)
                && let Err(err) = lsetxattr(dst, &xattr_name, &val, XattrFlags::empty())
            {
                crate::scoped_log!(
                    debug,
                    "xattr",
                    "copy overlay xattr skipped: name={}, src={}, dst={}, error={}",
                    name_str,
                    src.display(),
                    dst.display(),
                    err
                );
            }
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn copy_extended_attributes(_src: &Path, _dst: &Path) -> Result<()> {
    Ok(())
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
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn lsetfilecon<P: AsRef<Path>>(path: P, con: &str) -> Result<()> {
    lsetxattr(
        path.as_ref(),
        SELINUX_XATTR,
        con.as_bytes(),
        XattrFlags::empty(),
    )
    .with_context(|| {
        format!(
            "Failed to set SELinux context for {} to {}",
            path.as_ref().display(),
            con
        )
    })?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn lsetfilecon<P: AsRef<Path>>(_path: P, _con: &str) -> Result<()> {
    anyhow::bail!("SELinux context writes are only supported on linux/android");
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
    anyhow::bail!("SELinux context reads are only supported on linux/android");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn is_overlay_xattr_supported() -> Result<bool> {
    if let Some(cached) = TMPFS_XATTR_SUPPORTED.get() {
        return Ok(*cached);
    }

    use flate2::read::GzDecoder;
    let file = fs::File::open("/proc/config.gz")?;

    let mut config = String::new();
    let mut decoder = GzDecoder::new(file);
    decoder.read_to_string(&mut config)?;

    let supported = config.lines().any(|line| {
        if line.starts_with('#') {
            return false;
        }

        let Some((k, v)) = line.split_once('=') else {
            return false;
        };

        k.trim() == "CONFIG_TMPFS_XATTR" && v.trim() == "y"
    });

    let _ = TMPFS_XATTR_SUPPORTED.set(supported);

    Ok(supported)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn is_overlay_xattr_supported() -> Result<bool> {
    Ok(false)
}

pub fn internal_copy_extended_attributes(src: &Path, dst: &Path) -> Result<()> {
    copy_extended_attributes(src, dst)
}

fn managed_partition_start(relative: &Path, managed_partitions: &[String]) -> Option<usize> {
    let components: Vec<_> = relative.components().collect();
    let first = components.first().and_then(|component| match component {
        Component::Normal(value) => value.to_str(),
        _ => None,
    });
    if first.is_some_and(|value| managed_partitions.iter().any(|item| item == value)) {
        return Some(0);
    }

    let second = components.get(1).and_then(|component| match component {
        Component::Normal(value) => value.to_str(),
        _ => None,
    });
    if first.is_some_and(|value| value.starts_with("module"))
        && second.is_some_and(|value| managed_partitions.iter().any(|item| item == value))
    {
        return Some(1);
    }

    None
}

fn should_apply_live_context(relative: &Path, managed_partitions: &[String]) -> bool {
    managed_partition_start(relative, managed_partitions).is_some()
}

fn resolve_target_path(path: &Path) -> PathBuf {
    let resolved = match fs::read_link(path) {
        Ok(link_target) => {
            if link_target.is_absolute() {
                link_target
            } else {
                path.parent().unwrap_or(Path::new("/")).join(link_target)
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

fn resolve_target_path_cached(path: &Path, cache: &mut LiveContextCache) -> PathBuf {
    if let Some(cached) = cache.resolved_paths.get(path) {
        return cached.clone();
    }

    let resolved = resolve_target_path(path);
    cache
        .resolved_paths
        .insert(path.to_path_buf(), resolved.clone());
    resolved
}

fn resolve_live_target_with_root_cached(
    relative: &Path,
    managed_partitions: &[String],
    root: &Path,
    dst_is_dir: bool,
    cache: &mut LiveContextCache,
) -> Option<(PathBuf, PathBuf)> {
    let components: Vec<_> = relative.components().collect();
    let start_idx = managed_partition_start(relative, managed_partitions)?;

    let partition_root = root.join(components[start_idx].as_os_str());
    if fs::symlink_metadata(&partition_root).is_err() {
        return None;
    }

    let resolved_partition_root = resolve_target_path_cached(&partition_root, cache);
    let mut current = resolved_partition_root.clone();
    let tail = &components[start_idx + 1..];

    if tail.is_empty() {
        return Some((resolved_partition_root, current));
    }

    let resolve_count = if dst_is_dir {
        tail.len()
    } else {
        tail.len().saturating_sub(1)
    };

    for component in tail.iter().take(resolve_count) {
        current = resolve_target_path_cached(&current.join(component.as_os_str()), cache);
    }

    let target_path = if dst_is_dir {
        current
    } else {
        tail.last()
            .map(|leaf| current.join(leaf.as_os_str()))
            .unwrap_or(current)
    };

    Some((resolved_partition_root, target_path))
}

#[cfg(test)]
fn resolve_live_target_path_with_root(
    relative: &Path,
    managed_partitions: &[String],
    root: &Path,
    dst_is_dir: bool,
) -> Option<PathBuf> {
    let mut cache = LiveContextCache::default();
    resolve_live_target_with_root_cached(relative, managed_partitions, root, dst_is_dir, &mut cache)
        .map(|(_, target_path)| target_path)
}

fn resolved_target_directory(target_path: &Path, dst_is_dir: bool) -> PathBuf {
    if dst_is_dir {
        return target_path.to_path_buf();
    }

    target_path
        .parent()
        .map(|parent| parent.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn prefer_exact_target_context_path(target_path: &Path, dst_is_dir: bool) -> PathBuf {
    if dst_is_dir || fs::symlink_metadata(target_path).is_ok() {
        return target_path.to_path_buf();
    }

    target_path
        .parent()
        .map(|parent| parent.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn resolve_live_target_directory_context_cached(
    target_dir: &Path,
    target_root: &Path,
    cache: &mut LiveContextCache,
) -> Option<(PathBuf, String)> {
    if let Some(cached) = cache.resolved_contexts.get(target_dir) {
        return cached.clone();
    }

    let mut current = target_dir.to_path_buf();
    let mut traversed = Vec::new();

    let resolved = loop {
        if let Some(cached) = cache.resolved_contexts.get(&current) {
            break cached.clone();
        }

        traversed.push(current.clone());
        if let Ok(context) = lgetfilecon(&current) {
            break Some((current.clone(), context));
        }

        if current == target_root {
            break None;
        }

        let Some(parent) = current.parent() else {
            break None;
        };
        current = if parent.as_os_str().is_empty() {
            PathBuf::from("/")
        } else {
            parent.to_path_buf()
        };
    };

    for path in traversed {
        cache.resolved_contexts.insert(path, resolved.clone());
    }

    resolved
}

fn resolve_live_target_context_cached(
    target_path: &Path,
    target_root: &Path,
    dst_is_dir: bool,
    cache: &mut LiveContextCache,
) -> Option<(PathBuf, String)> {
    if let Some(cached) = cache.resolved_contexts.get(target_path) {
        return cached.clone();
    }

    if !dst_is_dir
        && fs::symlink_metadata(target_path).is_ok()
        && let Ok(context) = lgetfilecon(target_path)
    {
        let resolved = Some((target_path.to_path_buf(), context));
        cache
            .resolved_contexts
            .insert(target_path.to_path_buf(), resolved.clone());
        return resolved;
    }

    let target_dir = prefer_exact_target_context_path(target_path, dst_is_dir);
    let resolved = resolve_live_target_directory_context_cached(&target_dir, target_root, cache);
    cache
        .resolved_contexts
        .insert(target_path.to_path_buf(), resolved.clone());
    resolved
}

fn live_context_source_kind(target_path: &Path, source: &Path) -> LiveContextSourceKind {
    if source == target_path {
        LiveContextSourceKind::Exact
    } else {
        LiveContextSourceKind::AncestorFallback
    }
}

pub fn apply_best_effort_live_context_with_cache(
    dst: &Path,
    relative: &Path,
    managed_partitions: &[String],
    cache: &mut LiveContextCache,
) -> LiveContextApplyOutcome {
    if !should_apply_live_context(relative, managed_partitions) {
        return LiveContextApplyOutcome::SkippedUnmanaged;
    }

    let relative_display = if relative.as_os_str().is_empty() {
        "/".to_string()
    } else {
        relative.display().to_string()
    };
    let dst_is_dir = fs::symlink_metadata(dst)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or_else(|_| dst.is_dir());

    let Some((target_root, target_path)) = resolve_live_target_with_root_cached(
        relative,
        managed_partitions,
        Path::new("/"),
        dst_is_dir,
        cache,
    ) else {
        if dst_is_dir {
            crate::scoped_log!(
                warn,
                "selinux:context",
                "target resolve failed: relative={}, dst={}",
                relative_display,
                dst.display()
            );
        } else {
            crate::scoped_log!(
                debug,
                "selinux:context",
                "target resolve failed: relative={}, dst={}",
                relative_display,
                dst.display()
            );
        }
        return LiveContextApplyOutcome::MissingTarget;
    };

    let target_dir = resolved_target_directory(&target_path, dst_is_dir);

    if let Some((source, context)) =
        resolve_live_target_context_cached(&target_path, &target_root, dst_is_dir, cache)
    {
        if (context.contains("same_process_hal_file")
            | context.contains("vendor_file")
            | context.contains("lib_file"))
            && dst.ends_with("so")
        {
            return LiveContextApplyOutcome::MissingSet {
                reason: format!(
                    "skip set {} to {}, because it like the driver",
                    dst.display(),
                    context
                ),
            };
        }
        let kind = live_context_source_kind(&target_path, &source);

        if dst_is_dir {
            crate::scoped_log!(
                info,
                "selinux:context",
                "resolved: relative={}, dst={}, target_path={}, target_dir={}, live_source={}, live_context={}, source_kind={}",
                relative_display,
                dst.display(),
                target_path.display(),
                target_dir.display(),
                source.display(),
                context,
                match kind {
                    LiveContextSourceKind::Exact => "exact",
                    LiveContextSourceKind::AncestorFallback => "ancestor_fallback",
                }
            );
        } else {
            crate::scoped_log!(
                debug,
                "selinux:context",
                "resolved: relative={}, dst={}, target_path={}, target_dir={}, live_source={}, live_context={}, source_kind={}",
                relative_display,
                dst.display(),
                target_path.display(),
                target_dir.display(),
                source.display(),
                context,
                match kind {
                    LiveContextSourceKind::Exact => "exact",
                    LiveContextSourceKind::AncestorFallback => "ancestor_fallback",
                }
            );
        }

        if let Err(err) = lsetfilecon(dst, &context) {
            crate::scoped_log!(
                warn,
                "selinux:context",
                "apply failed: relative={}, dst={}, live_source={}, source_kind={}, error={:#}",
                relative_display,
                dst.display(),
                source.display(),
                match kind {
                    LiveContextSourceKind::Exact => "exact",
                    LiveContextSourceKind::AncestorFallback => "ancestor_fallback",
                },
                err
            );
            return LiveContextApplyOutcome::ApplyFailed { source, kind };
        }

        return LiveContextApplyOutcome::Applied { source, kind };
    }

    if dst_is_dir {
        crate::scoped_log!(
            warn,
            "selinux:context",
            "context resolve failed: relative={}, dst={}, target_path={}, target_dir={}, live_source=<none>, live_context=<none>",
            relative_display,
            dst.display(),
            target_path.display(),
            target_dir.display()
        );
    } else {
        crate::scoped_log!(
            debug,
            "selinux:context",
            "context resolve failed: relative={}, dst={}, target_path={}, target_dir={}, live_source=<none>, live_context=<none>",
            relative_display,
            dst.display(),
            target_path.display(),
            target_dir.display()
        );
    }

    LiveContextApplyOutcome::MissingContext {
        target_path,
        target_dir,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::{fs, path::Path};

    use tempfile::tempdir;

    use super::{
        LiveContextApplyOutcome, LiveContextCache, apply_best_effort_live_context_with_cache,
        resolve_live_target_path_with_root, resolved_target_directory, should_apply_live_context,
    };

    #[test]
    fn apply_best_effort_live_context_skips_unmanaged_paths() {
        let dst_root = tempdir().expect("failed to create temp root");
        let dst = dst_root.path().join("module.prop");
        fs::write(&dst, "name=demo").expect("failed to create dst file");

        let managed = vec!["system".to_string(), "vendor".to_string()];
        let mut cache = LiveContextCache::default();

        let outcome = apply_best_effort_live_context_with_cache(
            &dst,
            Path::new("module.prop"),
            &managed,
            &mut cache,
        );

        assert_eq!(outcome, LiveContextApplyOutcome::SkippedUnmanaged);
    }

    #[test]
    fn apply_best_effort_live_context_reports_missing_target_for_absent_partition_root() {
        let dst_root = tempdir().expect("failed to create temp root");
        let dst = dst_root.path().join("system");
        fs::create_dir_all(&dst).expect("failed to create dst dir");

        let managed = vec!["__codex_missing_partition__".to_string()];
        let mut cache = LiveContextCache::default();

        let outcome = apply_best_effort_live_context_with_cache(
            &dst,
            Path::new("__codex_missing_partition__/path"),
            &managed,
            &mut cache,
        );

        assert_eq!(outcome, LiveContextApplyOutcome::MissingTarget);
    }

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
            false,
        )
        .expect("target should resolve");

        assert_eq!(target, rootfs.join("vendor/firmware/gen80000_sqe.fw"));
    }

    #[test]
    #[cfg(unix)]
    fn resolve_live_target_path_preserves_leaf_symlink_for_file_nodes() {
        let root = tempdir().expect("failed to create temp root");
        let rootfs = root.path().join("rootfs");
        fs::create_dir_all(rootfs.join("system/bin")).expect("failed to create /system/bin");
        fs::write(rootfs.join("system/bin/toybox"), b"toybox").expect("failed to write toybox");
        symlink("toybox", rootfs.join("system/bin/sh"))
            .expect("failed to create /system/bin/sh symlink");

        let managed = vec!["system".to_string()];
        let target = resolve_live_target_path_with_root(
            Path::new("system/bin/sh"),
            &managed,
            &rootfs,
            false,
        )
        .expect("target should resolve");

        assert_eq!(target, rootfs.join("system/bin/sh"));
    }

    #[test]
    #[cfg(unix)]
    fn resolve_live_target_path_resolves_leaf_symlink_for_directory_nodes() {
        let root = tempdir().expect("failed to create temp root");
        let rootfs = root.path().join("rootfs");
        fs::create_dir_all(rootfs.join("system")).expect("failed to create /system");
        fs::create_dir_all(rootfs.join("vendor")).expect("failed to create /vendor");
        symlink("../vendor", rootfs.join("system/vendor"))
            .expect("failed to create /system/vendor symlink");

        let managed = vec!["system".to_string(), "vendor".to_string()];
        let target =
            resolve_live_target_path_with_root(Path::new("system/vendor"), &managed, &rootfs, true)
                .expect("target should resolve");

        assert_eq!(target, rootfs.join("vendor"));
    }

    #[test]
    fn resolved_target_directory_uses_file_parent_for_file_nodes() {
        let root = tempdir().expect("failed to create temp root");
        let rootfs = root.path().join("rootfs");
        fs::create_dir_all(rootfs.join("vendor/etc/permissions"))
            .expect("failed to create target directory");

        let file_target_dir =
            resolved_target_directory(&rootfs.join("vendor/etc/permissions/com.test.xml"), false);
        assert_eq!(file_target_dir, rootfs.join("vendor/etc/permissions"));

        let dir_target_dir =
            resolved_target_directory(&rootfs.join("vendor/etc/permissions"), true);
        assert_eq!(dir_target_dir, rootfs.join("vendor/etc/permissions"));
    }

    #[test]
    fn live_context_only_applies_to_managed_partition_paths() {
        let managed = vec![
            "system".to_string(),
            "product".to_string(),
            "vendor".to_string(),
        ];

        assert!(should_apply_live_context(
            Path::new("system/app/AnalyticsCore"),
            &managed
        ));
        assert!(should_apply_live_context(
            Path::new("module_a/vendor/etc/permissions/com.test.xml"),
            &managed
        ));
        assert!(!should_apply_live_context(Path::new("Host"), &managed));
        assert!(!should_apply_live_context(
            Path::new("mod/ads_monitor"),
            &managed
        ));
        assert!(!should_apply_live_context(Path::new("tools"), &managed));
    }
}
