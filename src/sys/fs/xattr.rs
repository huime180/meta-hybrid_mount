// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Component, Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{fs, io::Read, os::unix::ffi::OsStrExt};

#[cfg(any(target_os = "linux", target_os = "android"))]
use anyhow::Context;
use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "android"))]
use extattr::{Flags as XattrFlags, lgetxattr, llistxattr, lsetxattr};

#[cfg(any(target_os = "linux", target_os = "android"))]
const SELINUX_XATTR: &str = "security.selinux";
#[cfg(any(target_os = "linux", target_os = "android"))]
const OVERLAY_OPAQUE_XATTR: &str = "trusted.overlay.opaque";
const LEGACY_SYSTEM_FILE_CONTEXT: &str = "u:object_r:system_file:s0";

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

fn logical_live_candidates(relative: &Path, managed_partitions: &[String]) -> Vec<PathBuf> {
    let components: Vec<_> = relative.components().collect();
    let Some(start_idx) = components.iter().position(|component| {
        let Component::Normal(value) = component else {
            return false;
        };
        let Some(value) = value.to_str() else {
            return false;
        };
        managed_partitions.iter().any(|item| item == value)
    }) else {
        return Vec::new();
    };

    let mut current = PathBuf::from("/");
    for component in components.iter().skip(start_idx) {
        current.push(component.as_os_str());
    }

    let mut candidates = Vec::new();
    loop {
        candidates.push(current.clone());

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

    candidates
}

fn is_legacy_system_vendor_firmware_path(relative: &Path) -> bool {
    let components: Vec<_> = relative.components().collect();
    components.windows(3).any(|window| {
        let [a, b, c] = window else {
            return false;
        };
        &&matches!(c, Component::Normal(v) if v.to_str() == Some("firmware"))
    })
}

pub fn apply_best_effort_live_context(
    dst: &Path,
    relative: &Path,
    managed_partitions: &[String],
) -> Result<()> {
    if is_legacy_system_vendor_firmware_path(relative) {
        let _ = lsetfilecon(dst, LEGACY_SYSTEM_FILE_CONTEXT);
        return Ok(());
    }

    for candidate in logical_live_candidates(relative, managed_partitions) {
        if let Ok(context) = lgetfilecon(&candidate) {
            let _ = lsetfilecon(dst, &context);
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{is_legacy_system_vendor_firmware_path, logical_live_candidates};

    #[test]
    fn logical_live_candidates_skip_module_root_and_walk_parents() {
        let managed = vec![
            "system".to_string(),
            "product".to_string(),
            "vendor".to_string(),
        ];

        let candidates = logical_live_candidates(
            Path::new("module_a/system/product/overlay/Foo.apk"),
            &managed,
        );

        assert_eq!(
            candidates,
            vec![
                Path::new("/system/product/overlay/Foo.apk").to_path_buf(),
                Path::new("/system/product/overlay").to_path_buf(),
                Path::new("/system/product").to_path_buf(),
                Path::new("/system").to_path_buf(),
                Path::new("/").to_path_buf(),
            ]
        );
    }

    #[test]
    fn legacy_system_vendor_firmware_path_matches_only_target_prefix() {
        assert!(is_legacy_system_vendor_firmware_path(Path::new(
            "module_a/system/vendor/firmware/gen80000_sqe.fw"
        )));
        assert!(!is_legacy_system_vendor_firmware_path(Path::new(
            "module_a/vendor/firmware/gen80000_sqe.fw"
        )));
        assert!(!is_legacy_system_vendor_firmware_path(Path::new(
            "module_a/system/vendor/lib64/libGLESv2_adreno.so"
        )));
    }
}
