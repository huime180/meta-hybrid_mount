// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{LazyLock, Mutex, atomic::Ordering},
    thread,
    time::Duration,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{ffi::CString, io::Read, os::fd::AsRawFd};

#[cfg(any(target_os = "linux", target_os = "android"))]
use anyhow::Context;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use anyhow::bail;
use anyhow::{Result, anyhow};
use walkdir::WalkDir;

use crate::{conf::schema::HymoFsConfig, defs, sys::hymofs, utils::KSU};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LkmStatus {
    pub loaded: bool,
    pub module_name: Option<String>,
    pub autoload: bool,
    pub kmi_override: String,
    pub current_kmi: String,
    pub search_dir: PathBuf,
    pub module_file: Option<PathBuf>,
}

static LAST_ERROR: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
const SYS_INIT_MODULE_NUM: libc::c_long = 105;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
const SYS_INIT_MODULE_NUM: libc::c_long = 175;
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "arm"))]
const SYS_INIT_MODULE_NUM: libc::c_long = 128;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "aarch64", target_arch = "arm")
))]
const SYS_FINIT_MODULE_NUM: libc::c_long = 379;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
const SYS_FINIT_MODULE_NUM: libc::c_long = 313;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
const SYS_DELETE_MODULE_NUM: libc::c_long = 106;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "x86_64", target_arch = "x86")
))]
const SYS_DELETE_MODULE_NUM: libc::c_long = 176;
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "arm"))]
const SYS_DELETE_MODULE_NUM: libc::c_long = 129;

fn set_last_error(message: impl Into<String>) {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = Some(message.into());
    }
}

fn clear_last_error() {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = None;
    }
}

pub fn last_error() -> Option<String> {
    LAST_ERROR.lock().ok().and_then(|slot| slot.clone())
}

fn read_first_line(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().and_then(|content| {
        content
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToString::to_string)
    })
}

fn arch_suffix() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "_arm64"
    }
    #[cfg(target_arch = "arm")]
    {
        "_armv7"
    }
    #[cfg(target_arch = "x86_64")]
    {
        "_x86_64"
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64")))]
    {
        "_arm64"
    }
}

fn parse_kmi_from_release(release: &str) -> String {
    let full_version = release.trim();
    if full_version.is_empty() {
        return String::new();
    }

    let Some(dot1) = full_version.find('.') else {
        return String::new();
    };
    let dot2 = full_version[dot1 + 1..]
        .find('.')
        .map(|offset| dot1 + 1 + offset)
        .unwrap_or(full_version.len());
    let major_minor = &full_version[..dot2];

    let Some(android_pos) = full_version.find("-android") else {
        return String::new();
    };
    let ver_start = android_pos + "-android".len();
    let ver_end = full_version[ver_start..]
        .find('-')
        .map(|offset| ver_start + offset)
        .unwrap_or(full_version.len());
    let android_ver = &full_version[ver_start..ver_end];

    format!("android{}-{}", android_ver, major_minor)
}

fn real_kernel_release() -> String {
    if let Some(value) = read_first_line(Path::new("/proc/sys/kernel/osrelease")) {
        return value;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let uts = unsafe {
            let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
            if libc::uname(uts.as_mut_ptr()) == 0 {
                Some(uts.assume_init())
            } else {
                None
            }
        };

        if let Some(uts) = uts {
            let bytes = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_bytes();
            return String::from_utf8_lossy(bytes).trim().to_string();
        }
    }

    String::new()
}

pub fn current_kmi() -> String {
    parse_kmi_from_release(&real_kernel_release())
}

fn effective_kmi(config: &HymoFsConfig) -> String {
    if !config.lkm_kmi_override.trim().is_empty() {
        config.lkm_kmi_override.trim().to_string()
    } else {
        current_kmi()
    }
}

fn candidate_file_names(kmi: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let suffix = arch_suffix();

    if !kmi.is_empty() {
        candidates.push(format!("{kmi}{suffix}_hymofs_lkm.ko"));
        candidates.push(format!("{kmi}_hymofs_lkm.ko"));
    }
    candidates.push(format!("{suffix}_hymofs_lkm.ko"));
    candidates.push("hymofs_lkm.ko".to_string());

    let mut seen = HashSet::new();
    candidates.retain(|value| seen.insert(value.clone()));
    candidates
}

fn candidate_name_set(kmi: &str) -> HashSet<String> {
    candidate_file_names(kmi).into_iter().collect()
}

fn resolve_module_file(config: &HymoFsConfig) -> Option<PathBuf> {
    let kmi = effective_kmi(config);
    let candidates = candidate_file_names(&kmi);
    let candidate_names = candidate_name_set(&kmi);

    if config.lkm_dir.is_file() {
        return Some(config.lkm_dir.clone());
    }

    if config.lkm_dir.is_dir() {
        for candidate in &candidates {
            let direct = config.lkm_dir.join(candidate);
            if direct.is_file() {
                return Some(direct);
            }
        }

        for entry_result in WalkDir::new(&config.lkm_dir).follow_links(false) {
            let Ok(entry) = entry_result else {
                continue;
            };
            if !entry.file_type().is_file() {
                continue;
            }

            let name = entry.file_name().to_string_lossy().into_owned();
            if candidate_names.contains(&name) {
                return Some(entry.path().to_path_buf());
            }
        }
    }

    let legacy = PathBuf::from(defs::HYMOFS_LKM_FILE);
    legacy.is_file().then_some(legacy)
}

fn loaded_module_name() -> Option<String> {
    let content = fs::read_to_string("/proc/modules").ok()?;
    content.lines().find_map(|line| {
        let name = line.split_whitespace().next()?;
        matches!(name, defs::HYMOFS_LKM_MODULE_NAME | "hymofs").then(|| name.to_string())
    })
}

pub fn is_loaded() -> bool {
    loaded_module_name().is_some()
}

pub fn has_module_assets(config: &HymoFsConfig) -> bool {
    config.lkm_dir.exists() || Path::new(defs::HYMOFS_LKM_FILE).exists()
}

pub fn status(config: &HymoFsConfig) -> LkmStatus {
    LkmStatus {
        loaded: is_loaded(),
        module_name: loaded_module_name(),
        autoload: config.lkm_autoload,
        kmi_override: config.lkm_kmi_override.clone(),
        current_kmi: current_kmi(),
        search_dir: config.lkm_dir.clone(),
        module_file: resolve_module_file(config),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn load_module_via_init(ko_path: &Path, params: &str) -> Result<()> {
    let mut file = fs::File::open(ko_path)
        .with_context(|| format!("failed to open module {}", ko_path.display()))?;
    let mut image = Vec::new();
    file.read_to_end(&mut image)
        .with_context(|| format!("failed to read module {}", ko_path.display()))?;
    let params = CString::new(params).context("module params contain interior NUL")?;

    let ret = unsafe {
        libc::syscall(
            SYS_INIT_MODULE_NUM,
            image.as_ptr(),
            image.len(),
            params.as_ptr(),
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        return Err(err).with_context(|| format!("init_module failed for {}", ko_path.display()));
    }

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[allow(dead_code)]
fn load_module_via_init(_ko_path: &Path, _params: &str) -> Result<()> {
    bail!("kernel module loading is only supported on linux/android")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn load_module_via_finit(ko_path: &Path, params: &str) -> Result<()> {
    let file = fs::File::open(ko_path)
        .with_context(|| format!("failed to open module {}", ko_path.display()))?;
    let params = CString::new(params).context("module params contain interior NUL")?;

    let ret = unsafe { libc::syscall(SYS_FINIT_MODULE_NUM, file.as_raw_fd(), params.as_ptr(), 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOSYS) => {
                return load_module_via_init(ko_path, params.to_str().unwrap_or(""));
            }
            Some(libc::EEXIST) => return Ok(()),
            _ => {
                return Err(err)
                    .with_context(|| format!("finit_module failed for {}", ko_path.display()));
            }
        }
    }

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn load_module_via_finit(_ko_path: &Path, _params: &str) -> Result<()> {
    bail!("kernel module loading is only supported on linux/android")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn unload_module_via_syscall(module_name: &str) -> Result<()> {
    let module_name = CString::new(module_name).context("module name contains interior NUL")?;
    let ret = unsafe { libc::syscall(SYS_DELETE_MODULE_NUM, module_name.as_ptr(), 0) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("delete_module failed");
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn unload_module_via_syscall(_module_name: &str) -> Result<()> {
    bail!("kernel module unloading is only supported on linux/android")
}

fn load_module_via_ksud(ko_path: &Path, params: &str) -> Result<()> {
    let candidates = ["/data/adb/ksud", "ksud"];
    let mut last_failure = None;

    for candidate in candidates {
        let mut cmd = Command::new(candidate);
        cmd.arg("insmod").arg(ko_path);
        if !params.is_empty() {
            cmd.arg(params);
        }
        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let detail = if !stderr.is_empty() { stderr } else { stdout };
                last_failure = Some(anyhow!(
                    "{} insmod {} failed with status {}{}",
                    candidate,
                    ko_path.display(),
                    output.status,
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!(": {detail}")
                    }
                ));
            }
            Err(err) => {
                last_failure = Some(anyhow!("failed to execute {}: {}", candidate, err));
            }
        }
    }

    Err(last_failure
        .unwrap_or_else(|| anyhow!("ksud debug insmod failed for {}", ko_path.display())))
}

fn unload_module_via_rmmod(module_name: &str) -> Result<()> {
    let candidates = ["/system/bin/rmmod", "/sbin/rmmod", "rmmod"];
    let mut last_failure = None;

    for candidate in candidates {
        let output = Command::new(candidate).arg(module_name).output();
        match output {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let detail = if !stderr.is_empty() { stderr } else { stdout };
                last_failure = Some(anyhow!(
                    "{} {} failed with status {}{}",
                    candidate,
                    module_name,
                    output.status,
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!(": {detail}")
                    }
                ));
            }
            Err(err) => {
                last_failure = Some(anyhow!("failed to execute {}: {}", candidate, err));
            }
        }
    }

    Err(last_failure.unwrap_or_else(|| anyhow!("rmmod failed for {}", module_name)))
}

pub fn load(config: &HymoFsConfig) -> Result<()> {
    clear_last_error();

    if is_loaded() {
        hymofs::invalidate_status_cache();
        return Ok(());
    }

    let ko_path = resolve_module_file(config).ok_or_else(|| {
        anyhow!(
            "no matching HymoFS LKM found in {} for kmi '{}' (legacy fallback: {})",
            config.lkm_dir.display(),
            effective_kmi(config),
            defs::HYMOFS_LKM_FILE
        )
    })?;

    let params = format!("hymo_syscall_nr={}", hymofs::HYMO_SYSCALL_NR);
    if let Err(primary_err) = load_module_via_finit(&ko_path, &params) {
        if KSU.load(Ordering::Relaxed) {
            crate::scoped_log!(
                warn,
                "lkm",
                "finit_module failed, retrying via ksud: file={}, error={:#}",
                ko_path.display(),
                primary_err
            );
            if let Err(fallback_err) = load_module_via_ksud(&ko_path, &params) {
                let combined = anyhow!("{:#}; ksud fallback: {:#}", primary_err, fallback_err);
                set_last_error(format!("{:#}", combined));
                return Err(combined);
            }
        } else {
            set_last_error(format!("{:#}", primary_err));
            return Err(primary_err);
        }
    }

    hymofs::invalidate_status_cache();
    crate::scoped_log!(
        info,
        "lkm",
        "load complete: file={}, kmi={}",
        ko_path.display(),
        effective_kmi(config)
    );
    Ok(())
}

pub fn unload(config: &HymoFsConfig) -> Result<()> {
    clear_last_error();

    let Some(module_name) = loaded_module_name() else {
        hymofs::release_connection();
        hymofs::invalidate_status_cache();
        return Ok(());
    };

    let _ = hymofs::set_enabled(false);
    let _ = hymofs::clear_rules();
    hymofs::release_connection();
    thread::sleep(Duration::from_millis(120));

    let mut last_retry_error = None;
    for _ in 0..5 {
        match unload_module_via_syscall(&module_name) {
            Ok(()) => {
                hymofs::invalidate_status_cache();
                crate::scoped_log!(info, "lkm", "unload complete: module={}", module_name);
                return Ok(());
            }
            Err(err) => {
                let retryable = err
                    .downcast_ref::<std::io::Error>()
                    .and_then(|io_err| io_err.raw_os_error())
                    .is_some_and(|code| code == libc::EAGAIN || code == libc::EBUSY);
                last_retry_error = Some(err);
                if !retryable {
                    break;
                }
                thread::sleep(Duration::from_millis(120));
            }
        }
    }

    crate::scoped_log!(
        warn,
        "lkm",
        "delete_module fallback: module={}",
        module_name
    );
    unload_module_via_rmmod(&module_name)
        .map_err(|fallback_err| match last_retry_error {
            Some(syscall_err) => anyhow!("{}; {}", syscall_err, fallback_err),
            None => fallback_err,
        })
        .inspect_err(|err| {
            set_last_error(format!(
                "{:#} (module may still be busy; stop related mounts/processes or reboot)",
                err
            ));
        })?;

    hymofs::invalidate_status_cache();
    crate::scoped_log!(info, "lkm", "unload complete: module={}", module_name);
    let _ = config;
    Ok(())
}

pub fn autoload_if_needed(config: &HymoFsConfig) -> Result<bool> {
    if !config.enabled || !config.lkm_autoload || is_loaded() || !has_module_assets(config) {
        return Ok(false);
    }

    load(config)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{candidate_file_names, parse_kmi_from_release, resolve_module_file};
    use crate::conf::schema::HymoFsConfig;

    #[test]
    fn parse_kmi_uses_android_release_major_minor() {
        assert_eq!(
            parse_kmi_from_release("6.6.30-android15-8-g123456"),
            "android15-6.6"
        );
        assert_eq!(
            parse_kmi_from_release("5.15.167-android14"),
            "android14-5.15"
        );
        assert!(parse_kmi_from_release("6.1.55-generic").is_empty());
    }

    #[test]
    fn candidate_list_prefers_kmi_specific_file() {
        let candidates = candidate_file_names("android15-6.6");
        assert_eq!(
            candidates[0],
            format!("android15-6.6{}_hymofs_lkm.ko", super::arch_suffix())
        );
        assert!(candidates.contains(&"hymofs_lkm.ko".to_string()));
    }

    #[test]
    fn resolve_module_file_prefers_specific_match_inside_lkm_dir() {
        let temp = tempdir().expect("failed to create temp dir");
        let lkm_dir = temp.path().join("hymofs_lkm");
        fs::create_dir_all(&lkm_dir).expect("failed to create lkm dir");
        let exact = lkm_dir.join(format!(
            "android15-6.6{}_hymofs_lkm.ko",
            super::arch_suffix()
        ));
        let fallback = lkm_dir.join("hymofs_lkm.ko");
        fs::write(&exact, b"test").expect("failed to write exact ko");
        fs::write(&fallback, b"test").expect("failed to write fallback ko");

        let config = HymoFsConfig {
            lkm_dir,
            lkm_kmi_override: "android15-6.6".to_string(),
            ..HymoFsConfig::default()
        };

        assert_eq!(resolve_module_file(&config), Some(exact));
    }
}
