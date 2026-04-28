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

use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::process::{Command, Output};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "android"))]
use anyhow::{Context, bail};
#[cfg(any(target_os = "linux", target_os = "android"))]
use ksu::NukeExt4Sysfs;
#[cfg(any(target_os = "linux", target_os = "android"))]
use procfs::process::Process;

#[cfg(any(target_os = "linux", target_os = "android"))]
static APATCH_KPM_LOADED: AtomicBool = AtomicBool::new(false);

#[cfg(any(target_os = "linux", target_os = "android"))]
struct ApatchKpmConfig {
    kp_bin: String,
    kpm_module: String,
    kpm_id: String,
    call_mode: String,
    control_name: Option<String>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KptoolsCommand {
    Load,
    Control,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl KptoolsCommand {
    fn failure_prefix(self) -> &'static str {
        match self {
            Self::Load => "Failed to load kpm:",
            Self::Control => "Failed to control kpm:",
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_i64_token(token: &str) -> Option<i64> {
    token
        .trim_end_matches(|c: char| !matches!(c, '-' | '0'..='9'))
        .parse::<i64>()
        .ok()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn extract_kpm_rc_from_text(text: &str) -> Option<i64> {
    text.split_whitespace()
        .find_map(|token| token.strip_prefix("rc=").and_then(parse_i64_token))
        .or_else(|| {
            text.lines()
                .rev()
                .find_map(|line| line.trim().parse::<i64>().ok())
        })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn text_reports_kptools_failure(text: &str, command: KptoolsCommand) -> bool {
    text.lines()
        .any(|line| line.trim_start().starts_with(command.failure_prefix()))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn probe_ext4_procfs_node(path: &Path) -> Result<Option<std::path::PathBuf>> {
    let path_str = path
        .to_str()
        .context("nuke target path contains invalid utf-8")?;

    let process = Process::myself().context("failed to open self procfs handle")?;
    let mountinfo = process.mountinfo().context("failed to read mountinfo")?;
    let mount = mountinfo
        .into_iter()
        .find(|m| m.mount_point.to_string_lossy() == path_str)
        .context("nuke target is not a mount point")?;

    if mount.fs_type != "ext4" {
        bail!(
            "nuke target is not ext4: path={}, fs_type={}",
            path.display(),
            mount.fs_type
        );
    }

    let source_id = mount
        .mount_source
        .as_ref()
        .and_then(|s| {
            let source = s.as_str();
            source
                .trim()
                .rsplit('/')
                .next()
                .map(std::string::ToString::to_string)
        })
        .filter(|s| !s.is_empty())
        .context("unable to infer ext4 procfs node from mount source")?;

    Ok(Some(Path::new("/proc/fs/ext4").join(source_id)))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn execute_ksu_nuke(path: &Path) -> Result<()> {
    let mut nuke = NukeExt4Sysfs::new();
    nuke.add(path);
    nuke.execute()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apatch_nuke_strict_verify() -> bool {
    std::env::var("HYBRID_MOUNT_APATCH_NUKE_STRICT_VERIFY")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn resolve_apatch_kpm_config() -> Result<ApatchKpmConfig> {
    let kp_bin = std::env::var("HYBRID_MOUNT_APATCH_KP_BIN")
        .unwrap_or_else(|_| "/data/adb/ap/bin/kptools".to_string());
    if !Path::new(&kp_bin).exists() {
        bail!("apatch kp tool not found: {kp_bin}");
    }

    let kpm_module = std::env::var("HYBRID_MOUNT_APATCH_KPM_MODULE")
        .unwrap_or_else(|_| format!("{}/kpm/nuke_ext4_sysfs.kpm", crate::defs::HYBRID_MOUNT_DIR));
    if !Path::new(&kpm_module).exists() {
        bail!("apatch kpm module not found: {kpm_module}");
    }
    let kpm_id =
        std::env::var("HYBRID_MOUNT_APATCH_KPM_ID").unwrap_or_else(|_| "nuke_ext4_sysfs".into());
    let call_mode =
        std::env::var("HYBRID_MOUNT_APATCH_KPM_CALL_MODE").unwrap_or_else(|_| "control".into());
    let control_name = if call_mode.eq_ignore_ascii_case("nr") {
        None
    } else {
        let control_name = std::env::var("HYBRID_MOUNT_APATCH_KPM_CONTROL")
            .unwrap_or_else(|_| "nuke_ext4_sysfs".to_string());
        if control_name
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
        {
            bail!("invalid kpm control name: {control_name}");
        }
        Some(control_name)
    };

    Ok(ApatchKpmConfig {
        kp_bin,
        kpm_module,
        kpm_id,
        call_mode,
        control_name,
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn load_result_is_already_loaded(output: &Output) -> bool {
    let rc = extract_kpm_rc(output);
    rc == Some(-(libc::EEXIST as i64)) || output_mentions_file_exists(output)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn ensure_apatch_kpm_loaded(config: &ApatchKpmConfig) -> Result<()> {
    if APATCH_KPM_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    let load_output = Command::new(&config.kp_bin)
        .args(["kpm", "load", &config.kpm_module])
        .output()
        .with_context(|| format!("failed to load kpm module with {}", config.kp_bin))?;
    let load_rc = extract_kpm_rc(&load_output);
    let already_loaded = load_result_is_already_loaded(&load_output);

    if !load_output.status.success() && !already_loaded {
        bail!(
            "kpm load failed: module={}, code={:?}, output={}",
            config.kpm_module,
            load_output.status.code(),
            format_output(&load_output)
        );
    }
    if (output_reports_kptools_failure(&load_output, KptoolsCommand::Load)
        || load_rc.is_some_and(|rc| rc < 0))
        && !already_loaded
    {
        bail!(
            "kpm load reported failure: module={}, rc={}, output={}",
            config.kpm_module,
            format_optional_rc(load_rc),
            format_output(&load_output)
        );
    }

    APATCH_KPM_LOADED.store(true, Ordering::Release);

    if already_loaded {
        crate::scoped_log!(
            debug,
            "nuke",
            "apatch kpm already loaded: module={}, id={}",
            config.kpm_module,
            config.kpm_id
        );
    } else {
        crate::scoped_log!(
            info,
            "nuke",
            "apatch kpm preloaded: module={}, id={}",
            config.kpm_module,
            config.kpm_id
        );
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn preload_if_needed() -> Result<()> {
    if ksu::version().is_some() {
        return Ok(());
    }

    let config = resolve_apatch_kpm_config()?;
    ensure_apatch_kpm_loaded(&config)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn preload_if_needed() -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn execute_apatch_nuke(path: &Path) -> Result<()> {
    let config = resolve_apatch_kpm_config()?;
    ensure_apatch_kpm_loaded(&config)?;
    let strict_verify = apatch_nuke_strict_verify();
    let procfs_node = probe_ext4_procfs_node(path).ok().flatten();
    let before_exists = procfs_node.as_ref().is_some_and(|node| node.exists());

    let path_str = path.to_string_lossy().into_owned();
    let nr = if config.call_mode.eq_ignore_ascii_case("nr") {
        Some(
            std::env::var("HYBRID_MOUNT_APATCH_KPM_UNUSED_NR")
                .context("HYBRID_MOUNT_APATCH_KPM_UNUSED_NR is required when call mode is 'nr'")?,
        )
    } else {
        None
    };
    let call_output = if let Some(nr) = nr.as_deref() {
        let _ = nr
            .parse::<u32>()
            .with_context(|| format!("invalid unused nr value: {nr}"))?;
        crate::scoped_log!(
            info,
            "nuke",
            "kpm invoke start: mode=nr, path={}, nr={}",
            path.display(),
            nr
        );
        Command::new(&config.kp_bin)
            .args(["kpm", "call", nr, &path_str])
            .output()
            .with_context(|| format!("failed to call kpm unused nr with {}", config.kp_bin))
    } else {
        let control_name = config
            .control_name
            .as_deref()
            .context("missing kpm control name for control mode")?;
        crate::scoped_log!(
            info,
            "nuke",
            "kpm invoke start: mode=control, path={}, control_name={}",
            path.display(),
            control_name
        );
        Command::new(&config.kp_bin)
            .args(["kpm", "control", control_name, &path_str])
            .output()
            .with_context(|| format!("failed to call kpm control with {}", config.kp_bin))
    }?;

    let call_rc = extract_kpm_rc(&call_output);
    if !call_output.status.success() {
        bail!(
            "kpm invoke failed: mode={}, code={:?}, output={}",
            config.call_mode,
            call_output.status.code(),
            format_output(&call_output)
        );
    }
    if output_reports_kptools_failure(&call_output, KptoolsCommand::Control)
        || call_rc.is_some_and(|rc| rc < 0)
    {
        let Some(rc) = call_rc else {
            bail!(
                "kpm invoke reported failure without return code: mode={}, output={}",
                config.call_mode,
                format_output(&call_output)
            );
        };
        if !strict_verify && rc == -(libc::EEXIST as i64) {
            crate::scoped_log!(
                warn,
                "nuke",
                "kpm invoke returned -EEXIST in best-effort mode: mode={}, rc={}, output={}",
                config.call_mode,
                rc,
                format_output(&call_output)
            );
        } else {
            bail!(
                "kpm invoke reported failure: mode={}, rc={rc}, output={}",
                config.call_mode,
                format_output(&call_output)
            );
        }
    }

    if let Some(nr) = nr.as_deref() {
        crate::scoped_log!(
            info,
            "nuke",
            "kpm call success: path={}, nr={}, rc={}",
            path.display(),
            nr,
            format_optional_rc(call_rc)
        );
    } else {
        crate::scoped_log!(
            info,
            "nuke",
            "kpm control success: path={}, control_name={}, rc={}",
            path.display(),
            config.control_name.as_deref().unwrap_or("<missing>"),
            format_optional_rc(call_rc)
        );
    }

    if let Some(node) = procfs_node {
        let after_exists = node.exists();
        if after_exists {
            if strict_verify {
                bail!("procfs node still present after nuke: {}", node.display());
            }
            crate::scoped_log!(
                warn,
                "nuke",
                "procfs node still present after nuke (best-effort mode): path={}, before_exists={}, after_exists={}",
                node.display(),
                before_exists,
                after_exists
            );
        } else {
            crate::scoped_log!(
                debug,
                "nuke",
                "procfs node verification passed: path={}, before_exists={}, after_exists={}",
                node.display(),
                before_exists,
                after_exists
            );
        }
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn extract_kpm_rc(output: &Output) -> Option<i64> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    extract_kpm_rc_from_text(&stdout).or_else(|| extract_kpm_rc_from_text(&stderr))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn output_reports_kptools_failure(output: &Output, command: KptoolsCommand) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    text_reports_kptools_failure(&stdout, command) || text_reports_kptools_failure(&stderr, command)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn output_mentions_file_exists(output: &Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    text_mentions_file_exists(&stdout) || text_mentions_file_exists(&stderr)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn text_mentions_file_exists(text: &str) -> bool {
    text.to_ascii_lowercase().contains("file exists")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn format_optional_rc(rc: Option<i64>) -> String {
    rc.map(|value| value.to_string())
        .unwrap_or_else(|| "<unknown>".to_string())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn format_output(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => "<empty>".to_string(),
        (false, true) => format!("stdout={stdout}"),
        (true, false) => format!("stderr={stderr}"),
        (false, false) => format!("stdout={stdout}; stderr={stderr}"),
    }
}

pub fn nuke_path(path: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let result = if ksu::version().is_some() {
            execute_ksu_nuke(path)
        } else {
            execute_apatch_nuke(path)
        };

        match result {
            Ok(()) => {
                crate::scoped_log!(debug, "nuke", "execute success: path={}", path.display());
                Ok(())
            }
            Err(e) => {
                crate::scoped_log!(
                    warn,
                    "nuke",
                    "execute failed: path={}, error={:#}",
                    path.display(),
                    e
                );
                Err(e)
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = path;
        Ok(())
    }
}
