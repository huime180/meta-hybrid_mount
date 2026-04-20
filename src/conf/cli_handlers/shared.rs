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

use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;

use crate::{
    conf::{cli::Cli, config::Config, loader},
    defs,
    mount::hymofs as hymofs_mount,
    sys::hymofs,
};

pub(super) fn decode_hex_json<T: DeserializeOwned>(payload: &str, type_name: &str) -> Result<T> {
    if !payload.len().is_multiple_of(2) {
        bail!("Invalid hex payload length for {}", type_name);
    }

    let json_bytes = (0..payload.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&payload[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .with_context(|| format!("Failed to decode hex payload for {}", type_name))?;

    serde_json::from_slice(&json_bytes)
        .with_context(|| format!("Failed to parse {} JSON payload", type_name))
}

pub(super) fn load_effective_config(cli: &Cli) -> Result<Config> {
    let mut config = loader::load_config(cli)?;
    config.merge_with_cli(
        cli.moduledir.clone(),
        cli.mountsource.clone(),
        cli.partitions.clone(),
    );
    Ok(config)
}

pub(super) fn config_output_path(cli: &Cli) -> PathBuf {
    cli.config
        .clone()
        .unwrap_or_else(|| PathBuf::from(defs::CONFIG_FILE))
}

pub(super) fn save_config_for_cli(cli: &Cli, config: &Config) -> Result<PathBuf> {
    let main_path = config_output_path(cli);
    config
        .save_to_file(&main_path)
        .with_context(|| format!("Failed to save config file to {}", main_path.display()))?;
    Ok(main_path)
}

pub(super) fn apply_live_if_possible<F>(
    config: &Config,
    description: &str,
    operation: F,
) -> Result<bool>
where
    F: FnOnce() -> Result<()>,
{
    if !hymofs_mount::can_operate(config) {
        crate::scoped_log!(
            warn,
            "cli:hymofs",
            "live apply skipped: operation={}, status={}",
            description,
            hymofs::status_name(hymofs::check_status())
        );
        return Ok(false);
    }

    operation()?;
    Ok(true)
}

pub(super) fn apply_live_runtime_sync(config: &Config, description: &str) -> Result<bool> {
    apply_live_if_possible(config, description, || {
        hymofs_mount::sync_runtime_config_for_operation(config, description)
    })
}

pub(super) fn require_live_hymofs(config: &Config, description: &str) -> Result<()> {
    hymofs_mount::require_live(config, description)
}

pub(super) fn print_config_apply_result(path: &Path, what: &str, applied: bool) {
    if applied {
        println!("{what} saved to {} and applied to HymoFS.", path.display());
    } else {
        println!(
            "{what} saved to {}. HymoFS is not currently available, so only the config was updated.",
            path.display()
        );
    }
}

pub(super) fn clear_pathbuf(path: &mut PathBuf) {
    *path = PathBuf::new();
}

pub(super) fn detect_rule_file_type(path: &Path) -> Result<i32> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to read source metadata for {}", path.display()))?;
    let file_type = metadata.file_type();

    if file_type.is_char_device() && metadata.rdev() == 0 {
        bail!(
            "source {} is a whiteout node; use `hymofs rule hide` instead",
            path.display()
        );
    }

    if file_type.is_file() {
        Ok(libc::DT_REG as i32)
    } else if file_type.is_symlink() {
        Ok(libc::DT_LNK as i32)
    } else {
        bail!(
            "unsupported source type for rule add: {} (use `merge` or `add-dir` for directories)",
            path.display()
        )
    }
}
