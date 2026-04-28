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

use anyhow::{Context, Result};

use super::shared::{load_effective_config, require_live_kasumi};
use crate::{conf::cli::Cli, core::user_hide_rules, mount::kasumi as kasumi_mount, sys::kasumi};

pub fn handle_hide_list() -> Result<()> {
    let rules = user_hide_rules::load_user_hide_rules()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&rules).context("Failed to serialize user hide rules")?
    );
    Ok(())
}

pub fn handle_hide_add(cli: &Cli, path: &Path) -> Result<()> {
    let added = user_hide_rules::add_user_hide_rule(path)?;
    if added {
        let config = load_effective_config(cli)?;
        if kasumi_mount::can_operate(&config)
            && let Err(err) = kasumi::hide_path(path)
        {
            crate::scoped_log!(
                warn,
                "cli:hide",
                "live apply failed: path={}, error={:#}",
                path.display(),
                err
            );
        }
    }
    if added {
        println!("User hide rule added: {}", path.display());
    } else {
        println!("User hide rule already exists: {}", path.display());
    }
    Ok(())
}

pub fn handle_hide_remove(path: &Path) -> Result<()> {
    let removed = user_hide_rules::remove_user_hide_rule(path)?;
    if removed {
        println!(
            "User hide rule removed from persistent list: {}. Existing kernel hide state may persist until Kasumi rules are rebuilt.",
            path.display()
        );
    } else {
        println!("User hide rule was not present: {}", path.display());
    }
    Ok(())
}

pub fn handle_hide_apply(cli: &Cli) -> Result<()> {
    let config = load_effective_config(cli)?;
    require_live_kasumi(&config, "apply user hide rules")?;
    let (applied, failed) = user_hide_rules::apply_user_hide_rules()?;
    println!("User hide rules applied: {applied} succeeded, {failed} failed.");
    Ok(())
}
