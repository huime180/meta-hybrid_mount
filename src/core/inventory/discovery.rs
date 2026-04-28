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
    path::{Path, PathBuf},
};

use anyhow::Result;

use crate::{conf::config, core::inventory, domain::ModuleRules};

fn load_module_rules(module_id: &str, cfg: &config::Config) -> ModuleRules {
    let mut rules = ModuleRules {
        default_mode: cfg.default_mode.as_mount_mode(),
        ..Default::default()
    };

    if let Some(global_rules) = cfg.rules.get(module_id) {
        rules.default_mode = global_rules.default_mode;
        rules.paths.extend(global_rules.paths.clone());
    }

    rules
}

#[derive(Debug, Clone)]
pub struct Module {
    pub id: String,
    pub source_path: PathBuf,
    pub rules: ModuleRules,
}

pub fn scan(source_dir: &Path, cfg: &config::Config) -> Result<Vec<Module>> {
    if !source_dir.exists() {
        return Ok(Vec::new());
    }

    let dir_entries = fs::read_dir(source_dir)?.collect::<std::io::Result<Vec<_>>>()?;

    let mut modules = Vec::new();
    let mut skipped_reserved = 0usize;
    let mut skipped_blocked = 0usize;

    for entry in dir_entries {
        let path = entry.path();

        if !path.is_dir() {
            continue;
        }

        let id = entry.file_name().to_string_lossy().into_owned();

        if inventory::is_reserved_module_dir(&id) {
            skipped_reserved += 1;
            crate::scoped_log!(debug, "scanner", "skip: module={}, reason=reserved_dir", id);
            continue;
        }

        let block_markers = inventory::mount_block_markers(&path);
        if !block_markers.is_empty() {
            skipped_blocked += 1;
            crate::scoped_log!(
                debug,
                "scanner",
                "skip: module={}, reason=block_marker, markers={}",
                id,
                block_markers.join(",")
            );
            continue;
        }

        modules.push(Module {
            id: id.clone(),
            source_path: path,
            rules: load_module_rules(&id, cfg),
        });
    }

    crate::scoped_log!(
        info,
        "scanner",
        "complete: total_dirs={}, active_modules={}, skipped_reserved={}, skipped_blocked={}",
        modules.len() + skipped_reserved + skipped_blocked,
        modules.len(),
        skipped_reserved,
        skipped_blocked
    );

    modules.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(modules)
}
