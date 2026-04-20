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
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::Deserialize;

use crate::{
    conf::config,
    core::inventory,
    domain::{ModuleRules, MountMode},
};

#[derive(Deserialize)]
struct PartialRules {
    default_mode: Option<MountMode>,
    paths: Option<HashMap<String, MountMode>>,
}

fn load_module_rules(module_dir: &Path, module_id: &str, cfg: &config::Config) -> ModuleRules {
    let mut rules = ModuleRules {
        default_mode: cfg.default_mode.as_mount_mode(),
        ..Default::default()
    };

    let internal_config = module_dir.join("hybrid_rules.json");

    if internal_config.exists() {
        match fs::read_to_string(&internal_config) {
            Ok(content) => match serde_json::from_str::<PartialRules>(&content) {
                Ok(partial) => {
                    if let Some(mode) = partial.default_mode {
                        rules.default_mode = mode;
                    }
                    if let Some(paths) = partial.paths {
                        rules.paths = paths;
                    }
                }
                Err(e) => {
                    crate::scoped_log!(
                        warn,
                        "scanner",
                        "rules parse failed: module={}, error={}",
                        module_id,
                        e
                    )
                }
            },
            Err(e) => crate::scoped_log!(
                warn,
                "scanner",
                "rules read failed: module={}, error={}",
                module_id,
                e
            ),
        }
    }

    if let Some(global_rules) = cfg.rules.get(module_id) {
        rules.default_mode = global_rules.default_mode.clone();
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

        let id = entry.file_name().to_string_lossy().to_string();

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

        let rules = load_module_rules(&path, &id, cfg);

        modules.push(Module {
            id,
            source_path: path,
            rules,
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
