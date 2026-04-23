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

use std::{collections::HashSet, fs, path::Path};

const MANAGED_PARTITION_SEED: &[&str] = &[
    "system",
    "vendor",
    "product",
    "system_ext",
    "odm",
    "oem",
    "apex",
];

fn is_partition_candidate_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(ch) if ch.is_ascii_alphabetic())
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn partition_root_exists(name: &str) -> bool {
    fs::symlink_metadata(Path::new("/").join(name)).is_ok()
}

pub fn discover_partition_names(moduledir: &Path, extra_partitions: &[String]) -> Vec<String> {
    let mut names = MANAGED_PARTITION_SEED
        .iter()
        .map(|partition| partition.to_string())
        .collect::<Vec<_>>();
    names.extend(extra_partitions.iter().cloned());

    if let Ok(modules) = fs::read_dir(moduledir) {
        for module_entry in modules.flatten() {
            let module_path = module_entry.path();
            if !module_path.is_dir() {
                continue;
            }

            let Ok(children) = fs::read_dir(&module_path) else {
                continue;
            };

            for child_entry in children.flatten() {
                let child_path = child_entry.path();
                if !child_path.is_dir() {
                    continue;
                }

                let Some(candidate) = child_entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };

                if !is_partition_candidate_name(&candidate) || !partition_root_exists(&candidate) {
                    continue;
                }

                names.push(candidate);
            }
        }
    }

    names.sort();
    names.dedup();
    names
}

pub fn managed_partition_names(moduledir: &Path, extra_partitions: &[String]) -> Vec<String> {
    discover_partition_names(moduledir, extra_partitions)
}

pub fn managed_partition_set(moduledir: &Path, extra_partitions: &[String]) -> HashSet<String> {
    managed_partition_names(moduledir, extra_partitions)
        .into_iter()
        .collect()
}
