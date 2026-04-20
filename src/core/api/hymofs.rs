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

use std::{collections::BTreeSet, path::Path};

use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    conf::config::Config,
    core::runtime_state::RuntimeState,
    defs,
    sys::{
        hymofs::{self, HymoFsStatus},
        lkm,
    },
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HymofsRuleEntry {
    #[serde(rename = "type")]
    pub rule_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<i32>,
}

pub fn parse_hymofs_rule_listing(listing: &str) -> Vec<HymofsRuleEntry> {
    let mut rules = Vec::new();

    for raw_line in listing.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with("HymoFS Protocol:")
            || line.starts_with("HymoFS Enabled:")
        {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(kind_raw) = parts.next() else {
            continue;
        };
        let rule_type = kind_raw.to_uppercase();

        match rule_type.as_str() {
            "ADD" => {
                let target = parts.next().map(ToString::to_string);
                let source = parts.next().map(ToString::to_string);
                let file_type = parts.next().and_then(|value| value.parse::<i32>().ok());
                rules.push(HymofsRuleEntry {
                    rule_type,
                    target,
                    source,
                    path: None,
                    args: None,
                    file_type,
                });
            }
            "MERGE" => {
                let target = parts.next().map(ToString::to_string);
                let source = parts.next().map(ToString::to_string);
                rules.push(HymofsRuleEntry {
                    rule_type,
                    target,
                    source,
                    path: None,
                    args: None,
                    file_type: None,
                });
            }
            "HIDE" | "INJECT" => {
                rules.push(HymofsRuleEntry {
                    rule_type,
                    target: None,
                    source: None,
                    path: parts.next().map(ToString::to_string),
                    args: None,
                    file_type: None,
                });
            }
            _ => {
                let args = parts.collect::<Vec<_>>().join(" ");
                rules.push(HymofsRuleEntry {
                    rule_type,
                    target: None,
                    source: None,
                    path: None,
                    args: (!args.is_empty()).then_some(args),
                    file_type: None,
                });
            }
        }
    }

    rules
}

pub fn build_features_payload() -> Value {
    let bits = hymofs::get_features().unwrap_or_default();
    json!({
        "bitmask": bits,
        "names": hymofs::feature_names(bits),
    })
}

pub fn build_lkm_payload(config: &Config) -> Value {
    let status = lkm::status(&config.hymofs);
    json!({
        "loaded": status.loaded,
        "module_name": status.module_name,
        "autoload": status.autoload,
        "kmi_override": status.kmi_override,
        "current_kmi": status.current_kmi,
        "search_dir": status.search_dir,
        "module_file": status.module_file,
        "last_error": lkm::last_error(),
    })
}

pub fn build_hymofs_version_payload(config: &Config, state: &RuntimeState) -> Value {
    if !config.hymofs.enabled {
        return json!({
            "protocol_version": hymofs::HYMO_PROTOCOL_VERSION,
            "kernel_version": 0,
            "hymofs_available": false,
            "protocol_mismatch": false,
            "mismatch_message": Value::Null,
            "active_modules": Vec::<String>::new(),
            "mount_base": state.mount_point,
            "mirror_path": config.hymofs.mirror_path,
        });
    }

    let status = hymofs::check_status();
    let kernel_version = hymofs::get_protocol_version().ok();
    let active_rules = hymofs::get_active_rules().unwrap_or_default();
    let parsed_rules = parse_hymofs_rule_listing(&active_rules);
    let active_modules = if !state.hymofs_modules.is_empty() {
        let mut modules = state.hymofs_modules.clone();
        modules.sort();
        modules.dedup();
        modules
    } else {
        extract_active_module_ids(&parsed_rules, &config.hymofs.mirror_path)
    };

    let mismatch = kernel_version.is_some_and(|version| version != hymofs::HYMO_PROTOCOL_VERSION);

    json!({
        "protocol_version": hymofs::HYMO_PROTOCOL_VERSION,
        "kernel_version": kernel_version.unwrap_or_default(),
        "hymofs_available": status == HymoFsStatus::Available,
        "protocol_mismatch": mismatch,
        "mismatch_message": mismatch_message(status, kernel_version),
        "active_modules": active_modules,
        "mount_base": state.mount_point,
        "mirror_path": config.hymofs.mirror_path,
    })
}

fn mismatch_message(status: HymoFsStatus, kernel_version: Option<i32>) -> Option<String> {
    match status {
        HymoFsStatus::KernelTooOld => Some(format!(
            "kernel protocol {} is older than userspace api{}",
            kernel_version.unwrap_or_default(),
            hymofs::HYMO_PROTOCOL_VERSION
        )),
        HymoFsStatus::ModuleTooOld => Some(format!(
            "kernel protocol {} is newer than userspace api{}",
            kernel_version.unwrap_or_default(),
            hymofs::HYMO_PROTOCOL_VERSION
        )),
        HymoFsStatus::Available => kernel_version
            .filter(|version| *version != hymofs::HYMO_PROTOCOL_VERSION)
            .map(|version| {
                format!(
                    "protocol mismatch: userspace api{}, kernel api{}",
                    hymofs::HYMO_PROTOCOL_VERSION,
                    version
                )
            }),
        HymoFsStatus::NotPresent => None,
    }
}

fn extract_active_module_ids(rules: &[HymofsRuleEntry], mirror_path: &Path) -> Vec<String> {
    let mut modules = BTreeSet::new();

    for rule in rules {
        let Some(source) = rule.source.as_deref() else {
            continue;
        };

        if let Some(module_id) = extract_module_id_from_source(source, mirror_path) {
            modules.insert(module_id);
        }
    }

    modules.into_iter().collect()
}

fn extract_module_id_from_source(source: &str, mirror_path: &Path) -> Option<String> {
    let module_root = format!("{}/", defs::MODULES_DIR.trim_end_matches('/'));
    if let Some(rest) = source.strip_prefix(&module_root) {
        return rest
            .split('/')
            .next()
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
    }

    let mirror_prefix = format!(
        "{}/",
        mirror_path.display().to_string().trim_end_matches('/')
    );
    if let Some(rest) = source.strip_prefix(&mirror_prefix) {
        return rest
            .split('/')
            .next()
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
    }

    None
}
