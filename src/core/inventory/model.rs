// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::HashSet,
    fs::{self},
    io::{BufRead, BufReader},
    path::Path,
    sync::OnceLock,
};

use anyhow::Result;
use regex_lite::Regex;
use serde::Serialize;

use super::scanner as inventory;
use crate::{
    conf::config::{self, MountMode},
    core::state::RuntimeState,
};

static MODULE_PROP_REGEX: OnceLock<Regex> = OnceLock::new();

#[derive(Default)]
struct ModuleProp {
    name: String,
    version: String,
    author: String,
    description: String,
}

fn normalize_module_prop(module_id: &str, mut prop: ModuleProp) -> ModuleProp {
    if prop.name.trim().is_empty() {
        prop.name = module_id.to_string();
    }
    if prop.version.trim().is_empty() {
        prop.version = "unknown".to_string();
    }
    if prop.author.trim().is_empty() {
        prop.author = "unknown".to_string();
    }
    if prop.description.trim().is_empty() {
        prop.description = "No description".to_string();
    }
    prop
}

impl From<&Path> for ModuleProp {
    fn from(path: &Path) -> Self {
        let mut prop = ModuleProp::default();
        let re = MODULE_PROP_REGEX.get_or_init(|| {
            Regex::new(r"^([a-zA-Z0-9_.]+)=(.*)$").expect("Failed to compile module prop regex")
        });

        if let Ok(file) = fs::File::open(path) {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                if let Some(caps) = re.captures(line.trim()) {
                    let k = caps.get(1).map_or("", |m| m.as_str());
                    let v = caps.get(2).map_or("", |m| m.as_str());

                    match k {
                        "name" => prop.name = v.to_string(),
                        "version" => prop.version = v.to_string(),
                        "author" => prop.author = v.to_string(),
                        "description" => prop.description = v.to_string(),
                        _ => {}
                    }
                }
            }
        }
        prop
    }
}

#[derive(Serialize)]
struct ModuleInfo {
    id: String,
    name: String,
    version: String,
    author: String,
    description: String,
    mode: String,
    is_mounted: bool,
    rules: config::ModuleRules,
}

impl ModuleInfo {
    fn new(m: inventory::Module, mounted_set: &HashSet<&str>) -> Self {
        let prop = normalize_module_prop(
            &m.id,
            ModuleProp::from(m.source_path.join("module.prop").as_path()),
        );

        let mode_str = match m.rules.default_mode {
            MountMode::Overlay => "auto",
            MountMode::Magic => "magic",
            MountMode::Ignore => "ignore",
        };

        Self {
            is_mounted: mounted_set.contains(m.id.as_str()),
            id: m.id,
            name: prop.name,
            version: prop.version,
            author: prop.author,
            description: prop.description,
            mode: mode_str.to_string(),
            rules: m.rules,
        }
    }
}

pub fn print_list(config: &config::Config) -> Result<()> {
    let modules = inventory::scan(&config.moduledir, config)?;

    let state = RuntimeState::load().unwrap_or_default();
    let mounted_ids = state.mounted_module_ids();

    let infos: Vec<ModuleInfo> = modules
        .into_iter()
        .map(|m| ModuleInfo::new(m, &mounted_ids))
        .collect();

    println!("{}", serde_json::to_string(&infos)?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{ModuleProp, normalize_module_prop};

    #[test]
    fn module_prop_parses_expected_fields() {
        let dir = tempdir().expect("failed to create temp dir");
        let prop_file = dir.path().join("module.prop");
        fs::write(
            &prop_file,
            "name=Demo\nversion=1.0\nauthor=Hybrid Mount\ndescription=sample\nignored=1\n",
        )
        .expect("failed to write module.prop");

        let prop = ModuleProp::from(prop_file.as_path());
        assert_eq!(prop.name, "Demo");
        assert_eq!(prop.version, "1.0");
        assert_eq!(prop.author, "Hybrid Mount");
        assert_eq!(prop.description, "sample");
    }

    #[test]
    fn module_prop_returns_defaults_for_missing_file() {
        let dir = tempdir().expect("failed to create temp dir");
        let prop = ModuleProp::from(dir.path().join("not-found.prop").as_path());
        assert!(prop.name.is_empty());
        assert!(prop.version.is_empty());
        assert!(prop.author.is_empty());
        assert!(prop.description.is_empty());
    }

    #[test]
    fn normalize_module_prop_fills_empty_fields() {
        let normalized = normalize_module_prop("sample.id", ModuleProp::default());
        assert_eq!(normalized.name, "sample.id");
        assert_eq!(normalized.version, "unknown");
        assert_eq!(normalized.author, "unknown");
        assert_eq!(normalized.description, "No description");
    }
}
