// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::Command,
    sync::atomic::Ordering,
};

use crate::{defs, sys::fs::atomic_write, utils::KSU};

pub fn update_description(storage_mode: &str, overlay_count: usize, magic_count: usize) {
    let prop_path = Path::new(defs::MODULE_PROP_FILE);

    if !prop_path.exists() {
        return;
    }

    let mode_str = match storage_mode {
        "tmpfs" => "Tmpfs",
        _ => "Ext4",
    };

    let status_emoji = match storage_mode {
        "tmpfs" => "🐾",
        _ => "💿",
    };

    let desc_text = format!(
        "😋 运行中喵～ ({}) {} | Overlay: {} | Magic: {}",
        mode_str, status_emoji, overlay_count, magic_count
    );
    set_description(prop_path, &desc_text);
}

pub fn update_crash_description(reason: &str) {
    let prop_path = Path::new(defs::MODULE_PROP_FILE);

    if !prop_path.exists() {
        return;
    }

    let desc_text = format!("😭 崩溃了呜～ | 原因: {}", reason);
    set_description(prop_path, &desc_text);
}

fn set_description(prop_path: &Path, desc_text: &str) {
    if KSU.load(Ordering::Relaxed) {
        let result = Command::new("ksud")
            .arg("module")
            .arg("config")
            .arg("set")
            .arg("override.description")
            .arg(desc_text)
            .status();

        if let Ok(status) = result
            && status.success()
        {
            return;
        }
    }

    let lines: Vec<String> = match fs::File::open(prop_path) {
        Ok(file) => BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .map(|line| {
                if line.starts_with("description=") {
                    format!("description={}", desc_text)
                } else {
                    line
                }
            })
            .collect(),
        Err(_) => return,
    };

    let content = lines.join("\n");
    if let Err(err) = atomic_write(prop_path, format!("{}\n", content)) {
        log::warn!("Failed to update module description: {}", err);
    }
}
