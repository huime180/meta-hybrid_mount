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
    io::{BufRead, BufReader},
    path::Path,
    process::Command,
    sync::atomic::Ordering,
};

use crate::{defs, sys::fs::atomic_write, utils::KSU};

pub fn update_description(
    storage_mode: &str,
    overlay_count: usize,
    magic_count: usize,
    hymofs_count: usize,
) {
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

    let mut stats = Vec::new();
    if hymofs_count > 0 {
        stats.push(format!("HymoFS: {}", hymofs_count));
    }
    stats.push(format!("Overlay: {}", overlay_count));
    stats.push(format!("Magic: {}", magic_count));

    let stats_str = stats.join("  ");

    let desc_text = format!(
        "😋 运行中喵～ ({}) {}  {}",
        mode_str, status_emoji, stats_str
    );

    set_description(prop_path, &desc_text);
}

pub fn update_crash_description(reason: &str) {
    let prop_path = Path::new(defs::MODULE_PROP_FILE);

    if !prop_path.exists() {
        return;
    }

    let desc_text = format!("😭 崩溃了呜～ 原因: {}", reason);
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
        crate::scoped_log!(
            warn,
            "module_status",
            "description update failed: path={}, error={}",
            prop_path.display(),
            err
        );
    }
}
