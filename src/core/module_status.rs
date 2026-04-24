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

use std::{process::Command, sync::atomic::Ordering};

use crate::utils::KSU;

pub fn update_description(
    storage_mode: &str,
    overlay_count: usize,
    magic_count: usize,
    hymofs_count: usize,
) {
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

    set_description(&desc_text);
}

pub fn update_crash_description(reason: &str) {
    let desc_text = format!("😭 崩溃了呜～ 原因: {}", reason);
    set_description(&desc_text);
}

fn set_description(desc_text: &str) {
    let mut result = if KSU.load(Ordering::Relaxed) {
        Command::new("ksud")
    } else {
        Command::new("apd")
    };
    let status = result
        .arg("module")
        .arg("config")
        .arg("set")
        .arg("override.description")
        .arg("-t")
        .arg(desc_text)
        .status();

    if let Ok(status) = status
        && status.success()
    {
        return;
    }
}
