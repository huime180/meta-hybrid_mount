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

pub mod discovery;
pub mod listing;

pub use discovery::*;

use crate::defs;

pub fn is_reserved_module_dir(id: &str) -> bool {
    matches!(
        id,
        "hybrid-mount" | "lost+found" | ".git" | ".idea" | ".vscode"
    )
}

pub fn mount_block_markers(module_path: &std::path::Path) -> Vec<&'static str> {
    let mut markers = Vec::new();
    if module_path.join(defs::DISABLE_FILE_NAME).exists() {
        markers.push(defs::DISABLE_FILE_NAME);
    }
    if module_path.join(defs::REMOVE_FILE_NAME).exists() {
        markers.push(defs::REMOVE_FILE_NAME);
    }
    if module_path.join(defs::MOUNT_ERROR_FILE_NAME).exists() {
        markers.push(defs::MOUNT_ERROR_FILE_NAME);
    }
    if module_path.join(defs::SKIP_MOUNT_FILE_NAME).exists() {
        markers.push(defs::SKIP_MOUNT_FILE_NAME);
    }
    markers
}

pub fn has_mount_block_marker(module_path: &std::path::Path) -> bool {
    !mount_block_markers(module_path).is_empty()
}
