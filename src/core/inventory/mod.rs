// Copyright (C) 2026 YuzakiKokuban <heibanbaize@gmail.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

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

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn mount_block_markers_include_mount_error_and_legacy_skip() {
        let temp = tempdir().expect("failed to create temp dir");
        let module_path = temp.path();

        std::fs::write(module_path.join(defs::MOUNT_ERROR_FILE_NAME), b"")
            .expect("failed to create mount_error");
        std::fs::write(module_path.join(defs::SKIP_MOUNT_FILE_NAME), b"")
            .expect("failed to create skip_mount");

        let markers = mount_block_markers(module_path);
        assert!(markers.contains(&defs::MOUNT_ERROR_FILE_NAME));
        assert!(markers.contains(&defs::SKIP_MOUNT_FILE_NAME));
    }
}
