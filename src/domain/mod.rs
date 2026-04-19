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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultMode {
    #[default]
    Overlay,
    Magic,
    Hymofs,
}

impl DefaultMode {
    pub fn as_mount_mode(&self) -> MountMode {
        match self {
            Self::Overlay => MountMode::Overlay,
            Self::Magic => MountMode::Magic,
            Self::Hymofs => MountMode::Hymofs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MountMode {
    #[default]
    Overlay,
    Magic,
    Hymofs,
    Ignore,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleRules {
    #[serde(default)]
    pub default_mode: MountMode,
    #[serde(default)]
    pub paths: HashMap<String, MountMode>,
}

impl ModuleRules {
    pub fn get_mode(&self, relative_path: &str) -> MountMode {
        let mut best_match = None;
        let mut best_len = 0usize;

        for (path, mode) in &self.paths {
            let is_exact = relative_path == path;
            let is_prefix = relative_path.len() > path.len()
                && relative_path.starts_with(path)
                && relative_path.as_bytes().get(path.len()) == Some(&b'/');

            if (is_exact || is_prefix) && path.len() >= best_len {
                best_match = Some(mode.clone());
                best_len = path.len();
            }
        }

        if let Some(mode) = best_match {
            return mode;
        }

        self.default_mode.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{DefaultMode, ModuleRules, MountMode};

    #[test]
    fn default_mode_maps_to_mount_mode() {
        assert_eq!(DefaultMode::Overlay.as_mount_mode(), MountMode::Overlay);
        assert_eq!(DefaultMode::Magic.as_mount_mode(), MountMode::Magic);
        assert_eq!(DefaultMode::Hymofs.as_mount_mode(), MountMode::Hymofs);
    }

    #[test]
    fn module_rules_prefers_longest_prefix_match() {
        let rules = ModuleRules {
            default_mode: MountMode::Overlay,
            paths: HashMap::from([
                ("system".to_string(), MountMode::Magic),
                ("system/bin".to_string(), MountMode::Hymofs),
            ]),
        };

        assert_eq!(rules.get_mode("system/bin"), MountMode::Hymofs);
        assert_eq!(rules.get_mode("system/bin/sh"), MountMode::Hymofs);
        assert_eq!(rules.get_mode("system/lib"), MountMode::Magic);
    }
}
