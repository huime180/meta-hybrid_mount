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

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct OverlayOperation {
    pub partition_name: String,
    pub target: String,
    pub lowerdirs: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct HymofsAddRule {
    pub target: String,
    pub source: PathBuf,
    pub file_type: i32,
}

#[derive(Debug, Clone)]
pub struct HymofsMergeRule {
    pub target: String,
    pub source: PathBuf,
}

#[derive(Debug, Default)]
pub struct MountPlan {
    pub overlay_ops: Vec<OverlayOperation>,
    pub hymofs_add_rules: Vec<HymofsAddRule>,
    pub hymofs_merge_rules: Vec<HymofsMergeRule>,
    pub hymofs_hide_rules: Vec<String>,
    pub overlay_module_ids: Vec<String>,
    pub magic_module_ids: Vec<String>,
    pub hymofs_module_ids: Vec<String>,
}
