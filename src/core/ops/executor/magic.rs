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

use std::{collections::HashSet, path::Path};

use anyhow::Result;

use crate::{
    conf::config,
    core::{inventory::Module, runtime_state::MountStatistics},
    mount::magic_mount,
};

pub(super) fn mount_magic(
    modules: &[Module],
    ids: &[String],
    config: &config::Config,
    tempdir: &Path,
    use_hymofs: bool,
) -> Result<(Vec<String>, MountStatistics)> {
    let magic_ws_path = tempdir.join("magic_workspace");

    crate::scoped_log!(
        debug,
        "executor:magic",
        "prepare workspace: path={}",
        magic_ws_path.display()
    );

    if !magic_ws_path.exists() {
        std::fs::create_dir_all(&magic_ws_path)?;
    }

    let module_ids: HashSet<String> = ids.iter().cloned().collect();
    let selected_modules: Vec<Module> = modules
        .iter()
        .filter(|module| module_ids.contains(&module.id))
        .cloned()
        .collect();

    let stats = magic_mount::magic_mount(
        &magic_ws_path,
        tempdir,
        &config.mountsource,
        &config.partitions,
        &selected_modules,
        use_hymofs,
        !config.disable_umount,
    )?;

    crate::scoped_log!(
        debug,
        "executor:magic",
        "complete: module_count={}",
        ids.len()
    );

    Ok((ids.to_vec(), stats))
}
