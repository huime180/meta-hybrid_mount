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

use std::path::Path;

use anyhow::Result;

use crate::{
    conf::config::Config,
    core::{module_status, ops::executor::ExecutionResult, runtime_state::RuntimeState},
    defs,
};

pub fn finalize(
    config: &Config,
    storage_mode: &str,
    mount_point: &Path,
    result: &ExecutionResult,
) -> Result<()> {
    module_status::update_description(
        storage_mode,
        result.overlay_module_ids.len(),
        result.magic_module_ids.len(),
        result.hymofs_module_ids.len(),
    );

    let state = RuntimeState::build_from_execution(
        config,
        storage_mode,
        mount_point,
        result,
        defs::DAEMON_LOG_FILE.into(),
    );
    if let Err(err) = state.save() {
        crate::scoped_log!(warn, "finalize", "save runtime state failed: {:#}", err);
    }

    Ok(())
}
