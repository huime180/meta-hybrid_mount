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
