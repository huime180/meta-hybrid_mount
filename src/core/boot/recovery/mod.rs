// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

mod markers;
mod state;

use anyhow::{Context, Result};

use self::{
    markers::mark_failed_modules,
    state::{RecoveryDecision, RecoveryState},
};
use crate::{
    conf::config::Config,
    core::{MountController, recovery::ModuleStageFailure},
    sys, utils,
};

pub fn run(config: Config) -> Result<()> {
    let mut state = RecoveryState::new(&config)?;

    loop {
        let attempt = state.current_attempt();
        let mnt_base = utils::get_mnt();
        sys::fs::ensure_dir_exists(&mnt_base)?;
        log::info!(
            "[stage:recovery] attempt {}/{} started with runtime mount {}",
            attempt,
            state.max_restarts(),
            mnt_base.display()
        );

        let daemon_result = (|| -> Result<()> {
            MountController::new(config.clone(), &mnt_base)
                .init_storage(&mnt_base)
                .context("Failed to initialize storage")?
                .scan_and_sync()
                .context("Failed to scan and sync modules")?
                .generate_plan()
                .context("Failed to generate mount plan")?
                .execute()
                .context("Failed to execute mount plan")?
                .finalize()
                .context("Failed to finalize boot sequence")?;
            Ok(())
        })();

        match daemon_result {
            Ok(()) => {
                state.log_completion();
                return Ok(());
            }
            Err(e) => {
                if let Some(module_failure) = e.downcast_ref::<ModuleStageFailure>() {
                    if module_failure.module_ids.is_empty() {
                        match state.handle_unattributed_failure(module_failure.stage.to_string()) {
                            RecoveryDecision::RetryUnattributed => continue,
                            RecoveryDecision::AbortRetryLimit => {
                                return state.abort_on_retry_limit();
                            }
                            RecoveryDecision::InspectModules => {}
                        }
                    } else {
                        log::warn!(
                            "[stage:recovery] detected {} failure for modules: {}",
                            module_failure.stage,
                            module_failure.module_ids.join(", ")
                        );
                    }

                    let action = mark_failed_modules(
                        &module_failure.module_ids,
                        state.module_dirs(),
                        state.auto_skipped_mut(),
                    )?;

                    if !action.already_marked.is_empty() {
                        log::debug!(
                            "[stage:recovery] already marked modules ignored: {}",
                            action.already_marked.join(", ")
                        );
                    }
                    if !action.unknown_modules.is_empty() {
                        log::error!(
                            "[event:recovery_unknown_modules] stage={} attempt={}/{} modules={}",
                            module_failure.stage,
                            attempt,
                            state.max_restarts(),
                            action.unknown_modules.join(",")
                        );
                    }

                    if !action.newly_marked.is_empty() {
                        log::warn!(
                            "[event:recovery_mark_skip] stage={} attempt={}/{} modules={}",
                            module_failure.stage,
                            attempt,
                            state.max_restarts(),
                            action.newly_marked.join(",")
                        );

                        match state.handle_newly_marked_modules(module_failure.stage.to_string()) {
                            RecoveryDecision::RetryUnattributed => continue,
                            RecoveryDecision::AbortRetryLimit => {
                                return state.abort_on_retry_limit();
                            }
                            RecoveryDecision::InspectModules => continue,
                        }
                    }

                    log::error!(
                        "[stage:recovery] no newly marked modules for {} failure; aborting to avoid retry loop",
                        module_failure.stage
                    );
                }

                let err_msg = format!("{:#}", e).replace('\n', " -> ");
                log::error!("[stage:recovery] unrecoverable error: {}", err_msg);
                crate::core::module_description::update_crash_description(&err_msg);
                return Err(e);
            }
        }
    }
}
