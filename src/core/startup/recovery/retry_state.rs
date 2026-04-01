// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use anyhow::Result;

use crate::conf::config::Config;

pub(super) enum RecoveryDecision {
    RetryUnattributed,
    AbortRetryLimit,
    InspectModules,
}

pub(super) struct RecoveryState {
    module_dirs: HashMap<String, PathBuf>,
    max_restarts: usize,
    restart_round: usize,
    auto_skipped: HashSet<String>,
    unattributed_retry_used: bool,
}

impl RecoveryState {
    pub(super) fn new(config: &Config) -> anyhow::Result<Self> {
        let module_dirs = super::skip_markers::list_module_dirs(&config.moduledir)?;
        let max_restarts = module_dirs.len().saturating_add(1);
        log::info!(
            "[stage:recovery] initialized: module_candidates={}, restart_limit={}",
            module_dirs.len(),
            max_restarts
        );

        Ok(Self {
            module_dirs,
            max_restarts,
            restart_round: 0,
            auto_skipped: HashSet::new(),
            unattributed_retry_used: false,
        })
    }

    pub(super) fn current_attempt(&self) -> usize {
        self.restart_round + 1
    }

    pub(super) fn max_restarts(&self) -> usize {
        self.max_restarts
    }

    pub(super) fn module_dirs(&self) -> &HashMap<String, PathBuf> {
        &self.module_dirs
    }

    pub(super) fn auto_skipped_mut(&mut self) -> &mut HashSet<String> {
        &mut self.auto_skipped
    }

    pub(super) fn handle_unattributed_failure(&mut self, stage: String) -> RecoveryDecision {
        if self.restart_round > self.max_restarts {
            return RecoveryDecision::AbortRetryLimit;
        }

        if self.unattributed_retry_used {
            log::error!(
                "[event:recovery_retry_unattributed] exhausted=true stage={}",
                stage
            );
            return RecoveryDecision::InspectModules;
        }

        self.unattributed_retry_used = true;
        self.restart_round += 1;
        if self.restart_round > self.max_restarts {
            return RecoveryDecision::AbortRetryLimit;
        }
        log::warn!(
            "[event:recovery_retry_unattributed] stage={} next_attempt={}/{}",
            stage,
            self.restart_round + 1,
            self.max_restarts
        );
        RecoveryDecision::RetryUnattributed
    }

    pub(super) fn handle_newly_marked_modules(&mut self, stage: String) -> RecoveryDecision {
        self.restart_round += 1;
        if self.restart_round > self.max_restarts {
            return RecoveryDecision::AbortRetryLimit;
        }
        log::info!(
            "[event:recovery_restart] stage={} next_attempt={}/{}",
            stage,
            self.restart_round + 1,
            self.max_restarts
        );
        RecoveryDecision::InspectModules
    }

    pub(super) fn log_completion(&self) {
        if self.auto_skipped.is_empty() {
            log::info!("[stage:recovery] completed without auto-skip");
            return;
        }

        let mut skipped: Vec<String> = self.auto_skipped.iter().cloned().collect();
        skipped.sort();
        log::warn!(
            "[stage:recovery] completed after auto-skipping modules: {}",
            skipped.join(", ")
        );
    }

    pub(super) fn abort_on_retry_limit(&self) -> Result<()> {
        let loop_error = anyhow::anyhow!(
            "Auto-recovery reached restart limit ({} rounds), aborting to avoid loop",
            self.max_restarts
        );
        log::error!("[stage:recovery] {}", loop_error);
        crate::core::module_status::update_crash_description(&loop_error.to_string());
        Err(loop_error)
    }
}
