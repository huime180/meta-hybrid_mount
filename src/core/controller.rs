// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::{
    conf::config::Config,
    core::{
        inventory::{self},
        ops::{
            executor::{self},
            planner, sync,
        },
        recovery::{FailureStage, ModuleStageFailure},
        runtime_finalization,
        storage::{self, StorageHandle},
    },
    defs,
};

pub struct Init;

pub struct StorageReady {
    pub handle: StorageHandle,
}

pub struct ModulesReady {
    pub handle: StorageHandle,
    pub modules: Vec<inventory::Module>,
}

pub struct Planned {
    pub handle: StorageHandle,
    pub modules: Vec<inventory::Module>,
    pub plan: planner::MountPlan,
}

pub struct Executed {
    pub handle: StorageHandle,
    pub plan: planner::MountPlan,
    pub result: executor::ExecutionResult,
}

pub struct MountController<S> {
    config: Config,
    state: S,
    tempdir: PathBuf,
}

impl MountController<Init> {
    pub fn new<P>(config: Config, tempdir: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self {
            config,
            state: Init,
            tempdir: tempdir.as_ref().to_path_buf(),
        }
    }

    pub fn init_storage(self, mnt_base: &Path) -> Result<MountController<StorageReady>> {
        crate::scoped_log!(
            info,
            "controller:init_storage",
            "start: mount_base={}",
            mnt_base.display()
        );
        let handle = storage::setup(
            mnt_base,
            &self.config.moduledir,
            matches!(
                self.config.overlay_mode,
                crate::conf::config::OverlayMode::Ext4
            ),
            &self.config.mountsource,
            self.config.disable_umount,
        )?;

        crate::scoped_log!(
            info,
            "controller:init_storage",
            "complete: mode={}, mount_point={}",
            handle.mode(),
            handle.mount_point().display()
        );

        Ok(MountController {
            config: self.config,
            state: StorageReady { handle },
            tempdir: self.tempdir,
        })
    }
}

impl MountController<StorageReady> {
    pub fn scan_and_sync(mut self) -> Result<MountController<ModulesReady>> {
        crate::scoped_log!(
            info,
            "controller:scan_and_sync",
            "scan start: moduledir={}",
            self.config.moduledir.display()
        );
        let modules = inventory::scan(&self.config.moduledir, &self.config)?;

        crate::scoped_log!(
            info,
            "controller:scan_and_sync",
            "scan complete: modules={}",
            modules.len()
        );

        crate::scoped_log!(info, "controller:scan_and_sync", "sync start");
        sync::perform_sync(&modules, self.state.handle.mount_point(), &self.config)?;

        self.state.handle.commit(self.config.disable_umount)?;

        crate::scoped_log!(info, "controller:scan_and_sync", "commit complete");

        if planner::hymofs_backend_requested(&self.config, &modules) {
            let hymofs_modules: Vec<_> = modules
                .iter()
                .filter(|module| planner::module_requests_hymofs(module))
                .cloned()
                .collect();
            let hymofs_module_ids: Vec<String> = hymofs_modules
                .iter()
                .map(|module| module.id.clone())
                .collect();
            let hymofs_sources = hymofs_modules
                .iter()
                .map(|module| module.source_path.clone())
                .collect::<Vec<_>>();

            crate::scoped_log!(
                info,
                "controller:scan_and_sync",
                "hymofs storage start: target={}, modules={}",
                self.config.hymofs.mirror_path.display(),
                hymofs_modules.len()
            );

            let mut hymofs_storage = storage::setup_with_sources(
                &self.config.hymofs.mirror_path,
                &hymofs_sources,
                matches!(
                    self.config.overlay_mode,
                    crate::conf::config::OverlayMode::Ext4
                ),
                &self.config.mountsource,
                true,
                std::path::Path::new(defs::HYMOFS_IMG_FILE),
            )
            .map_err(|err| {
                ModuleStageFailure::new(
                    FailureStage::Sync,
                    hymofs_module_ids.clone(),
                    anyhow::anyhow!("Failed to initialize HymoFS mirror storage: {:#}", err),
                )
            })?;

            sync::perform_sync(&hymofs_modules, hymofs_storage.mount_point(), &self.config)?;
            hymofs_storage.commit(true).map_err(|err| {
                ModuleStageFailure::new(
                    FailureStage::Sync,
                    hymofs_module_ids.clone(),
                    anyhow::anyhow!("Failed to finalize HymoFS mirror storage: {:#}", err),
                )
            })?;

            crate::scoped_log!(
                info,
                "controller:scan_and_sync",
                "hymofs storage complete: mode={}, target={}",
                hymofs_storage.mode(),
                self.config.hymofs.mirror_path.display()
            );
        }

        Ok(MountController {
            config: self.config,
            state: ModulesReady {
                handle: self.state.handle,
                modules,
            },
            tempdir: self.tempdir,
        })
    }
}

impl MountController<ModulesReady> {
    pub fn generate_plan(self) -> Result<MountController<Planned>> {
        crate::scoped_log!(info, "controller:generate_plan", "start");
        let plan = planner::generate(
            &self.config,
            &self.state.modules,
            self.state.handle.mount_point(),
        )?;

        crate::scoped_log!(
            info,
            "controller:generate_plan",
            "complete: overlay_ops={}, overlay_modules={}, magic_modules={}, hymofs_modules={}, hymofs_rule_compile=deferred",
            plan.overlay_ops.len(),
            plan.overlay_module_ids.len(),
            plan.magic_module_ids.len(),
            plan.hymofs_module_ids.len()
        );

        Ok(MountController {
            config: self.config,
            state: Planned {
                handle: self.state.handle,
                modules: self.state.modules,
                plan,
            },
            tempdir: self.tempdir,
        })
    }
}

impl MountController<Planned> {
    pub fn execute(mut self) -> Result<MountController<Executed>> {
        crate::scoped_log!(info, "controller:execute", "start");
        let result = executor::Executor::execute(
            &mut self.state.plan,
            &self.state.modules,
            &self.config,
            self.tempdir.clone(),
        )?;

        crate::scoped_log!(
            info,
            "controller:execute",
            "complete: overlay_mounted={}, magic_mounted={}, hymofs_mounted={}",
            result.overlay_module_ids.len(),
            result.magic_module_ids.len(),
            result.hymofs_module_ids.len()
        );

        Ok(MountController {
            config: self.config,
            state: Executed {
                handle: self.state.handle,
                plan: self.state.plan,
                result,
            },
            tempdir: self.tempdir,
        })
    }
}

impl MountController<Executed> {
    pub fn finalize(self) -> Result<()> {
        crate::scoped_log!(info, "controller:finalize", "start");
        runtime_finalization::finalize(
            &self.config,
            self.state.handle.mode(),
            self.state.handle.mount_point(),
            &self.state.plan,
            &self.state.result,
        )?;

        crate::scoped_log!(info, "controller:finalize", "complete");

        Ok(())
    }
}
