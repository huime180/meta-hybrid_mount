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

use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::Result;

use crate::{
    conf::config::Config,
    core::{
        backend_capabilities::BackendCapabilities,
        hymofs_coordinator::HymofsCoordinator,
        inventory::{self},
        ops::{
            executor::{self},
            plan::MountPlan,
            planner, sync,
        },
        recovery::{FailureStage, ModuleStageFailure},
        runtime_finalization,
        storage::StorageHandle,
    },
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
    pub plan: MountPlan,
}

pub struct Executed {
    pub handle: StorageHandle,
    pub plan: MountPlan,
    pub result: executor::ExecutionResult,
}

pub struct MountController<S> {
    config: Config,
    backend_capabilities: BackendCapabilities,
    state: S,
    tempdir: PathBuf,
}

impl MountController<Init> {
    pub fn new<P>(config: Config, tempdir: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self {
            backend_capabilities: BackendCapabilities::detect(&config),
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
        let handle = crate::core::storage::setup(
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
            backend_capabilities: self.backend_capabilities,
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

        let hymofs = HymofsCoordinator::new(&self.config);
        hymofs
            .prepare_mirror_storage(&self.backend_capabilities, &modules)
            .map_err(|err| {
                let module_ids = hymofs
                    .hymofs_modules(&modules)
                    .into_iter()
                    .map(|module| module.id.clone())
                    .collect();
                ModuleStageFailure::new(
                    FailureStage::Sync,
                    module_ids,
                    anyhow::anyhow!("Failed to prepare HymoFS mirror storage: {:#}", err),
                )
            })?;

        Ok(MountController {
            config: self.config,
            backend_capabilities: self.backend_capabilities,
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
            &self.backend_capabilities,
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
            backend_capabilities: self.backend_capabilities,
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
            backend_capabilities: self.backend_capabilities,
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

        clean_up(
            &self.tempdir,
            &self.config.hymofs.mirror_path,
            self.config.disable_umount,
        )?;

        crate::scoped_log!(info, "controller:finalize", "complete");

        Ok(())
    }
}

fn clean_up(tempdir: &Path, hymofs_mirror_path: &Path, disable_umount: bool) -> Result<()> {
    if disable_umount {
        crate::scoped_log!(
            debug,
            "controller:finalize",
            "cleanup skipped: path={}, reason=disable_umount",
            tempdir.display()
        );
        return Ok(());
    }

    if !tempdir.starts_with("/mnt") {
        crate::scoped_log!(
            debug,
            "controller:finalize",
            "cleanup skipped: path={}, reason=outside_mnt",
            tempdir.display()
        );
        return Ok(());
    }

    clean_up_path(tempdir, hymofs_mirror_path)
}

fn clean_up_path(tempdir: &Path, hymofs_mirror_path: &Path) -> Result<()> {
    if tempdir == hymofs_mirror_path {
        crate::scoped_log!(
            info,
            "controller:finalize",
            "cleanup skipped: path={}, reason=hymofs_mirror",
            tempdir.display()
        );
        return Ok(());
    }

    if hymofs_mirror_path.starts_with(tempdir) {
        let Some(preserved_child) = hymofs_mirror_path
            .strip_prefix(tempdir)
            .ok()
            .and_then(|relative| relative.components().next())
            .map(|component| component.as_os_str().to_owned())
        else {
            return Ok(());
        };

        crate::scoped_log!(
            info,
            "controller:finalize",
            "cleanup partial: path={}, preserve={}",
            tempdir.display(),
            hymofs_mirror_path.display()
        );

        let entries = match fs::read_dir(tempdir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        };

        for entry in entries {
            let entry = entry?;
            if entry.file_name() == preserved_child {
                continue;
            }
            remove_path(&entry.path())?;
        }

        return Ok(());
    }

    crate::scoped_log!(
        info,
        "controller:finalize",
        "cleanup: remove={}",
        tempdir.display()
    );
    remove_path(tempdir)
}

fn remove_path(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::clean_up_path;

    #[test]
    fn clean_up_path_removes_tempdir_when_no_hymofs_mirror_is_inside() {
        let temp = tempdir().expect("failed to create temp dir");
        let mount_dir = temp.path().join("mnt-session");
        fs::create_dir_all(&mount_dir).expect("failed to create mount dir");
        fs::write(mount_dir.join("marker"), b"temp").expect("failed to create marker file");

        clean_up_path(&mount_dir, &temp.path().join("hymo-outside"))
            .expect("cleanup should succeed");

        assert!(!mount_dir.exists());
    }

    #[test]
    fn clean_up_path_preserves_nested_hymofs_mirror_dir() {
        let temp = tempdir().expect("failed to create temp dir");
        let mount_dir = temp.path().join("mnt-session");
        let magic_dir = mount_dir.join("magic_workspace");
        let hymofs_dir = mount_dir.join("hymofs");

        fs::create_dir_all(&magic_dir).expect("failed to create magic dir");
        fs::create_dir_all(&hymofs_dir).expect("failed to create hymofs dir");
        fs::write(magic_dir.join("marker"), b"temp").expect("failed to create magic marker");
        fs::write(hymofs_dir.join("marker"), b"hymo").expect("failed to create hymofs marker");

        clean_up_path(&mount_dir, &hymofs_dir).expect("cleanup should succeed");

        assert!(mount_dir.exists());
        assert!(!magic_dir.exists());
        assert!(hymofs_dir.exists());
    }
}
