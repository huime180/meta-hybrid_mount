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

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::{
    conf::config::{Config, OverlayMode},
    core::{
        backend_capabilities::BackendCapabilities,
        inventory::Module,
        ops::{plan::MountPlan, sync},
        storage,
    },
    defs,
    domain::MountMode,
    mount::hymofs,
};

pub struct HymofsCoordinator<'a> {
    config: &'a Config,
}

impl<'a> HymofsCoordinator<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }

    pub fn module_requests_hymofs(module: &Module) -> bool {
        matches!(module.rules.default_mode, MountMode::Hymofs)
            || module
                .rules
                .paths
                .values()
                .any(|mode| matches!(mode, MountMode::Hymofs))
    }

    pub fn backend_requested(
        &self,
        capabilities: &BackendCapabilities,
        modules: &[Module],
    ) -> bool {
        capabilities.can_use_hymofs() && modules.iter().any(Self::module_requests_hymofs)
    }

    pub fn hymofs_modules<'m>(&self, modules: &'m [Module]) -> Vec<&'m Module> {
        modules
            .iter()
            .filter(|module| Self::module_requests_hymofs(module))
            .collect()
    }

    pub fn prepare_mirror_storage(
        &self,
        capabilities: &BackendCapabilities,
        modules: &[Module],
    ) -> Result<()> {
        if !self.backend_requested(capabilities, modules) {
            return Ok(());
        }

        let hymofs_modules = self.hymofs_modules(modules);
        let hymofs_sources = hymofs_modules
            .iter()
            .map(|module| module.source_path.clone())
            .collect::<Vec<PathBuf>>();

        crate::scoped_log!(
            info,
            "hymofs:coordinator",
            "mirror storage start: target={}, modules={}",
            self.config.hymofs.mirror_path.display(),
            hymofs_modules.len()
        );

        let mut hymofs_storage = storage::setup_with_sources(
            &self.config.hymofs.mirror_path,
            &hymofs_sources,
            matches!(self.config.overlay_mode, OverlayMode::Ext4),
            &self.config.mountsource,
            true,
            Path::new(defs::HYMOFS_IMG_FILE),
        )?;

        let hymofs_modules = hymofs_modules.into_iter().cloned().collect::<Vec<_>>();
        sync::perform_sync(&hymofs_modules, hymofs_storage.mount_point(), self.config)?;
        hymofs_storage.commit(true)?;

        crate::scoped_log!(
            info,
            "hymofs:coordinator",
            "mirror storage complete: mode={}, target={}",
            hymofs_storage.mode(),
            self.config.hymofs.mirror_path.display()
        );

        Ok(())
    }

    pub fn reset_runtime(&self) -> Result<bool> {
        hymofs::reset_runtime(self.config)
    }

    pub fn apply_runtime(&self, plan: &mut MountPlan, modules: &[Module]) -> Result<bool> {
        hymofs::apply(plan, modules, self.config)
    }

    pub fn hide_overlay_xattrs(&self, target: &Path) {
        if !self.config.hymofs.enabled || !hymofs::can_operate(self.config) {
            return;
        }

        if let Err(err) = crate::sys::hymofs::hide_overlay_xattrs(target) {
            crate::scoped_log!(
                warn,
                "hymofs:coordinator",
                "hide overlay xattrs failed: target={}, error={:#}",
                target.display(),
                err
            );
        }
    }
}
