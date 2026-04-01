// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

mod fallback;
mod magic;
mod overlay;

use std::{collections::HashSet, path::Path};

use anyhow::{Result, bail};

use crate::{
    conf::config,
    core::{
        ops::planner::MountPlan,
        recovery::{FailureStage, ModuleStageFailure},
    },
    mount::{overlayfs::utils::umount_dir, umount_mgr},
};

pub struct ExecutionResult {
    pub overlay_module_ids: Vec<String>,
    pub magic_module_ids: Vec<String>,
}

pub struct Executer;

impl Executer {
    pub fn execute<P>(
        plan: &MountPlan,
        config: &config::Config,
        tempdir: P,
    ) -> Result<ExecutionResult>
    where
        P: AsRef<Path>,
    {
        log::info!(
            "[executor] start: overlay_ops={}, preselected_magic_modules={}",
            plan.overlay_ops.len(),
            plan.magic_module_ids.len()
        );
        let mut final_magic_ids: HashSet<String> = plan.magic_module_ids.iter().cloned().collect();
        let mut final_overlay_ids: HashSet<String> = HashSet::new();

        if Self::is_supported()? {
            log::info!("[executor] overlayfs supported, applying overlay operations");
            for op in &plan.overlay_ops {
                log::info!(
                    "[executor] apply overlay op: partition={}, target={}, layers={}",
                    op.partition_name,
                    op.target,
                    op.lowerdirs.len()
                );
                match overlay::mount_overlay(op, config) {
                    Ok(ids) => {
                        log::info!(
                            "[executor] overlay op success: target={}, modules={}",
                            op.target,
                            ids.len()
                        );
                        final_overlay_ids.extend(ids);
                    }
                    Err(err) => {
                        let involved_modules = fallback::collect_involved_modules(op);
                        let is_symlink_loop = fallback::is_symlink_loop_mount_error(&err);
                        if is_symlink_loop {
                            if !fallback::overlay_fallback_allowed(config) {
                                log::error!(
                                    "[executor] overlay op hit symlink-loop mount error on {}, but enable_overlay_fallback=false; cannot downgrade to magic mount",
                                    op.target
                                );
                            } else if involved_modules.is_empty() {
                                log::error!(
                                    "[executor] overlay op hit symlink-loop mount error on {}, but no module ids were inferred; cannot downgrade to magic mount",
                                    op.target
                                );
                            } else {
                                log::warn!(
                                    "[executor] overlay op hit symlink-loop mount error on {}; fallback to magic mount for modules: {}",
                                    op.target,
                                    involved_modules.join(", ")
                                );
                                final_magic_ids.extend(involved_modules);
                                continue;
                            }
                        } else {
                            log::error!(
                                "[executor] overlay op failed on {} with non-symlink-loop error; forwarding failure to recovery",
                                op.target
                            );
                        }
                        return Err(ModuleStageFailure::new(
                            FailureStage::Execute,
                            involved_modules,
                            anyhow::anyhow!("Overlay mount failed for {}: {:#}", op.target, err),
                        )
                        .into());
                    }
                }
            }
        } else {
            if !plan.overlay_ops.is_empty() {
                if fallback::overlay_fallback_allowed(config) {
                    let fallback_ids = fallback::collect_overlay_modules_for_magic_fallback(plan);
                    if fallback_ids.is_empty() {
                        bail!(
                            "[executor] overlayfs unsupported and no modules could be inferred for magic fallback"
                        );
                    }
                    log::warn!(
                        "[executor] overlayfs unsupported, fallback enabled; switching {} modules to magic mount",
                        fallback_ids.len()
                    );
                    final_magic_ids.extend(fallback_ids);
                } else {
                    bail!("[executor] overlayfs unsupported and overlay operations are pending");
                }
            }
            log::info!("[executor] overlayfs unsupported, no overlay operations to apply");
        }

        let mut magic_need_list: Vec<String> = final_magic_ids.iter().cloned().collect();
        magic_need_list.sort();

        if !magic_need_list.is_empty() {
            let magic_need_ids: HashSet<String> = magic_need_list.iter().cloned().collect();
            log::info!(
                "[executor] applying magic mount for modules: {}",
                magic_need_list.join(", ")
            );
            let mounted_ids = magic::mount_magic(&magic_need_ids, config, tempdir.as_ref())
                .map_err(|err| {
                    let failed_module_ids =
                        fallback::resolve_magic_failure_modules(&err, &magic_need_list);
                    ModuleStageFailure::new(
                        FailureStage::Execute,
                        failed_module_ids.clone(),
                        anyhow::anyhow!(
                            "Failed to mount Magic Mount modules [{}]: {:#}",
                            failed_module_ids.join(", "),
                            err
                        ),
                    )
                })?;
            final_magic_ids.retain(|id| mounted_ids.contains(id));
            log::info!(
                "[executor] magic mount completed: mounted_modules={}",
                mounted_ids.len()
            );
        }

        let _ = umount_dir(tempdir.as_ref());

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if !config.disable_umount {
                let _ = umount_mgr::send_umountable(tempdir.as_ref());
                let _ = umount_mgr::commit();
            }
        }

        let mut result_overlay: Vec<String> = final_overlay_ids.into_iter().collect();
        let mut result_magic: Vec<String> = final_magic_ids.into_iter().collect();

        result_overlay.sort();
        result_magic.sort();

        log::info!(
            "[executor] completed: overlay_modules={}, magic_modules={}",
            result_overlay.len(),
            result_magic.len()
        );

        Ok(ExecutionResult {
            overlay_module_ids: result_overlay,
            magic_module_ids: result_magic,
        })
    }

    fn is_supported() -> Result<bool> {
        crate::mount::overlayfs::utils::is_overlay_supported()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::PathBuf};

    use anyhow::anyhow;

    use super::fallback;
    use crate::{
        conf::config::{Config, OverlayMode},
        core::ops::planner::{MountPlan, OverlayOperation},
        mount::magic_mount::MagicMountModuleFailure,
    };

    #[test]
    fn collect_overlay_modules_for_magic_fallback_deduplicates_modules() {
        let mut plan = MountPlan::default();
        plan.overlay_ops.push(OverlayOperation {
            partition_name: "system".to_string(),
            target: "/system/bin".to_string(),
            lowerdirs: vec![PathBuf::from("/modA/system"), PathBuf::from("/modB/system")],
        });
        plan.overlay_ops.push(OverlayOperation {
            partition_name: "vendor".to_string(),
            target: "/vendor/lib".to_string(),
            lowerdirs: vec![PathBuf::from("/modA/vendor"), PathBuf::from("/modC/vendor")],
        });

        let result = fallback::collect_overlay_modules_for_magic_fallback(&plan);
        let expected = HashSet::from(["modA".to_string(), "modB".to_string(), "modC".to_string()]);
        assert_eq!(result, expected);
    }

    #[test]
    fn symlink_loop_detection_matches_expected_messages() {
        let err = anyhow!(
            "Failed to fsconfig create new fs: Too many symbolic links encountered (os error 40)"
        );
        assert!(fallback::is_symlink_loop_mount_error(&err));

        let other = anyhow!("permission denied");
        assert!(!fallback::is_symlink_loop_mount_error(&other));
    }

    #[test]
    fn resolve_magic_failure_modules_prefers_precise_modules() {
        let err: anyhow::Error = MagicMountModuleFailure::new(
            vec!["modB".to_string(), "modA".to_string()],
            anyhow!("tmpfs mount failed"),
        )
        .into();
        let fallback = vec!["modA".to_string(), "modB".to_string(), "modC".to_string()];

        let result = fallback::resolve_magic_failure_modules(&err, &fallback);
        assert_eq!(result, vec!["modB".to_string(), "modA".to_string()]);
    }

    #[test]
    fn resolve_magic_failure_modules_falls_back_when_untyped_error() {
        let err = anyhow!("unknown magic mount error");
        let fallback = vec!["modA".to_string(), "modC".to_string()];

        let result = fallback::resolve_magic_failure_modules(&err, &fallback);
        assert_eq!(result, fallback);
    }

    #[test]
    fn overlay_fallback_is_controlled_by_enable_overlay_fallback() {
        let mut cfg = Config {
            overlay_mode: OverlayMode::Tmpfs,
            ..Config::default()
        };
        cfg.enable_overlay_fallback = false;
        assert!(!fallback::overlay_fallback_allowed(&cfg));

        cfg.enable_overlay_fallback = true;
        assert!(fallback::overlay_fallback_allowed(&cfg));
    }
}
