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

use anyhow::Result;

use crate::conf::{
    cli::{
        ApiCommands, Cli, Commands, HideCommands, HymofsCmdlineCommands, HymofsCommands,
        HymofsHideUidsCommands, HymofsKstatCommands, HymofsMapsCommands, HymofsRuleCommands,
        HymofsUnameCommands, LkmCommands,
    },
    cli_handlers,
};

pub fn run(cli: &Cli, command: &Commands) -> Result<()> {
    let _ = crate::utils::init_logging();

    match command {
        Commands::GenConfig { output, force } => cli_handlers::handle_gen_config(output, *force),
        Commands::ShowConfig => cli_handlers::handle_show_config(cli),
        Commands::SaveConfig { payload } => cli_handlers::handle_save_config(payload),
        Commands::SaveModuleRules { module, payload } => {
            cli_handlers::handle_save_module_rules(module, payload)
        }
        Commands::Modules => cli_handlers::handle_modules(cli),
        Commands::State => cli_handlers::handle_state(),
        Commands::Logs { lines } => cli_handlers::handle_logs(*lines),
        Commands::Api { command } => match command {
            ApiCommands::System => cli_handlers::handle_api_system(cli),
            ApiCommands::Storage => cli_handlers::handle_api_storage(),
            ApiCommands::MountStats => cli_handlers::handle_api_mount_stats(),
            ApiCommands::MountTopology => cli_handlers::handle_api_mount_topology(cli),
            ApiCommands::Partitions => cli_handlers::handle_api_partitions(cli),
            ApiCommands::Lkm => cli_handlers::handle_api_lkm(cli),
            ApiCommands::Features => cli_handlers::handle_api_features(),
            ApiCommands::Hooks => cli_handlers::handle_api_hooks(cli),
        },
        Commands::Lkm { command } => match command {
            LkmCommands::Load => cli_handlers::handle_lkm_load(cli),
            LkmCommands::Unload => cli_handlers::handle_lkm_unload(cli),
            LkmCommands::Status => cli_handlers::handle_lkm_status(cli),
            LkmCommands::SetAutoload { state } => {
                cli_handlers::handle_lkm_set_autoload(cli, state.enabled())
            }
            LkmCommands::SetKmi { kmi } => cli_handlers::handle_lkm_set_kmi(cli, kmi),
            LkmCommands::ClearKmi => cli_handlers::handle_lkm_clear_kmi(cli),
        },
        Commands::Hide { command } => match command {
            HideCommands::List => cli_handlers::handle_hide_list(),
            HideCommands::Add { path } => cli_handlers::handle_hide_add(cli, path),
            HideCommands::Remove { path } => cli_handlers::handle_hide_remove(path),
            HideCommands::Apply => cli_handlers::handle_hide_apply(cli),
        },
        Commands::Hymofs { command } => match command {
            HymofsCommands::Status => cli_handlers::handle_hymofs_status(cli),
            HymofsCommands::List => cli_handlers::handle_hymofs_list(cli),
            HymofsCommands::Version => cli_handlers::handle_hymofs_version(cli),
            HymofsCommands::Features => cli_handlers::handle_hymofs_features(),
            HymofsCommands::Hooks => cli_handlers::handle_hymofs_hooks(),
            HymofsCommands::Clear => cli_handlers::handle_hymofs_clear(),
            HymofsCommands::ReleaseConnection => cli_handlers::handle_hymofs_release_connection(),
            HymofsCommands::InvalidateCache => cli_handlers::handle_hymofs_invalidate_cache(),
            HymofsCommands::FixMounts => cli_handlers::handle_hymofs_fix_mounts(),
            HymofsCommands::Enable => cli_handlers::handle_hymofs_set_enabled(cli, true),
            HymofsCommands::Disable => cli_handlers::handle_hymofs_set_enabled(cli, false),
            HymofsCommands::Hidexattr { state } => {
                cli_handlers::handle_hymofs_set_hidexattr(cli, state.enabled())
            }
            HymofsCommands::SetMirror { path } => cli_handlers::handle_hymofs_set_mirror(cli, path),
            HymofsCommands::Debug { state } => {
                cli_handlers::handle_hymofs_set_debug(cli, state.enabled())
            }
            HymofsCommands::Stealth { state } => {
                cli_handlers::handle_hymofs_set_stealth(cli, state.enabled())
            }
            HymofsCommands::IgnoreProtocol { state } => {
                cli_handlers::handle_hymofs_set_ignore_protocol_mismatch(cli, state.enabled())
            }
            HymofsCommands::MountHide {
                state,
                path_pattern,
            } => cli_handlers::handle_hymofs_set_mount_hide(
                cli,
                state.enabled(),
                path_pattern.as_deref(),
            ),
            HymofsCommands::MapsSpoof { state } => {
                cli_handlers::handle_hymofs_set_maps_spoof(cli, state.enabled())
            }
            HymofsCommands::StatfsSpoof {
                state,
                path,
                f_type,
            } => cli_handlers::handle_hymofs_set_statfs_spoof(
                cli,
                state.enabled(),
                path.as_deref(),
                *f_type,
            ),
            HymofsCommands::Uname { command } => match command {
                HymofsUnameCommands::Set {
                    sysname,
                    nodename,
                    release,
                    version,
                    machine,
                    domainname,
                } => cli_handlers::handle_hymofs_set_uname(
                    cli,
                    sysname.as_deref(),
                    nodename.as_deref(),
                    release.as_deref(),
                    version.as_deref(),
                    machine.as_deref(),
                    domainname.as_deref(),
                ),
                HymofsUnameCommands::Clear => cli_handlers::handle_hymofs_clear_uname(cli),
            },
            HymofsCommands::Cmdline { command } => match command {
                HymofsCmdlineCommands::Set { value } => {
                    cli_handlers::handle_hymofs_set_cmdline(cli, value)
                }
                HymofsCmdlineCommands::Clear => cli_handlers::handle_hymofs_clear_cmdline(cli),
            },
            HymofsCommands::HideUids { command } => match command {
                HymofsHideUidsCommands::Set { uids } => {
                    cli_handlers::handle_hymofs_set_hide_uids(cli, uids)
                }
                HymofsHideUidsCommands::Clear => cli_handlers::handle_hymofs_clear_hide_uids(cli),
            },
            HymofsCommands::Maps { command } => match command {
                HymofsMapsCommands::Add {
                    target_ino,
                    target_dev,
                    spoofed_ino,
                    spoofed_dev,
                    path,
                } => cli_handlers::handle_hymofs_add_maps_rule(
                    cli,
                    *target_ino,
                    *target_dev,
                    *spoofed_ino,
                    *spoofed_dev,
                    path,
                ),
                HymofsMapsCommands::Clear => cli_handlers::handle_hymofs_clear_maps_rules(cli),
            },
            HymofsCommands::Kstat { command } => match command {
                HymofsKstatCommands::Upsert {
                    target_ino,
                    target_path,
                    spoofed_ino,
                    spoofed_dev,
                    spoofed_nlink,
                    spoofed_size,
                    spoofed_atime_sec,
                    spoofed_atime_nsec,
                    spoofed_mtime_sec,
                    spoofed_mtime_nsec,
                    spoofed_ctime_sec,
                    spoofed_ctime_nsec,
                    spoofed_blksize,
                    spoofed_blocks,
                    is_static,
                } => cli_handlers::handle_hymofs_upsert_kstat_rule(
                    cli,
                    *target_ino,
                    target_path,
                    *spoofed_ino,
                    *spoofed_dev,
                    *spoofed_nlink,
                    *spoofed_size,
                    *spoofed_atime_sec,
                    *spoofed_atime_nsec,
                    *spoofed_mtime_sec,
                    *spoofed_mtime_nsec,
                    *spoofed_ctime_sec,
                    *spoofed_ctime_nsec,
                    *spoofed_blksize,
                    *spoofed_blocks,
                    *is_static,
                ),
                HymofsKstatCommands::ClearConfig => {
                    cli_handlers::handle_hymofs_clear_kstat_rules_config(cli)
                }
            },
            HymofsCommands::Rule { command } => match command {
                HymofsRuleCommands::Add {
                    target,
                    source,
                    file_type,
                } => cli_handlers::handle_hymofs_rule_add(cli, target, source, *file_type),
                HymofsRuleCommands::Merge { target, source } => {
                    cli_handlers::handle_hymofs_rule_merge(cli, target, source)
                }
                HymofsRuleCommands::Hide { path } => {
                    cli_handlers::handle_hymofs_rule_hide(cli, path)
                }
                HymofsRuleCommands::Delete { path } => {
                    cli_handlers::handle_hymofs_rule_delete(cli, path)
                }
                HymofsRuleCommands::AddDir {
                    target_base,
                    source_dir,
                } => cli_handlers::handle_hymofs_rule_add_dir(cli, target_base, source_dir),
                HymofsRuleCommands::RemoveDir {
                    target_base,
                    source_dir,
                } => cli_handlers::handle_hymofs_rule_remove_dir(cli, target_base, source_dir),
            },
        },
    }
}
