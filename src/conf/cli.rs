// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::defs;

#[derive(Parser, Debug)]
#[command(name = "hybrid-mount", version, about = "Hybrid Mount Metamodule")]
pub struct Cli {
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
    #[arg(short = 'm', long = "moduledir")]
    pub moduledir: Option<PathBuf>,
    #[arg(short = 's', long = "mountsource")]
    pub mountsource: Option<String>,
    #[arg(short = 'p', long = "partitions", value_delimiter = ',')]
    pub partitions: Vec<String>,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    GenConfig {
        #[arg(short = 'o', long = "output", default_value = defs::CONFIG_FILE)]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    ShowConfig,
    #[command(name = "save-config")]
    SaveConfig {
        #[arg(long)]
        payload: String,
    },
    #[command(name = "save-module-rules")]
    SaveModuleRules {
        #[arg(long)]
        module: String,
        #[arg(long)]
        payload: String,
    },
    Modules,
    State,
    Logs {
        #[arg(long, default_value_t = 200)]
        lines: usize,
    },
    Api {
        #[command(subcommand)]
        command: ApiCommands,
    },
    Lkm {
        #[command(subcommand)]
        command: LkmCommands,
    },
    Hide {
        #[command(subcommand)]
        command: HideCommands,
    },
    Hymofs {
        #[command(subcommand)]
        command: HymofsCommands,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToggleState {
    On,
    Off,
}

impl ToggleState {
    pub fn enabled(self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Subcommand, Debug)]
pub enum HymofsCommands {
    Status,
    List,
    Version,
    Features,
    Hooks,
    Clear,
    #[command(name = "release-connection")]
    ReleaseConnection,
    #[command(name = "invalidate-cache")]
    InvalidateCache,
    #[command(name = "fix-mounts")]
    FixMounts,
    Enable,
    Disable,
    Hidexattr {
        state: ToggleState,
    },
    #[command(name = "set-mirror")]
    SetMirror {
        path: PathBuf,
    },
    Debug {
        state: ToggleState,
    },
    Stealth {
        state: ToggleState,
    },
    #[command(name = "ignore-protocol")]
    IgnoreProtocol {
        state: ToggleState,
    },
    #[command(name = "mount-hide")]
    MountHide {
        state: ToggleState,
        #[arg(long)]
        path_pattern: Option<PathBuf>,
    },
    #[command(name = "maps-spoof")]
    MapsSpoof {
        state: ToggleState,
    },
    #[command(name = "statfs-spoof")]
    StatfsSpoof {
        state: ToggleState,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long = "f-type")]
        f_type: Option<u64>,
    },
    Uname {
        #[command(subcommand)]
        command: HymofsUnameCommands,
    },
    Cmdline {
        #[command(subcommand)]
        command: HymofsCmdlineCommands,
    },
    #[command(name = "hide-uids")]
    HideUids {
        #[command(subcommand)]
        command: HymofsHideUidsCommands,
    },
    Maps {
        #[command(subcommand)]
        command: HymofsMapsCommands,
    },
    Kstat {
        #[command(subcommand)]
        command: HymofsKstatCommands,
    },
    Rule {
        #[command(subcommand)]
        command: HymofsRuleCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum HideCommands {
    List,
    Add { path: PathBuf },
    Remove { path: PathBuf },
    Apply,
}

#[derive(Subcommand, Debug)]
pub enum ApiCommands {
    System,
    Storage,
    #[command(name = "mount-stats")]
    MountStats,
    Partitions,
    Lkm,
    Features,
    Hooks,
}

#[derive(Subcommand, Debug)]
pub enum LkmCommands {
    Load,
    Unload,
    Status,
    #[command(name = "set-autoload")]
    SetAutoload {
        state: ToggleState,
    },
    #[command(name = "set-kmi")]
    SetKmi {
        kmi: String,
    },
    #[command(name = "clear-kmi")]
    ClearKmi,
}

#[derive(Subcommand, Debug)]
pub enum HymofsUnameCommands {
    Set {
        #[arg(long)]
        sysname: Option<String>,
        #[arg(long)]
        nodename: Option<String>,
        #[arg(long)]
        release: Option<String>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        machine: Option<String>,
        #[arg(long)]
        domainname: Option<String>,
    },
    Clear,
}

#[derive(Subcommand, Debug)]
pub enum HymofsCmdlineCommands {
    Set { value: String },
    Clear,
}

#[derive(Subcommand, Debug)]
pub enum HymofsHideUidsCommands {
    Set {
        #[arg(num_args = 1..)]
        uids: Vec<u32>,
    },
    Clear,
}

#[derive(Subcommand, Debug)]
pub enum HymofsMapsCommands {
    Add {
        #[arg(long = "target-ino")]
        target_ino: u64,
        #[arg(long = "target-dev")]
        target_dev: u64,
        #[arg(long = "spoofed-ino")]
        spoofed_ino: u64,
        #[arg(long = "spoofed-dev")]
        spoofed_dev: u64,
        #[arg(long = "path")]
        path: PathBuf,
    },
    Clear,
}

#[derive(Subcommand, Debug)]
pub enum HymofsKstatCommands {
    Upsert {
        #[arg(long = "target-ino")]
        target_ino: u64,
        #[arg(long = "target-path")]
        target_path: PathBuf,
        #[arg(long = "spoofed-ino")]
        spoofed_ino: u64,
        #[arg(long = "spoofed-dev")]
        spoofed_dev: u64,
        #[arg(long = "spoofed-nlink", default_value_t = 0)]
        spoofed_nlink: u32,
        #[arg(long = "spoofed-size", default_value_t = 0)]
        spoofed_size: i64,
        #[arg(long = "atime-sec", default_value_t = 0)]
        spoofed_atime_sec: i64,
        #[arg(long = "atime-nsec", default_value_t = 0)]
        spoofed_atime_nsec: i64,
        #[arg(long = "mtime-sec", default_value_t = 0)]
        spoofed_mtime_sec: i64,
        #[arg(long = "mtime-nsec", default_value_t = 0)]
        spoofed_mtime_nsec: i64,
        #[arg(long = "ctime-sec", default_value_t = 0)]
        spoofed_ctime_sec: i64,
        #[arg(long = "ctime-nsec", default_value_t = 0)]
        spoofed_ctime_nsec: i64,
        #[arg(long = "blksize", default_value_t = 0)]
        spoofed_blksize: u64,
        #[arg(long = "blocks", default_value_t = 0)]
        spoofed_blocks: u64,
        #[arg(long = "static", default_value_t = false)]
        is_static: bool,
    },
    #[command(name = "clear-config")]
    ClearConfig,
}

#[derive(Subcommand, Debug)]
pub enum HymofsRuleCommands {
    Add {
        target: PathBuf,
        source: PathBuf,
        #[arg(long = "type")]
        file_type: Option<i32>,
    },
    Merge {
        target: PathBuf,
        source: PathBuf,
    },
    Hide {
        path: PathBuf,
    },
    Delete {
        path: PathBuf,
    },
    #[command(name = "add-dir")]
    AddDir {
        target_base: PathBuf,
        source_dir: PathBuf,
    },
    #[command(name = "remove-dir")]
    RemoveDir {
        target_base: PathBuf,
        source_dir: PathBuf,
    },
}
