// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;

use crate::{conf::cli::Cli, core};

pub fn run(cli: Cli) -> Result<()> {
    if let Some(command) = &cli.command {
        return core::cli_commands::run(&cli, command);
    }

    core::startup::run(&cli)
}
