// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};

use crate::conf::{cli::Cli, config::Config};

pub fn load_config(cli: &Cli) -> Result<Config> {
    if let Some(config_path) = &cli.config {
        return Config::load_optional_from_file(config_path).with_context(|| {
            format!(
                "Failed to load config from custom path: {}",
                config_path.display()
            )
        });
    }

    match Config::load_default() {
        Ok(config) => Ok(config),
        Err(e) => {
            let is_not_found = e
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .map(|io_err| io_err.kind() == std::io::ErrorKind::NotFound)
                .unwrap_or(false);

            if !is_not_found {
                crate::scoped_log!(
                    warn,
                    "config",
                    "load_default failed, fallback=defaults: {:#}",
                    e
                );
            }

            Ok(Config::default())
        }
    }
}
