// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

pub mod validation;

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};

pub use self::validation::*;
use crate::defs;

#[macro_export]
macro_rules! scoped_log {
    ($level:ident, $scope:literal, $fmt:literal $(, $args:expr)* $(,)?) => {
        log::$level!(concat!("[", $scope, "] ", $fmt) $(, $args)*)
    };
}

pub fn get_mnt() -> PathBuf {
    let mut name = String::new();

    for _ in 0..10 {
        name.push(fastrand::alphanumeric());
    }

    Path::new("/mnt").join(name)
}

pub fn init_logging() -> Result<()> {
    static LOGGER_INIT: OnceLock<()> = OnceLock::new();

    if LOGGER_INIT.get().is_some() {
        return Ok(());
    }

    if let Some(parent) = Path::new(defs::DAEMON_LOG_FILE).parent() {
        fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(defs::DAEMON_LOG_FILE)?;

    let logger = DualLogger {
        level: log::LevelFilter::Trace,
        file: Mutex::new(file),
    };

    log::set_boxed_logger(Box::new(logger)).map_err(|err| anyhow!("set logger failed: {err}"))?;
    log::set_max_level(log::LevelFilter::Trace);
    let _ = LOGGER_INIT.set(());
    Ok(())
}

struct DualLogger {
    level: log::LevelFilter,
    file: Mutex<std::fs::File>,
}

impl DualLogger {
    fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn format_line(&self, record: &log::Record<'_>) -> String {
        format!(
            "[{}] [{}] [{}] {}\n",
            Self::timestamp(),
            record.level(),
            record.target(),
            record.args()
        )
    }
}

impl log::Log for DualLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let line = self.format_line(record);

        let _ = io::stderr().write_all(line.as_bytes());
        let _ = io::stderr().flush();

        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }

    fn flush(&self) {
        let _ = io::stderr().flush();
        if let Ok(mut file) = self.file.lock() {
            let _ = file.flush();
        }
    }
}
