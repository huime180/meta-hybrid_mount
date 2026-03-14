// Copyright 2026 Hybrid Mount Developers
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use anyhow::Result;


pub trait StorageBackend: Send + Sync {
    fn commit(&mut self, disable_umount: bool) -> Result<()>;
    fn mount_point(&self) -> &Path;
    fn mode(&self) -> &str;
}
