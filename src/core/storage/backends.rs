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

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::core::backend::StorageBackend;

pub struct Ext4Backend {
    pub mount_point: PathBuf,
    pub mode: String,
}

impl Ext4Backend {
    pub fn new(mount_point: &Path) -> Self {
        Self {
            mount_point: mount_point.to_path_buf(),
            mode: "ext4".to_string(),
        }
    }
}

impl StorageBackend for Ext4Backend {
    fn commit(&mut self, _disable_umount: bool) -> Result<()> {
        Ok(())
    }

    fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    fn mode(&self) -> &str {
        &self.mode
    }
}

pub struct TmpfsBackend {
    pub mount_point: PathBuf,
    pub mode: String,
}

impl TmpfsBackend {
    pub fn new(mount_point: &Path) -> Self {
        Self {
            mount_point: mount_point.to_path_buf(),
            mode: "tmpfs".to_string(),
        }
    }
}

impl StorageBackend for TmpfsBackend {
    fn commit(&mut self, _disable_umount: bool) -> Result<()> {
        Ok(())
    }

    fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    fn mode(&self) -> &str {
        &self.mode
    }
}
