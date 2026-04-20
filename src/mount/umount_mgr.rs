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

use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{
    collections::HashSet,
    sync::{LazyLock, Mutex},
};

use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "android"))]
use ksu::{TryUmount, TryUmountFlags};
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::path::Arg;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub static LIST: LazyLock<Mutex<TryUmount>> = LazyLock::new(|| Mutex::new(TryUmount::new()));
#[cfg(any(target_os = "linux", target_os = "android"))]
static HISTORY: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

pub fn send_umountable<P>(target: P) -> Result<()>
where
    P: AsRef<Path>,
{
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = target;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if !crate::utils::KSU.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }

        let target = target.as_ref();
        let path = target.as_str()?;
        let mut history = HISTORY
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock history mutex"))?;

        history.insert(path.to_string());
        LIST.lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock umount list"))?
            .add(target);
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn commit() -> Result<()> {
    if !crate::utils::KSU.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    let mut list = LIST
        .lock()
        .map_err(|_| anyhow::anyhow!("Failed to lock umount list"))?;

    list.format_msg(|p| format!("{p:?} umount successful "));
    list.flags(TryUmountFlags::MNT_DETACH);
    if let Err(e2) = list.umount() {
        crate::scoped_log!(warn, "umount", "commit failed: {:#}", e2);
    }

    Ok(())
}
