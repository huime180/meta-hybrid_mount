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

use crate::{conf::config::Config, sys::hymofs};

#[derive(Debug, Clone, Default)]
pub struct BackendCapabilities {
    hymofs_status: String,
    hymofs_usable: bool,
}

impl BackendCapabilities {
    pub fn detect(config: &Config) -> Self {
        let status = hymofs::check_status();

        Self {
            hymofs_status: hymofs::status_name(status).to_string(),
            hymofs_usable: config.hymofs.enabled
                && hymofs::can_operate(config.hymofs.ignore_protocol_mismatch),
        }
    }

    pub fn can_use_hymofs(&self) -> bool {
        self.hymofs_usable
    }

    pub fn hymofs_status(&self) -> &str {
        &self.hymofs_status
    }
}
