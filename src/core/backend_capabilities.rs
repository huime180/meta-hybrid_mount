// Copyright (C) 2026 YuzakiKokuban <heibanbaize@gmail.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

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
