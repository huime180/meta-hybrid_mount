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

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ErrorPayload {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Print a structured JSON error to stdout and exit with code 0.
/// This ensures the frontend can parse error details from ksu.exec() output
/// rather than relying solely on stderr + exit code.
pub fn print_json_error(err: &anyhow::Error) {
    let payload = ErrorPayload {
        kind: "error",
        error: format!("{:#}", err),
        code: None,
    };
    println!(
        "{}",
        serde_json::to_string(&payload)
            .unwrap_or_else(|_| r#"{"type":"error","error":"failed to serialize error payload"}"#.to_string())
    );
}
