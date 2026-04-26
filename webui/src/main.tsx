/**
 * Copyright 2025 Meta-Hybrid Mount Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { render } from "solid-js/web";
import "./init";
import App from "./App.tsx";
import "./app.css";
import "./layout.css";

const root = document.getElementById("app");

if (root instanceof HTMLElement) {
  render(() => <App />, root);
}
