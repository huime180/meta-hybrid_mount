/**
 * Copyright 2025 Meta-Hybrid Mount Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

export default defineConfig({
  base: "./",
  build: {
    outDir: "../module/webroot",
    target: "esnext",
  },
  plugins: [solid()],
});
