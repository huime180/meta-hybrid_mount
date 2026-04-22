# Hybrid Mount

<img src="https://raw.githubusercontent.com/Hybrid-Mount/meta-hybrid_mount/master/icon.svg" align="right" width="120" />

![Language](https://img.shields.io/badge/Language-Rust-orange?style=flat-square&logo=rust)
![Platform](https://img.shields.io/badge/Platform-Android-green?style=flat-square&logo=android)
![License](https://img.shields.io/badge/License-Apache--2.0-blue?style=flat-square)

Hybrid Mount is a mount orchestration metamodule for **KernelSU** and **APatch**.  
It merges module files into Android partitions with three mount modes:

- **OverlayFS** for compatibility-first layered mounts.
- **Magic Mount (bind mount)** for direct path binding or fallback.
- **HymoFS** for explicit HymoFS routing and runtime-backed hide/spoof features.

The runtime is designed for predictable boot behavior, conflict visibility, and policy-level control.

**[🇨🇳 中文文档](README_ZH.md)**

---

## Table of Contents

- [Design Goals](#design-goals)
- [Mount Modes](#mount-modes)
- [Architecture](#architecture)
- [Repository Layout](#repository-layout)
- [Configuration](#configuration)
- [HymoFS](#hymofs)
- [Policy Behavior Matrix](#policy-behavior-matrix)
- [CLI](#cli)
- [Build](#build)
- [Operational Notes](#operational-notes)
- [License](#license)

---

## Design Goals

1. **Compatibility-first mounting** across diverse Android kernels.
2. **Deterministic behavior** through explicit planning and conflict analysis.
3. **Operational safety** with recovery-friendly defaults.
4. **Automation-friendly CLI** for WebUI or external controllers.

## Mount Modes

Hybrid Mount currently supports three backend strategies:

- `overlay`: use OverlayFS for module paths that can be merged safely.
- `magic`: use Magic Mount bind mounts for direct per-path replacement or fallback.
- `hymofs`: route module paths through the HymoFS mirror/runtime when the module or path explicitly requires it.

## Architecture

At startup, `hybrid-mount` follows this pipeline:

1. Load config (file + CLI override).
2. Scan module tree and inventory mountable entries.
3. Generate an execution plan (overlay/magic/hymofs/ignore).
4. Apply mounts and persist runtime state.
5. Emit diagnostics/conflict reports when requested.

Key implementation modules:

- `src/conf`: config schema, loader, CLI handlers.
- `src/core/inventory`: module scanning and inventory modeling.
- `src/core/ops`: planning, execution, synchronization.
- `src/mount`: OverlayFS, Magic Mount, and HymoFS backends.
- `src/sys`: filesystem/mount helpers and low-level integration.

## Repository Layout

```text
.
├─ src/                 # daemon/runtime implementation
├─ module/              # module scripts and packaging assets
├─ xtask/               # build/release automation commands
├─ Cargo.toml           # workspace + runtime crate settings
└─ README*.md           # user and developer docs
```

## Configuration

Default path: `/data/adb/hybrid-mount/config.toml`.

### Top-level fields

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `moduledir` | string | `/data/adb/modules` | Module source directory. |
| `mountsource` | string | auto-detect | Runtime source tag (e.g. `KSU`, `APatch`). |
| `partitions` | list\|csv string | `[]` | Extra managed partitions. |
| `overlay_mode` | `ext4` \| `tmpfs` | `ext4` | Overlay upper/work backing mode. |
| `disable_umount` | bool | `false` | Skip umount operations (debug-only). |
| `enable_overlay_fallback` | bool | `false` | When overlayfs is unavailable, allow falling back to Magic Mount for planned overlay modules. |
| `default_mode` | `overlay` \| `magic` \| `hymofs` | `overlay` | Default policy for module paths. |
| `rules` | map | `{}` | Per-module path-level mount policy. |

### Example

```toml
moduledir = "/data/adb/modules"
mountsource = "KSU"
partitions = ["system", "vendor"]
overlay_mode = "ext4"
disable_umount = false
enable_overlay_fallback = false
default_mode = "overlay"

[rules.my_module]
default_mode = "magic"

[rules.my_module.paths]
"system/bin/tool" = "overlay"
"vendor/lib64/libfoo.so" = "ignore"
```

## HymoFS

`HymoFS` is the third mount backend in Hybrid Mount. It is kernel/LKM-backed and is used when a module/path is explicitly routed to `hymofs`, or when HymoFS-only runtime features are required.

It currently covers two categories of work:

- `mode = "hymofs"` mount mapping for modules or paths that should resolve from the HymoFS mirror tree.
- Auxiliary runtime features such as stealth/hide-xattr behavior, mount hiding, `/proc/<pid>/maps` spoofing, `statfs` spoofing, UID hiding, uname/cmdline spoofing, and per-file kstat spoof rules.

### When runtime turns on

Setting `hymofs.enabled = true` only makes the backend available. Hybrid Mount actually enables the HymoFS runtime when at least one of these is true:

- the generated mount plan contains at least one HymoFS-managed module/path
- an auxiliary feature is configured (`enable_hidexattr`, `enable_mount_hide`, `enable_maps_spoof`, `enable_statfs_spoof`, `hide_uids`, `cmdline_value`, `uname*`, `maps_rules`, `kstat_rules`, or persisted user hide rules)

Behavior details that matter in practice:

- `enable_hidexattr` is a compatibility umbrella and effectively turns on `stealth`, `mount_hide`, `maps_spoof`, and `statfs_spoof`
- `mount_hide.path_pattern` and `statfs_spoof.{path,spoof_f_type}` also count as enabling those features
- the CLI disable commands now clear those subordinate structured fields so `disable` really disables the feature instead of leaving it implicitly active

### Key config fields

| Key | Purpose |
| --- | --- |
| `hymofs.enabled` | Master switch for HymoFS integration. |
| `hymofs.lkm_autoload` | Try to auto-load the HymoFS LKM during startup. |
| `hymofs.lkm_dir` / `hymofs.lkm_kmi_override` | LKM search directory and optional KMI override. |
| `hymofs.mirror_path` | Runtime mirror root used by HymoFS rules, default `/dev/hymo_mirror`. |
| `hymofs.enable_kernel_debug` | Toggle kernel-side debug output. |
| `hymofs.enable_stealth` | Explicit stealth mode toggle. |
| `hymofs.enable_hidexattr` | Compatibility umbrella for stealth + hide/spoof helpers. |
| `hymofs.enable_mount_hide` / `hymofs.mount_hide.path_pattern` | Hide mounts globally or with a path pattern. |
| `hymofs.enable_maps_spoof` / `hymofs.maps_rules` | Enable maps spoofing and install inode/device rewrite rules. |
| `hymofs.enable_statfs_spoof` / `hymofs.statfs_spoof.*` | Enable generic or path-scoped `statfs` spoofing. |
| `hymofs.hide_uids` | Hide selected UIDs from HymoFS-aware queries. |
| `hymofs.uname.*` | Structured uname spoof fields. |
| `hymofs.cmdline_value` | Replacement kernel cmdline payload. |
| `hymofs.kstat_rules` | Per-target stat metadata spoof rules. |

### Example

```toml
[hymofs]
enabled = true
lkm_autoload = true
mirror_path = "/dev/hymo_mirror"
enable_mount_hide = true

[rules.my_module]
default_mode = "hymofs"

[rules.my_module.paths]
"system/bin/su" = "hymofs"
```

### Useful commands

```bash
# runtime/LKM status
hybrid-mount hymofs status
hybrid-mount hymofs version
hybrid-mount hymofs features
hybrid-mount lkm status

# enable/disable runtime-backed features
hybrid-mount hymofs enable
hybrid-mount hymofs disable
hybrid-mount hymofs mount-hide enable --path-pattern /dev/hymo_mirror
hybrid-mount hymofs statfs-spoof enable --path /system --f-type 0x794c7630
hybrid-mount hymofs maps add --target-ino 1 --target-dev 2 --spoofed-ino 3 --spoofed-dev 4 --path /dev/hymo_mirror/system/bin/sh
hybrid-mount hymofs kstat upsert --target-ino 11 --target-path /system/bin/app_process64 --spoofed-ino 22 --spoofed-dev 33
```

Operational caveat:

- `hymofs kstat clear-config` only removes persisted config. Existing kernel kstat spoof rules may remain until the HymoFS LKM is reloaded or the whole runtime is rebuilt.

## Policy Behavior Matrix

This matrix clarifies what happens under each policy and runtime condition:

| Rule result | Backend availability | `enable_overlay_fallback` | Effective behavior |
| --- | --- | --- | --- |
| `overlay` | OverlayFS available | any | Mount with OverlayFS. |
| `overlay` | OverlayFS unavailable | `false` | Skip mount and report as failed planning/execution item. |
| `overlay` | OverlayFS unavailable | `true` | Retry as Magic Mount (bind mount). |
| `magic` | n/a | any | Mount with Magic Mount directly. |
| `hymofs` | HymoFS available | any | Mount with HymoFS directly. |
| `hymofs` | HymoFS unavailable or disabled | any | Skip HymoFS mapping for this path/module. |
| `ignore` | n/a | any | Do not mount this path. |

### Rule precedence

When multiple policies may apply, evaluation follows this order:

1. Path-level override (`rules.<module>.paths["..."]`)
2. Module-level default (`rules.<module>.default_mode`)
3. Global default (`default_mode`)

### Practical examples

- Keep one problematic binary on bind mount while the rest of the module uses overlay:
  - set module default to `overlay`
  - set `rules.<module>.paths["system/bin/<tool>"] = "magic"`
- Temporarily disable one conflicting file without disabling the full module:
  - set `rules.<module>.paths["..."] = "ignore"`
- For kernels with unstable OverlayFS support:
  - set `enable_overlay_fallback = true` to reduce boot-time mount failures.

## CLI

```bash
hybrid-mount [OPTIONS] [COMMAND]
```

Global options:

- `-c, --config <PATH>` custom config path
- `-m, --moduledir <PATH>` override module directory
- `-s, --mountsource <SOURCE>` override source tag
- `-p, --partitions <CSV>` override partition list

Subcommands:

- `gen-config` generate config file
- `show-config` print effective config JSON
- `save-config --payload <HEX_JSON>` save config from WebUI payload
- `save-module-rules --module <ID> --payload <HEX_JSON>` update one module rule set
- `modules` list detected modules

## Build

Prerequisites:

- Rust toolchain from `rust-toolchain.toml`
- Android NDK (recommended r27+)
- `Hybrid-Mount/nuke-kpm` checkout for the GPL-2.0-only APatch KPM module source (`HYBRID_MOUNT_KPM_DIR`, or clone into `./nuke-kpm`)
- `AndroidPatch/kpm` checkout for APatch KPM builds (`HYBRID_MOUNT_KP_DIR` or `KP_DIR`)
- Node.js 20+ (only when building WebUI assets)

Build commands:

```bash
# full package
cargo run -p xtask -- build --release

# runtime only (skip web assets)
cargo run -p xtask -- build --release --skip-webui

# local arm64 debug package
./scripts/build-local.sh

# local package with prebuilt HymoFS LKM assets
./scripts/build-local.sh --release --hymofs-lkm-dir /path/to/hymofs-lkm
```

For APatch-ready release packages, export `HYBRID_MOUNT_KPM_DIR` to point at the `Hybrid-Mount/nuke-kpm` checkout, plus `HYBRID_MOUNT_KP_DIR` (or `KP_DIR`) and an Android NDK path before invoking `xtask`. Set `HYBRID_MOUNT_BUILD_KPM=1` if you want to force a KPM rebuild instead of reusing an existing artifact.

If KPM build prerequisites are available, `xtask` also builds `nuke_ext4_sysfs.kpm` from the external KPM source repo and stages it into the module zip. Release builds require that artifact; debug builds will warn and continue when KPM prerequisites are missing.

Artifacts are produced under `output/`.

## Operational Notes

- Fresh installs now rely on mount-source auto-detection unless `mountsource` is explicitly set in `config.toml`.
- On APatch, Hybrid Mount preloads `/data/adb/hybrid-mount/kpm/nuke_ext4_sysfs.kpm` through `/data/adb/ap/bin/kptools kpm load` during early startup, then issues `kpm control/call` only when `ext4_unregister_sysfs` is needed before falling back to `MNT_DETACH`.
- APatch runtime overrides are available through `HYBRID_MOUNT_APATCH_KP_BIN`, `HYBRID_MOUNT_APATCH_KPM_MODULE`, `HYBRID_MOUNT_APATCH_KPM_ID`, `HYBRID_MOUNT_APATCH_KPM_CALL_MODE`, `HYBRID_MOUNT_APATCH_KPM_CONTROL`, and `HYBRID_MOUNT_APATCH_KPM_UNUSED_NR`.
- If a bad config causes boot issues, regenerate a minimal config with `gen-config` and reapply module rules incrementally.
- For binary size optimization, prefer dependency feature trimming and release profile tuning before invasive refactors.

## License

Licensed under [Apache-2.0](LICENSE).
Optional external build inputs referenced above, such as APatch KPM sources, remain under their respective upstream licenses.
