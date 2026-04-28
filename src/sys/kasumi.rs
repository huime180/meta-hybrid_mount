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

#![allow(dead_code)]

use std::{
    ffi::{CString, c_char, c_int, c_long, c_uint, c_ulong, c_void},
    fs,
    mem::size_of,
    os::{
        fd::BorrowedFd,
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt},
        },
    },
    path::Path,
    sync::{LazyLock, Mutex},
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{thread, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use rustix::{
    io::Errno,
    ioctl::{self, Ioctl, IoctlOutput, Opcode},
};
use walkdir::WalkDir;

pub const HYMO_MAGIC1: c_int = 0x4859_4D4F;
pub const HYMO_MAGIC2: c_int = 0x524F_4F54;
pub const HYMO_PROTOCOL_VERSION: c_int = 14;

pub const HYMO_MAX_LEN_PATHNAME: usize = 256;
pub const HYMO_FAKE_CMDLINE_SIZE: usize = 4096;
pub const HYMO_UNAME_LEN: usize = 65;

pub const HYMO_SYSCALL_NR: libc::c_long = 142;
pub const HYMO_CMD_GET_FD: c_int = 0x48021;
pub const HYMO_PRCTL_GET_FD: c_int = 0x48021;

pub const HYMO_FEATURE_KSTAT_SPOOF: c_int = 1 << 0;
pub const HYMO_FEATURE_UNAME_SPOOF: c_int = 1 << 1;
pub const HYMO_FEATURE_CMDLINE_SPOOF: c_int = 1 << 2;
pub const HYMO_FEATURE_SELINUX_BYPASS: c_int = 1 << 4;
pub const HYMO_FEATURE_MERGE_DIR: c_int = 1 << 5;
pub const HYMO_FEATURE_MOUNT_HIDE: c_int = 1 << 6;
pub const HYMO_FEATURE_MAPS_SPOOF: c_int = 1 << 7;
pub const HYMO_FEATURE_STATFS_SPOOF: c_int = 1 << 8;

const HYMO_IOC_MAGIC: u8 = b'H';

type HymoIoctlRequest = Opcode;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HymoSyscallArg {
    pub src: *const c_char,
    pub target: *const c_char,
    pub type_: c_int,
}

impl HymoSyscallArg {
    fn new(src: &CString, target: Option<&CString>, type_: c_int) -> Self {
        Self {
            src: src.as_ptr(),
            target: target.map_or(std::ptr::null(), |value| value.as_ptr()),
            type_,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HymoSyscallListArg {
    pub buf: *mut c_char,
    pub size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HymoUidListArg {
    pub count: u32,
    pub reserved: u32,
    pub uids: u64,
}

impl HymoUidListArg {
    pub fn from_slice(uids: &[u32]) -> Self {
        Self {
            count: uids.len() as u32,
            reserved: 0,
            uids: if uids.is_empty() {
                0
            } else {
                uids.as_ptr() as usize as u64
            },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HymoSpoofKstat {
    pub target_ino: c_ulong,
    pub target_pathname: [c_char; HYMO_MAX_LEN_PATHNAME],
    pub spoofed_ino: c_ulong,
    pub spoofed_dev: c_ulong,
    pub spoofed_nlink: c_uint,
    pub spoofed_size: i64,
    pub spoofed_atime_sec: c_long,
    pub spoofed_atime_nsec: c_long,
    pub spoofed_mtime_sec: c_long,
    pub spoofed_mtime_nsec: c_long,
    pub spoofed_ctime_sec: c_long,
    pub spoofed_ctime_nsec: c_long,
    pub spoofed_blksize: c_ulong,
    pub spoofed_blocks: u64,
    pub is_static: c_int,
    pub err: c_int,
}

impl Default for HymoSpoofKstat {
    fn default() -> Self {
        Self {
            target_ino: 0,
            target_pathname: [0; HYMO_MAX_LEN_PATHNAME],
            spoofed_ino: 0,
            spoofed_dev: 0,
            spoofed_nlink: 0,
            spoofed_size: 0,
            spoofed_atime_sec: 0,
            spoofed_atime_nsec: 0,
            spoofed_mtime_sec: 0,
            spoofed_mtime_nsec: 0,
            spoofed_ctime_sec: 0,
            spoofed_ctime_nsec: 0,
            spoofed_blksize: 0,
            spoofed_blocks: 0,
            is_static: 0,
            err: 0,
        }
    }
}

impl HymoSpoofKstat {
    pub fn new(target_ino: c_ulong, target_pathname: impl AsRef<Path>) -> Result<Self> {
        let mut value = Self {
            target_ino,
            ..Self::default()
        };
        value.set_target_pathname(target_pathname)?;
        Ok(value)
    }

    pub fn set_target_pathname(&mut self, target_pathname: impl AsRef<Path>) -> Result<()> {
        write_path_into_c_buf(
            &mut self.target_pathname,
            target_pathname.as_ref(),
            "Kasumi kstat target pathname",
        )
    }

    pub fn target_pathname(&self) -> String {
        read_c_buf(&self.target_pathname)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HymoSpoofUname {
    pub sysname: [c_char; HYMO_UNAME_LEN],
    pub nodename: [c_char; HYMO_UNAME_LEN],
    pub release: [c_char; HYMO_UNAME_LEN],
    pub version: [c_char; HYMO_UNAME_LEN],
    pub machine: [c_char; HYMO_UNAME_LEN],
    pub domainname: [c_char; HYMO_UNAME_LEN],
    pub err: c_int,
}

impl Default for HymoSpoofUname {
    fn default() -> Self {
        Self {
            sysname: [0; HYMO_UNAME_LEN],
            nodename: [0; HYMO_UNAME_LEN],
            release: [0; HYMO_UNAME_LEN],
            version: [0; HYMO_UNAME_LEN],
            machine: [0; HYMO_UNAME_LEN],
            domainname: [0; HYMO_UNAME_LEN],
            err: 0,
        }
    }
}

impl HymoSpoofUname {
    pub fn new(release: &str, version: &str) -> Result<Self> {
        let mut value = Self::default();
        value.set_release(release)?;
        value.set_version(version)?;
        Ok(value)
    }

    pub fn set_sysname(&mut self, value: &str) -> Result<()> {
        write_str_into_c_buf(&mut self.sysname, value, "Kasumi uname sysname")
    }

    pub fn set_nodename(&mut self, value: &str) -> Result<()> {
        write_str_into_c_buf(&mut self.nodename, value, "Kasumi uname nodename")
    }

    pub fn set_release(&mut self, value: &str) -> Result<()> {
        write_str_into_c_buf(&mut self.release, value, "Kasumi uname release")
    }

    pub fn set_version(&mut self, value: &str) -> Result<()> {
        write_str_into_c_buf(&mut self.version, value, "Kasumi uname version")
    }

    pub fn set_machine(&mut self, value: &str) -> Result<()> {
        write_str_into_c_buf(&mut self.machine, value, "Kasumi uname machine")
    }

    pub fn set_domainname(&mut self, value: &str) -> Result<()> {
        write_str_into_c_buf(&mut self.domainname, value, "Kasumi uname domainname")
    }

    pub fn release(&self) -> String {
        read_c_buf(&self.release)
    }

    pub fn version(&self) -> String {
        read_c_buf(&self.version)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HymoSpoofCmdline {
    pub cmdline: [c_char; HYMO_FAKE_CMDLINE_SIZE],
    pub err: c_int,
}

impl Default for HymoSpoofCmdline {
    fn default() -> Self {
        Self {
            cmdline: [0; HYMO_FAKE_CMDLINE_SIZE],
            err: 0,
        }
    }
}

impl HymoSpoofCmdline {
    pub fn new(cmdline: &str) -> Result<Self> {
        let mut value = Self::default();
        value.set_cmdline(cmdline)?;
        Ok(value)
    }

    pub fn set_cmdline(&mut self, cmdline: &str) -> Result<()> {
        write_str_into_c_buf(&mut self.cmdline, cmdline, "Kasumi cmdline")
    }

    pub fn cmdline(&self) -> String {
        read_c_buf(&self.cmdline)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HymoMapsRule {
    pub target_ino: c_ulong,
    pub target_dev: c_ulong,
    pub spoofed_ino: c_ulong,
    pub spoofed_dev: c_ulong,
    pub spoofed_pathname: [c_char; HYMO_MAX_LEN_PATHNAME],
    pub err: c_int,
}

impl Default for HymoMapsRule {
    fn default() -> Self {
        Self {
            target_ino: 0,
            target_dev: 0,
            spoofed_ino: 0,
            spoofed_dev: 0,
            spoofed_pathname: [0; HYMO_MAX_LEN_PATHNAME],
            err: 0,
        }
    }
}

impl HymoMapsRule {
    pub fn new(
        target_ino: c_ulong,
        target_dev: c_ulong,
        spoofed_ino: c_ulong,
        spoofed_dev: c_ulong,
        spoofed_pathname: impl AsRef<Path>,
    ) -> Result<Self> {
        let mut value = Self {
            target_ino,
            target_dev,
            spoofed_ino,
            spoofed_dev,
            ..Self::default()
        };
        value.set_spoofed_pathname(spoofed_pathname)?;
        Ok(value)
    }

    pub fn set_spoofed_pathname(&mut self, spoofed_pathname: impl AsRef<Path>) -> Result<()> {
        write_path_into_c_buf(
            &mut self.spoofed_pathname,
            spoofed_pathname.as_ref(),
            "Kasumi maps spoofed pathname",
        )
    }

    pub fn spoofed_pathname(&self) -> String {
        read_c_buf(&self.spoofed_pathname)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HymoMountHideArg {
    pub enable: c_int,
    pub path_pattern: [c_char; HYMO_MAX_LEN_PATHNAME],
    pub err: c_int,
}

impl Default for HymoMountHideArg {
    fn default() -> Self {
        Self {
            enable: 0,
            path_pattern: [0; HYMO_MAX_LEN_PATHNAME],
            err: 0,
        }
    }
}

impl HymoMountHideArg {
    pub fn new(enable: bool, path_pattern: Option<&Path>) -> Result<Self> {
        let mut value = Self {
            enable: if enable { 1 } else { 0 },
            ..Self::default()
        };
        if let Some(path_pattern) = path_pattern {
            value.set_path_pattern(path_pattern)?;
        }
        Ok(value)
    }

    pub fn set_path_pattern(&mut self, path_pattern: impl AsRef<Path>) -> Result<()> {
        write_path_into_c_buf(
            &mut self.path_pattern,
            path_pattern.as_ref(),
            "Kasumi mount_hide path_pattern",
        )
    }

    pub fn path_pattern(&self) -> String {
        read_c_buf(&self.path_pattern)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HymoMapsSpoofArg {
    pub enable: c_int,
    pub reserved: [c_char; size_of::<HymoMapsRule>()],
    pub err: c_int,
}

impl Default for HymoMapsSpoofArg {
    fn default() -> Self {
        Self {
            enable: 0,
            reserved: [0; size_of::<HymoMapsRule>()],
            err: 0,
        }
    }
}

impl HymoMapsSpoofArg {
    pub fn new(enable: bool) -> Self {
        Self {
            enable: if enable { 1 } else { 0 },
            ..Self::default()
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HymoStatfsSpoofArg {
    pub enable: c_int,
    pub path: [c_char; HYMO_MAX_LEN_PATHNAME],
    pub spoof_f_type: c_ulong,
    pub err: c_int,
}

impl Default for HymoStatfsSpoofArg {
    fn default() -> Self {
        Self {
            enable: 0,
            path: [0; HYMO_MAX_LEN_PATHNAME],
            spoof_f_type: 0,
            err: 0,
        }
    }
}

impl HymoStatfsSpoofArg {
    pub fn new(enable: bool) -> Self {
        Self {
            enable: if enable { 1 } else { 0 },
            ..Self::default()
        }
    }

    pub fn with_path_and_f_type(
        enable: bool,
        path: impl AsRef<Path>,
        spoof_f_type: c_ulong,
    ) -> Result<Self> {
        let mut value = Self::new(enable);
        value.set_path(path)?;
        value.set_spoof_f_type(spoof_f_type);
        Ok(value)
    }

    pub fn set_path(&mut self, path: impl AsRef<Path>) -> Result<()> {
        write_path_into_c_buf(&mut self.path, path.as_ref(), "Kasumi statfs path")
    }

    pub fn set_spoof_f_type(&mut self, spoof_f_type: c_ulong) {
        self.spoof_f_type = spoof_f_type;
    }

    pub fn spoof_f_type(&self) -> c_ulong {
        self.spoof_f_type
    }

    pub fn path(&self) -> String {
        read_c_buf(&self.path)
    }
}

pub const HYMO_IOC_ADD_RULE: HymoIoctlRequest =
    ioctl::opcode::write::<HymoSyscallArg>(HYMO_IOC_MAGIC, 1);
pub const HYMO_IOC_DEL_RULE: HymoIoctlRequest =
    ioctl::opcode::write::<HymoSyscallArg>(HYMO_IOC_MAGIC, 2);
pub const HYMO_IOC_HIDE_RULE: HymoIoctlRequest =
    ioctl::opcode::write::<HymoSyscallArg>(HYMO_IOC_MAGIC, 3);
pub const HYMO_IOC_CLEAR_ALL: HymoIoctlRequest = ioctl::opcode::none(HYMO_IOC_MAGIC, 5);
pub const HYMO_IOC_GET_VERSION: HymoIoctlRequest = ioctl::opcode::read::<c_int>(HYMO_IOC_MAGIC, 6);
pub const HYMO_IOC_LIST_RULES: HymoIoctlRequest =
    ioctl::opcode::read_write::<HymoSyscallListArg>(HYMO_IOC_MAGIC, 7);
pub const HYMO_IOC_SET_DEBUG: HymoIoctlRequest = ioctl::opcode::write::<c_int>(HYMO_IOC_MAGIC, 8);
pub const HYMO_IOC_REORDER_MNT_ID: HymoIoctlRequest = ioctl::opcode::none(HYMO_IOC_MAGIC, 9);
pub const HYMO_IOC_SET_STEALTH: HymoIoctlRequest =
    ioctl::opcode::write::<c_int>(HYMO_IOC_MAGIC, 10);
pub const HYMO_IOC_HIDE_OVERLAY_XATTRS: HymoIoctlRequest =
    ioctl::opcode::write::<HymoSyscallArg>(HYMO_IOC_MAGIC, 11);
pub const HYMO_IOC_ADD_MERGE_RULE: HymoIoctlRequest =
    ioctl::opcode::write::<HymoSyscallArg>(HYMO_IOC_MAGIC, 12);
pub const HYMO_IOC_SET_MIRROR_PATH: HymoIoctlRequest =
    ioctl::opcode::write::<HymoSyscallArg>(HYMO_IOC_MAGIC, 14);
pub const HYMO_IOC_ADD_SPOOF_KSTAT: HymoIoctlRequest =
    ioctl::opcode::write::<HymoSpoofKstat>(HYMO_IOC_MAGIC, 15);
pub const HYMO_IOC_UPDATE_SPOOF_KSTAT: HymoIoctlRequest =
    ioctl::opcode::write::<HymoSpoofKstat>(HYMO_IOC_MAGIC, 16);
pub const HYMO_IOC_SET_UNAME: HymoIoctlRequest =
    ioctl::opcode::write::<HymoSpoofUname>(HYMO_IOC_MAGIC, 17);
pub const HYMO_IOC_SET_CMDLINE: HymoIoctlRequest =
    ioctl::opcode::write::<HymoSpoofCmdline>(HYMO_IOC_MAGIC, 18);
pub const HYMO_IOC_GET_FEATURES: HymoIoctlRequest =
    ioctl::opcode::read::<c_int>(HYMO_IOC_MAGIC, 19);
pub const HYMO_IOC_SET_ENABLED: HymoIoctlRequest =
    ioctl::opcode::write::<c_int>(HYMO_IOC_MAGIC, 20);
pub const HYMO_IOC_SET_HIDE_UIDS: HymoIoctlRequest =
    ioctl::opcode::write::<HymoUidListArg>(HYMO_IOC_MAGIC, 21);
pub const HYMO_IOC_GET_HOOKS: HymoIoctlRequest =
    ioctl::opcode::read_write::<HymoSyscallListArg>(HYMO_IOC_MAGIC, 22);
pub const HYMO_IOC_ADD_MAPS_RULE: HymoIoctlRequest =
    ioctl::opcode::write::<HymoMapsRule>(HYMO_IOC_MAGIC, 23);
pub const HYMO_IOC_CLEAR_MAPS_RULES: HymoIoctlRequest = ioctl::opcode::none(HYMO_IOC_MAGIC, 24);
pub const HYMO_IOC_SET_MOUNT_HIDE: HymoIoctlRequest =
    ioctl::opcode::write::<HymoMountHideArg>(HYMO_IOC_MAGIC, 25);
pub const HYMO_IOC_SET_MAPS_SPOOF: HymoIoctlRequest =
    ioctl::opcode::write::<HymoMapsSpoofArg>(HYMO_IOC_MAGIC, 26);
pub const HYMO_IOC_SET_STATFS_SPOOF: HymoIoctlRequest =
    ioctl::opcode::write::<HymoStatfsSpoofArg>(HYMO_IOC_MAGIC, 27);

struct HymoIoctlNoArg {
    request: HymoIoctlRequest,
}

impl HymoIoctlNoArg {
    const fn new(request: HymoIoctlRequest) -> Self {
        Self { request }
    }
}

unsafe impl Ioctl for HymoIoctlNoArg {
    type Output = ();

    const IS_MUTATING: bool = false;

    fn opcode(&self) -> Opcode {
        self.request
    }

    fn as_ptr(&mut self) -> *mut c_void {
        std::ptr::null_mut()
    }

    unsafe fn output_from_ptr(_: IoctlOutput, _: *mut c_void) -> rustix::io::Result<Self::Output> {
        Ok(())
    }
}

struct HymoIoctlArg<'a, T> {
    request: HymoIoctlRequest,
    arg: &'a mut T,
}

impl<'a, T> HymoIoctlArg<'a, T> {
    fn new(request: HymoIoctlRequest, arg: &'a mut T) -> Self {
        Self { request, arg }
    }
}

unsafe impl<T> Ioctl for HymoIoctlArg<'_, T> {
    type Output = ();

    const IS_MUTATING: bool = true;

    fn opcode(&self) -> Opcode {
        self.request
    }

    fn as_ptr(&mut self) -> *mut c_void {
        (self.arg as *mut T).cast()
    }

    unsafe fn output_from_ptr(_: IoctlOutput, _: *mut c_void) -> rustix::io::Result<Self::Output> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KasumiStatus {
    Available,
    #[default]
    NotPresent,
    KernelTooOld,
    ModuleTooOld,
}

pub fn status_name(status: KasumiStatus) -> &'static str {
    match status {
        KasumiStatus::Available => "available",
        KasumiStatus::NotPresent => "not_present",
        KasumiStatus::KernelTooOld => "kernel_too_old",
        KasumiStatus::ModuleTooOld => "module_too_old",
    }
}

pub fn feature_names(bits: c_int) -> Vec<String> {
    let mut names = Vec::new();

    if bits & HYMO_FEATURE_KSTAT_SPOOF != 0 {
        names.push("kstat_spoof".to_string());
    }
    if bits & HYMO_FEATURE_UNAME_SPOOF != 0 {
        names.push("uname_spoof".to_string());
    }
    if bits & HYMO_FEATURE_CMDLINE_SPOOF != 0 {
        names.push("cmdline_spoof".to_string());
    }
    if bits & HYMO_FEATURE_SELINUX_BYPASS != 0 {
        names.push("selinux_bypass".to_string());
    }
    if bits & HYMO_FEATURE_MERGE_DIR != 0 {
        names.push("merge_dir".to_string());
    }
    if bits & HYMO_FEATURE_MOUNT_HIDE != 0 {
        names.push("mount_hide".to_string());
    }
    if bits & HYMO_FEATURE_MAPS_SPOOF != 0 {
        names.push("maps_spoof".to_string());
    }
    if bits & HYMO_FEATURE_STATFS_SPOOF != 0 {
        names.push("statfs_spoof".to_string());
    }

    names
}

#[derive(Debug, Default)]
struct StatusCache {
    checked: bool,
    status: KasumiStatus,
}

static STATUS_CACHE: LazyLock<Mutex<StatusCache>> =
    LazyLock::new(|| Mutex::new(StatusCache::default()));
static FD_CACHE: LazyLock<Mutex<Option<c_int>>> = LazyLock::new(|| Mutex::new(None));

fn cstring_from_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains interior NUL byte: {}", path.display()))
}

fn lock_error(name: &str) -> anyhow::Error {
    anyhow!("failed to lock Kasumi {name} mutex")
}

fn read_c_buf(buf: &[c_char]) -> String {
    let len = buf.iter().position(|ch| *ch == 0).unwrap_or(buf.len());
    let bytes: Vec<u8> = buf[..len].iter().map(|ch| *ch as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn write_bytes_into_c_buf(buf: &mut [c_char], bytes: &[u8], field_name: &str) -> Result<()> {
    if bytes.len() >= buf.len() {
        bail!("{field_name} exceeds {} bytes", buf.len() - 1);
    }

    buf.fill(0);
    for (dst, src) in buf.iter_mut().zip(bytes.iter().copied()) {
        *dst = src as c_char;
    }

    Ok(())
}

fn write_str_into_c_buf(buf: &mut [c_char], value: &str, field_name: &str) -> Result<()> {
    write_bytes_into_c_buf(buf, value.as_bytes(), field_name)
}

fn write_path_into_c_buf(buf: &mut [c_char], path: &Path, field_name: &str) -> Result<()> {
    write_bytes_into_c_buf(buf, path.as_os_str().as_bytes(), field_name)
}

fn module_loaded() -> bool {
    let Ok(content) = fs::read_to_string("/proc/modules") else {
        return false;
    };

    content.lines().any(|line| {
        line.starts_with("kasumi_lkm ")
            || line.starts_with("kasumi_lkm\t")
            || line.starts_with("kasumi ")
            || line.starts_with("kasumi\t")
            || line.starts_with("hymofs_lkm ")
            || line.starts_with("hymofs_lkm\t")
            || line.starts_with("hymofs ")
            || line.starts_with("hymofs\t")
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn fetch_anon_fd() -> Result<c_int> {
    {
        let cache = FD_CACHE.lock().map_err(|_| lock_error("fd"))?;
        if let Some(fd) = *cache {
            crate::scoped_log!(debug, "kasumi:fd", "complete: source=cache, fd={}", fd);
            return Ok(fd);
        }
    }

    crate::scoped_log!(debug, "kasumi:fd", "start: source=kernel_query");

    let mut fd = -1;
    const WAIT_ATTEMPTS: usize = 4;
    const SHORT_RETRIES: usize = 2;

    for wait_round in 0..WAIT_ATTEMPTS {
        if wait_round > 0 {
            thread::sleep(Duration::from_secs(1));
        }

        unsafe {
            libc::prctl(
                HYMO_PRCTL_GET_FD,
                &mut fd as *mut c_int as libc::c_ulong,
                0,
                0,
                0,
            );
        }

        if fd >= 0 {
            crate::scoped_log!(
                debug,
                "kasumi:fd",
                "complete: source=prctl, round={}",
                wait_round
            );
            break;
        }

        for retry in 0..SHORT_RETRIES {
            if retry > 0 {
                thread::sleep(Duration::from_millis(80));
            }
            unsafe {
                libc::syscall(
                    HYMO_SYSCALL_NR,
                    HYMO_MAGIC1 as libc::c_long,
                    HYMO_MAGIC2 as libc::c_long,
                    HYMO_CMD_GET_FD as libc::c_long,
                    &mut fd as *mut c_int,
                );
            }

            if fd >= 0 {
                crate::scoped_log!(
                    debug,
                    "kasumi:fd",
                    "complete: source=syscall, round={}, retry={}",
                    wait_round,
                    retry
                );
                break;
            }
        }

        if fd >= 0 {
            break;
        }
    }

    if fd < 0 {
        crate::scoped_log!(
            warn,
            "kasumi:fd",
            "failed: reason=obtain_fd_failed, attempts={}, short_retries={}",
            WAIT_ATTEMPTS,
            SHORT_RETRIES
        );
        bail!("failed to obtain Kasumi anonymous fd");
    }

    let mut cache = FD_CACHE.lock().map_err(|_| lock_error("fd"))?;
    *cache = Some(fd);
    Ok(fd)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn fetch_anon_fd() -> Result<c_int> {
    bail!("Kasumi is only supported on linux/android")
}

fn ioctl_error_context(name: &str, request: HymoIoctlRequest, err: Errno) -> String {
    let hint = match err.raw_os_error() {
        libc::EINVAL => "invalid payload or protocol mismatch",
        libc::EOPNOTSUPP | libc::ENOTTY => "unsupported by the current kernel/module build",
        _ => "kernel call failed",
    };

    format!(
        "Kasumi ioctl failed: name={name}, opcode=0x{:x}, errno={} ({hint})",
        request,
        err.raw_os_error()
    )
}

fn ioctl_noarg(name: &str, request: HymoIoctlRequest) -> Result<()> {
    crate::scoped_log!(
        debug,
        "kasumi:ioctl",
        "start: name={}, opcode=0x{:x}, has_arg=false",
        name,
        request
    );
    let fd = unsafe { BorrowedFd::borrow_raw(fetch_anon_fd()?) };
    let ioctl = HymoIoctlNoArg::new(request);
    match unsafe { ioctl::ioctl(fd, ioctl) } {
        Ok(()) => {
            crate::scoped_log!(
                debug,
                "kasumi:ioctl",
                "complete: name={}, opcode=0x{:x}",
                name,
                request
            );
            Ok(())
        }
        Err(err) => {
            let context = ioctl_error_context(name, request, err);
            crate::scoped_log!(
                error,
                "kasumi:ioctl",
                "failed: name={}, opcode=0x{:x}, errno={}",
                name,
                request,
                err.raw_os_error()
            );
            Err(anyhow::Error::new(err).context(context))
        }
    }
}

fn ioctl_with_arg<T>(name: &str, request: HymoIoctlRequest, arg: &mut T) -> Result<()> {
    crate::scoped_log!(
        debug,
        "kasumi:ioctl",
        "start: name={}, opcode=0x{:x}, has_arg=true",
        name,
        request
    );
    let fd = unsafe { BorrowedFd::borrow_raw(fetch_anon_fd()?) };
    let ioctl = HymoIoctlArg::new(request, arg);
    match unsafe { ioctl::ioctl(fd, ioctl) } {
        Ok(()) => {
            crate::scoped_log!(
                debug,
                "kasumi:ioctl",
                "complete: name={}, opcode=0x{:x}",
                name,
                request
            );
            Ok(())
        }
        Err(err) => {
            let context = ioctl_error_context(name, request, err);
            crate::scoped_log!(
                error,
                "kasumi:ioctl",
                "failed: name={}, opcode=0x{:x}, errno={}",
                name,
                request,
                err.raw_os_error()
            );
            Err(anyhow::Error::new(err).context(context))
        }
    }
}

fn ioctl_with_bool(name: &str, request: HymoIoctlRequest, value: bool) -> Result<()> {
    let mut raw: c_int = if value { 1 } else { 0 };
    ioctl_with_arg(name, request, &mut raw)
}

fn ensure_kernel_err(context: &str, kernel_err: c_int) -> Result<()> {
    if kernel_err != 0 {
        bail!("{context} kernel err={kernel_err}");
    }
    Ok(())
}

fn list_ioctl(request: HymoIoctlRequest, capacity: usize, description: &str) -> Result<String> {
    crate::scoped_log!(
        debug,
        "kasumi:list_ioctl",
        "start: description={}, opcode=0x{:x}, capacity={}",
        description,
        request,
        capacity
    );
    let mut buf = vec![0u8; capacity];
    let mut arg = HymoSyscallListArg {
        buf: buf.as_mut_ptr() as *mut c_char,
        size: buf.len(),
    };
    ioctl_with_arg(description, request, &mut arg)
        .with_context(|| format!("failed to query Kasumi {description}"))?;

    let len = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    let output = String::from_utf8_lossy(&buf[..len]).into_owned();
    crate::scoped_log!(
        debug,
        "kasumi:list_ioctl",
        "complete: description={}, bytes={}",
        description,
        len
    );
    Ok(output)
}

pub fn get_protocol_version() -> Result<c_int> {
    let mut version = 0;
    ioctl_with_arg("get_version", HYMO_IOC_GET_VERSION, &mut version)?;
    Ok(version)
}

pub fn check_status() -> KasumiStatus {
    if let Ok(cache) = STATUS_CACHE.lock()
        && cache.checked
    {
        crate::scoped_log!(
            debug,
            "kasumi:status",
            "complete: source=cache, status={}",
            status_name(cache.status)
        );
        return cache.status;
    }

    let status = if !module_loaded() {
        KasumiStatus::NotPresent
    } else {
        match get_protocol_version() {
            Ok(version) if version < HYMO_PROTOCOL_VERSION => KasumiStatus::KernelTooOld,
            Ok(version) if version > HYMO_PROTOCOL_VERSION => KasumiStatus::ModuleTooOld,
            Ok(_) => KasumiStatus::Available,
            Err(_) => KasumiStatus::NotPresent,
        }
    };

    if let Ok(mut cache) = STATUS_CACHE.lock() {
        cache.checked = true;
        cache.status = status;
    }

    crate::scoped_log!(
        debug,
        "kasumi:status",
        "complete: source=probe, status={}",
        status_name(status)
    );

    status
}

pub fn can_operate() -> bool {
    let operable = matches!(check_status(), KasumiStatus::Available);
    crate::scoped_log!(debug, "kasumi:status", "complete: can_operate={}", operable);
    operable
}

pub fn clear_rules() -> Result<()> {
    ioctl_noarg("clear_rules", HYMO_IOC_CLEAR_ALL)
}

pub fn add_rule(virtual_path: &Path, backing_path: &Path, file_type: c_int) -> Result<()> {
    let src = cstring_from_path(virtual_path)?;
    let target = cstring_from_path(backing_path)?;
    let mut arg = HymoSyscallArg::new(&src, Some(&target), file_type);
    ioctl_with_arg("add_rule", HYMO_IOC_ADD_RULE, &mut arg)
}

pub fn add_merge_rule(virtual_path: &Path, backing_path: &Path) -> Result<()> {
    let src = cstring_from_path(virtual_path)?;
    let target = cstring_from_path(backing_path)?;
    let mut arg = HymoSyscallArg::new(&src, Some(&target), 0);
    ioctl_with_arg("add_merge_rule", HYMO_IOC_ADD_MERGE_RULE, &mut arg)
}

pub fn delete_rule(virtual_path: &Path) -> Result<()> {
    let src = cstring_from_path(virtual_path)?;
    let mut arg = HymoSyscallArg::new(&src, None, 0);
    ioctl_with_arg("delete_rule", HYMO_IOC_DEL_RULE, &mut arg)
}

pub fn hide_path(virtual_path: &Path) -> Result<()> {
    let src = cstring_from_path(virtual_path)?;
    let mut arg = HymoSyscallArg::new(&src, None, 0);
    ioctl_with_arg("hide_path", HYMO_IOC_HIDE_RULE, &mut arg)
}

fn helper_rule_dtype(path: &Path) -> Result<Option<c_int>> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to read Kasumi helper metadata for {}",
            path.display()
        )
    })?;
    let file_type = metadata.file_type();

    if file_type.is_file() {
        Ok(Some(libc::DT_REG as c_int))
    } else if file_type.is_symlink() {
        Ok(Some(libc::DT_LNK as c_int))
    } else if file_type.is_char_device() && metadata.rdev() == 0 {
        Ok(None)
    } else {
        bail!(
            "unsupported helper entry type for {} (expected regular file, symlink, or whiteout)",
            path.display()
        );
    }
}

pub fn list_rules() -> Result<String> {
    list_rules_with_capacity(16 * 1024)
}

pub fn get_active_rules() -> Result<String> {
    list_rules()
}

pub fn list_rules_with_capacity(capacity: usize) -> Result<String> {
    list_ioctl(HYMO_IOC_LIST_RULES, capacity, "rule list")
}

pub fn add_rules_from_directory(target_base: &Path, module_dir: &Path) -> Result<()> {
    if !module_dir.exists() || !module_dir.is_dir() {
        bail!(
            "Kasumi helper source is not a directory: {}",
            module_dir.display()
        );
    }

    for entry_result in WalkDir::new(module_dir).follow_links(false) {
        let entry = entry_result.with_context(|| {
            format!(
                "failed to walk Kasumi helper directory {}",
                module_dir.display()
            )
        })?;

        if entry.depth() == 0 || entry.file_type().is_dir() {
            continue;
        }

        let path = entry.path();
        let relative = path.strip_prefix(module_dir).with_context(|| {
            format!(
                "failed to compute relative path for Kasumi helper entry {}",
                path.display()
            )
        })?;
        let target_path = target_base.join(relative);

        match helper_rule_dtype(path)? {
            Some(file_type) => add_rule(&target_path, path, file_type)?,
            None => hide_path(&target_path)?,
        }
    }

    Ok(())
}

pub fn remove_rules_from_directory(target_base: &Path, module_dir: &Path) -> Result<()> {
    if !module_dir.exists() || !module_dir.is_dir() {
        bail!(
            "Kasumi helper source is not a directory: {}",
            module_dir.display()
        );
    }

    for entry_result in WalkDir::new(module_dir).follow_links(false) {
        let entry = entry_result.with_context(|| {
            format!(
                "failed to walk Kasumi helper directory {}",
                module_dir.display()
            )
        })?;

        if entry.depth() == 0 || entry.file_type().is_dir() {
            continue;
        }

        let path = entry.path();
        let relative = path.strip_prefix(module_dir).with_context(|| {
            format!(
                "failed to compute relative path for Kasumi helper entry {}",
                path.display()
            )
        })?;
        let target_path = target_base.join(relative);

        match helper_rule_dtype(path)? {
            Some(_) | None => delete_rule(&target_path)?,
        }
    }

    Ok(())
}

pub fn set_mirror_path(path: &Path) -> Result<()> {
    let src = cstring_from_path(path)?;
    let mut arg = HymoSyscallArg::new(&src, None, 0);
    ioctl_with_arg("set_mirror_path", HYMO_IOC_SET_MIRROR_PATH, &mut arg)
}

pub fn set_debug(enable: bool) -> Result<()> {
    ioctl_with_bool("set_debug", HYMO_IOC_SET_DEBUG, enable)
}

pub fn set_stealth(enable: bool) -> Result<()> {
    ioctl_with_bool("set_stealth", HYMO_IOC_SET_STEALTH, enable)
}

pub fn set_enabled(enable: bool) -> Result<()> {
    ioctl_with_bool("set_enabled", HYMO_IOC_SET_ENABLED, enable)
}

pub fn add_spoof_kstat(rule: &HymoSpoofKstat) -> Result<()> {
    let mut rule = *rule;
    ioctl_with_arg("add_spoof_kstat", HYMO_IOC_ADD_SPOOF_KSTAT, &mut rule)?;
    ensure_kernel_err("Kasumi add_spoof_kstat", rule.err)
}

pub fn update_spoof_kstat(rule: &HymoSpoofKstat) -> Result<()> {
    let mut rule = *rule;
    ioctl_with_arg("update_spoof_kstat", HYMO_IOC_UPDATE_SPOOF_KSTAT, &mut rule)?;
    ensure_kernel_err("Kasumi update_spoof_kstat", rule.err)
}

pub fn set_uname(uname: &HymoSpoofUname) -> Result<()> {
    let mut uname = *uname;
    ioctl_with_arg("set_uname", HYMO_IOC_SET_UNAME, &mut uname)?;
    ensure_kernel_err("Kasumi set_uname", uname.err)
}

pub fn set_cmdline(cmdline: &HymoSpoofCmdline) -> Result<()> {
    let mut cmdline = *cmdline;
    let fd = unsafe { BorrowedFd::borrow_raw(fetch_anon_fd()?) };
    let ioctl = HymoIoctlArg::new(HYMO_IOC_SET_CMDLINE, &mut cmdline);
    if let Err(err) = unsafe { ioctl::ioctl(fd, ioctl) } {
        let context = ioctl_error_context("set_cmdline", HYMO_IOC_SET_CMDLINE, err);
        return Err(anyhow::Error::new(err).context(context));
    }
    ensure_kernel_err("Kasumi set_cmdline", cmdline.err)
}

pub fn set_cmdline_str(cmdline: &str) -> Result<()> {
    let cmdline = HymoSpoofCmdline::new(cmdline)?;
    set_cmdline(&cmdline)
}

pub fn set_hide_uids(uids: &[u32]) -> Result<()> {
    let mut arg = HymoUidListArg::from_slice(uids);
    ioctl_with_arg("set_hide_uids", HYMO_IOC_SET_HIDE_UIDS, &mut arg)
}

pub fn fix_mounts() -> Result<()> {
    ioctl_noarg("fix_mounts", HYMO_IOC_REORDER_MNT_ID)
}

pub fn hide_overlay_xattrs(path: &Path) -> Result<()> {
    let src = cstring_from_path(path)?;
    let mut arg = HymoSyscallArg::new(&src, None, 0);
    ioctl_with_arg(
        "hide_overlay_xattrs",
        HYMO_IOC_HIDE_OVERLAY_XATTRS,
        &mut arg,
    )
}

pub fn get_features() -> Result<c_int> {
    let mut features = 0;
    ioctl_with_arg("get_features", HYMO_IOC_GET_FEATURES, &mut features)?;
    Ok(features)
}

pub fn get_hooks() -> Result<String> {
    get_hooks_with_capacity(4 * 1024)
}

pub fn get_hooks_with_capacity(capacity: usize) -> Result<String> {
    list_ioctl(HYMO_IOC_GET_HOOKS, capacity, "hook list")
}

pub fn add_maps_rule(rule: &HymoMapsRule) -> Result<()> {
    let mut rule = *rule;
    ioctl_with_arg("add_maps_rule", HYMO_IOC_ADD_MAPS_RULE, &mut rule)?;
    ensure_kernel_err("Kasumi add_maps_rule", rule.err)
}

pub fn clear_maps_rules() -> Result<()> {
    ioctl_noarg("clear_maps_rules", HYMO_IOC_CLEAR_MAPS_RULES)
}

pub fn set_mount_hide(enable: bool) -> Result<()> {
    let config = HymoMountHideArg::new(enable, None)?;
    set_mount_hide_config(&config)
}

pub fn set_mount_hide_config(config: &HymoMountHideArg) -> Result<()> {
    let mut config = *config;
    ioctl_with_arg("set_mount_hide", HYMO_IOC_SET_MOUNT_HIDE, &mut config)?;
    ensure_kernel_err("Kasumi mount_hide", config.err)
}

pub fn set_maps_spoof(enable: bool) -> Result<()> {
    let config = HymoMapsSpoofArg::new(enable);
    set_maps_spoof_config(&config)
}

pub fn set_maps_spoof_config(config: &HymoMapsSpoofArg) -> Result<()> {
    let mut config = *config;
    ioctl_with_arg("set_maps_spoof", HYMO_IOC_SET_MAPS_SPOOF, &mut config)?;
    ensure_kernel_err("Kasumi maps_spoof", config.err)
}

pub fn set_statfs_spoof(enable: bool) -> Result<()> {
    let config = HymoStatfsSpoofArg::new(enable);
    set_statfs_spoof_config(&config)
}

pub fn set_statfs_spoof_config(config: &HymoStatfsSpoofArg) -> Result<()> {
    let mut config = *config;
    ioctl_with_arg("set_statfs_spoof", HYMO_IOC_SET_STATFS_SPOOF, &mut config)?;
    ensure_kernel_err("Kasumi statfs_spoof", config.err)
}

pub fn release_connection() {
    if let Ok(mut cache) = FD_CACHE.lock()
        && let Some(fd) = cache.take()
    {
        unsafe {
            libc::close(fd);
        }
    }
    invalidate_status_cache();
}

pub fn invalidate_status_cache() {
    if let Ok(mut cache) = STATUS_CACHE.lock() {
        cache.checked = false;
        cache.status = KasumiStatus::NotPresent;
    }
}
