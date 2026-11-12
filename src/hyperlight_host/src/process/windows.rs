// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Windows confinement resources, allocated before process creation.
//!
//! AppContainer is the default authority boundary. An explicitly authorized
//! Windows VM host has no AppContainer filesystem or network boundary.
//! Job limits account committed virtual
//! memory, not resident memory. A Windows CPU rate has an OS-selected interval,
//! so it cannot implement the public quota/period contract.
//! Runtime image paths map beneath the private image working directory. Windows
//! drive roots are not remapped and OS AppContainer-readable resources remain
//! governed by the Windows AppContainer policy.
//!
//! API contracts:
//! * <https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute>
//! * <https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-createappcontainerprofile>
//! * <https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-deleteappcontainerprofile>
//! * <https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation>
//! * <https://learn.microsoft.com/windows/win32/api/winnt/ne-winnt-token_information_class>
//! * <https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information>
//! * <https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information>

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use mesh_process::{ProcessConfig, SandboxProfile};
use pal::windows::process::{Builder as ProcessBuilder, ChildProcessPolicy, Stdio};
use pal::windows::security::Sid;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_NO_MORE_ITEMS, ERROR_SHARING_VIOLATION,
    ERROR_SUCCESS, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, FreeSid, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectCpuRateControlInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ, REG_SZ, RegCloseKey, RegEnumValueW,
    RegOpenKeyExW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_Windows, SHGetKnownFolderPath,
};

use super::launch::{
    ControlOutcome, ControlResult, PreparedProcess, ProcessGuard, WindowsProcessPolicyReport,
};
use super::program::{ProcessDefinition, ProcessTopologyDefinition, ProgramRole, ValidatedProgram};
use super::{ProcessControl, ProcessProfile, WindowsSandboxHostPolicy};
use crate::{Result, new_error};

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn known_folder(id: &windows_sys::core::GUID) -> io::Result<PathBuf> {
    let mut text = null_mut();
    // SAFETY: id is a live GUID. A null token requests the current user's folder.
    let result = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut text) };
    let path = if result >= 0 && !text.is_null() {
        let mut length = 0;
        // SAFETY: success returns a null-terminated, CoTaskMemFree-owned UTF-16 path.
        unsafe {
            while *text.add(length) != 0 {
                length += 1;
            }
            Ok(PathBuf::from(OsString::from_wide(
                std::slice::from_raw_parts(text, length),
            )))
        }
    } else {
        Err(io::Error::other(format!(
            "Known-folder lookup failed: HRESULT {result:#010x}"
        )))
    };
    // SAFETY: the API requires CoTaskMemFree even on failure. Null is permitted.
    unsafe { CoTaskMemFree(text.cast()) };
    let path = path?;
    if !path.is_absolute() || !path.is_dir() {
        return Err(io::Error::other(
            "Known folder is not an existing absolute directory",
        ));
    }
    Ok(path)
}

fn checked(success: i32) -> io::Result<()> {
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Owns the allocation returned by LocalAlloc-based security APIs.
struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: This allocation was returned by an API requiring LocalFree.
        unsafe { LocalFree(self.0) };
    }
}

fn sid_string(sid: *mut c_void) -> io::Result<String> {
    let mut text = null_mut();
    // SAFETY: Callers supply a live SID. The returned string is LocalFree-owned.
    checked(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
    let _allocation = LocalAllocation(text.cast());
    let mut length = 0;
    // SAFETY: ConvertSidToStringSidW returns a null-terminated UTF-16 string.
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
        Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
            text, length,
        )))
    }
}

fn current_user_sid() -> io::Result<String> {
    let mut token = null_mut();
    // SAFETY: Valid pseudo process handle and writable output pointer.
    checked(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
    // SAFETY: OpenProcessToken transferred ownership of this handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut length = 0;
    // SAFETY: The zero-size probe writes only the required buffer length.
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut length) };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }

    // usize alignment suffices for TOKEN_USER and the trailing SID.
    let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    // SAFETY: The buffer has the required size and alignment.
    checked(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    })?;
    // SAFETY: Successful TokenUser query initializes TOKEN_USER and its SID.
    sid_string(unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}

fn current_process_is_elevated() -> io::Result<bool> {
    let mut token = null_mut();
    // SAFETY: Valid pseudo process handle and writable output pointer.
    checked(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
    // SAFETY: OpenProcessToken transferred ownership of this handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = size_of_val(&elevation) as u32;
    // SAFETY: The output buffer matches TOKEN_ELEVATION.
    checked(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            length,
            &mut length,
        )
    })?;
    Ok(elevation.TokenIsElevated != 0)
}

/// One logical process owns this identity across its nonoverlapping generations.
struct AppContainer {
    name: String,
    sid: String,
    removed: AtomicBool,
    retained: AtomicBool,
    #[cfg(test)]
    previous_job: Mutex<Option<ConfinementJob>>,
}

impl AppContainer {
    fn new() -> io::Result<Self> {
        let name = format!("Hyperlight.{:032x}", rand::random::<u128>());
        let wide_name = wide(&name);
        let mut sid = null_mut();
        // SAFETY: Input strings persist through the call. No capabilities are
        // requested. The returned SID must be released with FreeSid.
        let result = unsafe {
            CreateAppContainerProfile(
                wide_name.as_ptr(),
                wide_name.as_ptr(),
                wide_name.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        if result < 0 {
            return Err(io::Error::other(format!(
                "CreateAppContainerProfile({name}): HRESULT {result:#010x}"
            )));
        }
        let converted = sid_string(sid);
        // SAFETY: CreateAppContainerProfile returned this owned SID.
        unsafe { FreeSid(sid) };
        match converted {
            Ok(sid) => Ok(Self {
                name,
                sid,
                removed: AtomicBool::new(false),
                retained: AtomicBool::new(false),
                #[cfg(test)]
                previous_job: Mutex::new(None),
            }),
            Err(error) => {
                // SAFETY: Only the successfully created task-owned profile is deleted.
                unsafe { DeleteAppContainerProfile(wide_name.as_ptr()) };
                Err(error)
            }
        }
    }

    fn remove(&self) -> io::Result<()> {
        if self.removed.load(Ordering::Acquire) {
            return Ok(());
        }
        // SAFETY: This exact unique profile was created by this owner.
        let result = unsafe { DeleteAppContainerProfile(wide(&self.name).as_ptr()) };
        if result < 0 {
            return Err(io::Error::other(format!(
                "DeleteAppContainerProfile({}): HRESULT {result:#010x}",
                self.name
            )));
        }
        self.removed.store(true, Ordering::Release);
        Ok(())
    }

    fn pal_sid(&self) -> io::Result<Sid<[u32; 8]>> {
        let parts = self
            .sid
            .strip_prefix("S-1-15-")
            .ok_or_else(|| io::Error::other("Unexpected AppContainer SID authority"))?;
        let values = parts
            .split('-')
            .map(|value| {
                value
                    .parse::<u32>()
                    .map_err(|_| io::Error::other("Invalid AppContainer SID"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let values: [u32; 8] = values
            .try_into()
            .map_err(|_| io::Error::other("Unexpected AppContainer SID length"))?;
        if values[0] != 2 {
            return Err(io::Error::other("Unexpected AppContainer SID type"));
        }
        Ok(Sid::new([0, 0, 0, 0, 0, 15], values))
    }
}

impl Drop for AppContainer {
    fn drop(&mut self) {
        if self.retained.load(Ordering::Acquire) && !self.removed.load(Ordering::Acquire) {
            tracing::error!(name = %self.name, sid = %self.sid, "Retaining AppContainer after unconfirmed cleanup");
            return;
        }
        if let Err(error) = self.remove() {
            tracing::error!(%error, "Task-owned AppContainer profile cleanup failed");
        }
    }
}

pub(super) struct WindowsPrincipals {
    sandbox: Option<(String, Option<Arc<AppContainer>>)>,
    workers: BTreeMap<String, Option<Arc<AppContainer>>>,
}

impl WindowsPrincipals {
    pub(super) fn new(
        topology: &ProcessTopologyDefinition,
        authorized_workers: &std::collections::BTreeSet<String>,
    ) -> Result<Self> {
        topology.validate()?;
        let sandbox = topology
            .sandbox()
            .map(|definition| {
                let principal = match definition.windows_sandbox_host_policy() {
                    WindowsSandboxHostPolicy::AppContainer => Some(Arc::new(AppContainer::new()?)),
                    WindowsSandboxHostPolicy::WindowsVmHost => None,
                };
                Ok::<_, io::Error>((definition.name().to_owned(), principal))
            })
            .transpose()?;
        let workers = topology
            .workers()
            .iter()
            .map(|definition| {
                let principal = if authorized_workers.contains(definition.name()) {
                    None
                } else {
                    Some(Arc::new(AppContainer::new()?))
                };
                Ok((definition.name().to_owned(), principal))
            })
            .collect::<io::Result<_>>()?;
        Ok(Self { sandbox, workers })
    }

    fn principal(&self, role: ProgramRole, name: &str) -> Result<Option<Arc<AppContainer>>> {
        let principal = match role {
            ProgramRole::SandboxHost => self
                .sandbox
                .as_ref()
                .filter(|(expected, _)| expected == name)
                .map(|(_, principal)| principal.clone()),
            ProgramRole::FunctionWorker => self.workers.get(name).cloned(),
        };
        principal.ok_or_else(|| new_error!("No Windows principal for {role:?} '{name}'"))
    }

    fn peers(&self, role: ProgramRole) -> Vec<&AppContainer> {
        match role {
            ProgramRole::SandboxHost => {
                self.workers.values().filter_map(Option::as_deref).collect()
            }
            ProgramRole::FunctionWorker => self
                .sandbox
                .iter()
                .filter_map(|(_, principal)| principal.as_deref())
                .collect(),
        }
    }
}

/// Host owner and SYSTEM manage files. A confined process gets read/execute access.
/// No ACL is changed outside the new task-owned staging directory.
fn protect_directory(path: &Path, user_sid: &str, container_sid: Option<&str>) -> io::Result<()> {
    let mut sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user_sid})");
    if let Some(sid) = container_sid {
        sddl.push_str(&format!("(A;OICI;GRGX;;;{sid})"));
    }
    let sddl = wide(sddl);
    let mut descriptor = null_mut();
    // SAFETY: SDDL is null-terminated. Revision 1 is SDDL_REVISION_1.
    checked(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    })?;
    let _allocation = LocalAllocation(descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = null_mut();
    // SAFETY: Descriptor remains live through ACL extraction and application.
    checked(unsafe {
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted)
    })?;
    if present == 0 || acl.is_null() {
        return Err(io::Error::other("Missing protected staging DACL"));
    }
    // SAFETY: The path and descriptor remain live. Only this new directory is changed.
    let error = unsafe {
        SetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    Ok(())
}

fn runtime_path(image_path: &str) -> io::Result<PathBuf> {
    if !image_path.starts_with('/') {
        return Err(io::Error::other("Runtime path must be image-absolute"));
    }
    let mut relative = PathBuf::new();
    for component in image_path[1..].split('/') {
        let stem = component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        if component.is_empty()
            || !component.is_ascii()
            || component == "."
            || component == ".."
            || component.ends_with(['.', ' '])
            || component.contains(['\\', ':', '<', '>', '"', '|', '?', '*'])
            || component.contains('~')
            || component.chars().any(char::is_control)
            || matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            || stem
                .strip_prefix("COM")
                .or_else(|| stem.strip_prefix("LPT"))
                .is_some_and(|n| {
                    matches!(
                        n,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
        {
            return Err(io::Error::other("Unsafe Windows runtime image path"));
        }
        relative.push(component);
    }
    Ok(relative)
}

pub(super) fn capture_adjacent_dependencies(
    executable: &[u8],
    source_directory: Option<&Path>,
) -> Result<Vec<super::program::ProgramFile>> {
    let source_directory = source_directory.ok_or_else(|| {
        new_error!("Native program path has no parent directory for DLL discovery")
    })?;
    let mut pending = VecDeque::from([(executable.to_vec(), true)]);
    let mut visited = BTreeSet::new();
    let mut files = Vec::new();
    let mut total = executable.len() as u64;
    while let Some((image, is_root)) = pending.pop_front() {
        let pe = goblin::pe::PE::parse(&image)
            .map_err(|error| new_error!("Invalid Windows native program: {error}"))?;
        validate_pe_role(&pe, is_root)?;
        for library in pe.libraries {
            if Path::new(library).file_name() != Some(OsStr::new(library)) {
                return Err(new_error!(
                    "Windows native program import '{library}' is not a DLL basename"
                ));
            }
            let key = library.to_ascii_lowercase();
            if !visited.insert(key.clone()) {
                continue;
            }
            if visited.len() > 128 {
                return Err(new_error!(
                    "Windows native program dependency closure exceeds 128 DLLs"
                ));
            }
            if is_windows_forced_system_library(library)? {
                continue;
            }
            let adjacent = source_directory.join(library);
            if adjacent.is_file() {
                let captured = super::provider::capture_file(&adjacent)?;
                total = total
                    .checked_add(captured.bytes.len() as u64)
                    .filter(|total| *total <= super::provider::MAX_PROGRAM_BYTES)
                    .ok_or_else(|| {
                        new_error!("Windows native program dependency closure exceeds 256 MiB")
                    })?;
                pending.push_back((captured.bytes.clone(), false));
                files.push(super::program::ProgramFile::new(
                    format!("/{library}"),
                    captured.bytes,
                )?);
                continue;
            }
            if is_windows_system_fallback(library) {
                continue;
            }
        }
    }
    Ok(files)
}

pub(super) fn runtime_closure(
    executable: &[u8],
    runtime_files: &[super::program::ProgramFile],
) -> Result<Vec<super::program::ProgramFile>> {
    runtime_closure_with_limits(
        executable,
        runtime_files,
        128,
        super::provider::MAX_PROGRAM_BYTES,
    )
}

pub(super) fn runtime_closure_with_limits(
    executable: &[u8],
    runtime_files: &[super::program::ProgramFile],
    max_files: usize,
    max_bytes: u64,
) -> Result<Vec<super::program::ProgramFile>> {
    if runtime_files.len() > max_files {
        return Err(new_error!(
            "Windows native program dependency closure exceeds 128 DLLs"
        ));
    }
    let mut total = executable.len() as u64;
    let mut available = BTreeMap::new();
    for file in runtime_files {
        total = total
            .checked_add(file.bytes().len() as u64)
            .filter(|total| *total <= max_bytes)
            .ok_or_else(|| {
                new_error!("Windows native program dependency closure exceeds 256 MiB")
            })?;
        let path = file.image_path();
        if let Some(name) = path.strip_prefix('/').filter(|path| !path.contains('/')) {
            available.insert(name.to_ascii_lowercase(), file);
        }
    }
    let mut pending = VecDeque::from([(executable, true)]);
    let mut visited = BTreeSet::new();
    let mut queued = BTreeSet::new();
    while let Some((image, is_root)) = pending.pop_front() {
        let pe = goblin::pe::PE::parse(image)
            .map_err(|error| new_error!("Invalid Windows native program: {error}"))?;
        validate_pe_role(&pe, is_root)?;
        for library in pe.libraries {
            if Path::new(library).file_name() != Some(OsStr::new(library)) {
                return Err(new_error!(
                    "Windows native program import '{library}' is not a DLL basename"
                ));
            }
            let key = library.to_ascii_lowercase();
            if !visited.insert(key.clone()) {
                continue;
            }
            if visited.len() > max_files {
                return Err(new_error!(
                    "Windows native program dependency closure exceeds 128 DLLs"
                ));
            }
            if is_windows_forced_system_library(library)? {
                continue;
            }
            if let Some(file) = available.get(&key) {
                if queued.insert(key) {
                    pending.push_back((file.bytes(), false));
                }
                continue;
            }
            if is_windows_system_fallback(library) {
                continue;
            }
            return Err(new_error!(
                "Required application DLL '{library}' was not captured. Place it beside the \
                 executable or declare it before placement with MeshProcessProvider::with_runtime_file \
                 or MeshProcessProvider::with_program_runtime_file"
            ));
        }
    }
    Ok(runtime_files.to_vec())
}

fn validate_pe_role(pe: &goblin::pe::PE<'_>, is_root: bool) -> Result<()> {
    if is_root == pe.is_lib {
        return Err(if is_root {
            new_error!("Windows native program image is marked as a DLL")
        } else {
            new_error!("Windows native runtime dependency is not marked as a DLL")
        });
    }
    Ok(())
}

fn is_windows_forced_system_library(library: &str) -> Result<bool> {
    let lower = library.to_ascii_lowercase();
    if lower.starts_with("api-ms-win-") || lower.starts_with("ext-ms-win-") {
        return Ok(true);
    }
    Ok(known_dlls()?.contains(&lower))
}

fn is_windows_system_fallback(library: &str) -> bool {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .is_some_and(|root| root.join("System32").join(library).is_file())
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: RegOpenKeyExW returned this live key handle.
        unsafe { RegCloseKey(self.0) };
    }
}

pub(super) fn known_dlls() -> Result<&'static BTreeSet<String>> {
    static KNOWN_DLLS: OnceLock<std::result::Result<BTreeSet<String>, String>> = OnceLock::new();
    match KNOWN_DLLS.get_or_init(read_known_dlls) {
        Ok(known) => Ok(known),
        Err(error) => Err(new_error!(
            "Mesh provider cannot read the Windows KnownDLL policy: {error}"
        )),
    }
}

fn read_known_dlls() -> std::result::Result<BTreeSet<String>, String> {
    let mut key = std::ptr::null_mut();
    let path = wide(r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs");
    // SAFETY: The predefined root and null-terminated path are valid. `key` is writable.
    let result = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };
    if result != ERROR_SUCCESS {
        return Err(format!("RegOpenKeyExW failed with error {result}"));
    }
    let key = RegistryKey(key);
    let mut known = BTreeSet::new();
    for index in 0.. {
        let mut name = vec![0_u16; 1024];
        let mut name_length = name.len() as u32;
        let mut data = vec![0_u16; 1024];
        let mut data_bytes = (data.len() * size_of::<u16>()) as u32;
        let mut value_type = 0;
        // SAFETY: All buffers are writable for the lengths supplied. Reserved is null.
        let result = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_length,
                std::ptr::null(),
                &mut value_type,
                data.as_mut_ptr().cast(),
                &mut data_bytes,
            )
        };
        if result == ERROR_NO_MORE_ITEMS {
            break;
        }
        if result != ERROR_SUCCESS {
            return Err(format!("RegEnumValueW failed with error {result}"));
        }
        if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
            continue;
        }
        let length = (data_bytes as usize / size_of::<u16>())
            .min(data.len())
            .saturating_sub(1);
        let value = String::from_utf16_lossy(&data[..length]).to_ascii_lowercase();
        if value.ends_with(".dll") {
            known.insert(value);
        }
    }
    Ok(known)
}

struct StagedImage {
    // Locks are released before the directory is deleted.
    locks: Mutex<Vec<File>>,
    directory: Option<tempfile::TempDir>,
    executable: PathBuf,
    scratch: Option<PathBuf>,
}

impl StagedImage {
    fn new(program: &ValidatedProgram, container: Option<&AppContainer>) -> io::Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("hyperlight-image-")
            .tempdir()?;
        protect_directory(
            directory.path(),
            &current_user_sid()?,
            container.map(|container| container.sid.as_str()),
        )?;
        let executable = directory.path().join("program.exe");
        let mut staged = Self {
            locks: Mutex::new(Vec::new()),
            directory: Some(directory),
            executable,
            scratch: None,
        };
        let root = staged.directory.as_ref().unwrap().path().to_owned();
        let mut paths = BTreeSet::from(["program.exe".to_owned()]);
        let mut files = Vec::new();
        for file in program.runtime_files() {
            let relative = runtime_path(file.image_path())?;
            let key = relative.to_string_lossy().to_lowercase();
            if !paths.insert(key) {
                return Err(io::Error::other(
                    "Windows runtime path aliases another file",
                ));
            }
            files.push((root.join(relative), file.bytes()));
        }
        staged.write_file(&staged.executable.clone(), program.executable())?;
        for (path, bytes) in files {
            std::fs::create_dir_all(path.parent().unwrap())?;
            staged.write_file(&path, bytes)?;
        }
        if container.is_none() {
            // The image root owns scratch through the same root/job cleanup barrier.
            staged.scratch = Some(
                tempfile::Builder::new()
                    .prefix(".hyperlight-scratch-")
                    .tempdir_in(&root)?
                    .keep(),
            );
        }
        // A directory lock prevents rename/deletion of the image root.
        staged
            .locks
            .get_mut()
            .map_err(|_| io::Error::other("Image lock poisoned"))?
            .push(
                OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(&root)?,
            );
        Ok(staged)
    }

    fn write_file(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        self.locks
            .get_mut()
            .map_err(|_| io::Error::other("Image lock poisoned"))?
            .push(
                OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ)
                    .open(path)?,
            );
        Ok(())
    }

    fn remove(&self, deadline: Instant) -> io::Result<()> {
        let mut locks = self
            .locks
            .lock()
            .map_err(|_| io::Error::other("Image lock poisoned"))?;
        locks.clear();
        if let Some(directory) = &self.directory {
            retry_image_removal(deadline, || {
                match std::fs::remove_dir_all(directory.path()) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error),
                }
            })?;
        }
        Ok(())
    }
}

impl Drop for StagedImage {
    fn drop(&mut self) {
        if let Err(error) = self.remove(Instant::now()) {
            tracing::error!(%error, "Task-owned executable image cleanup failed");
        }
    }
}

fn retry_image_removal(
    deadline: Instant,
    mut remove: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    loop {
        match remove() {
            Err(error)
                if matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(
                    Duration::from_millis(5)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            result => return result,
        }
    }
}

struct ConfinementJob(OwnedHandle);

impl ConfinementJob {
    fn new(
        memory: Option<usize>,
        cpu_rate_percent: Option<u8>,
        deny_children: bool,
    ) -> io::Result<Self> {
        // SAFETY: Null security attributes make the anonymous job non-inheritable.
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateJobObjectW transfers handle ownership.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Some(bytes) = memory {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            limits.JobMemoryLimit = bytes;
        }
        if deny_children {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
        }
        // SAFETY: The job handle and exact limit structure are valid.
        checked(unsafe {
            SetInformationJobObject(
                job.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&limits) as u32,
            )
        })?;
        let applied = job.limits()?;
        if applied.BasicLimitInformation.LimitFlags != limits.BasicLimitInformation.LimitFlags
            || (deny_children && applied.BasicLimitInformation.ActiveProcessLimit != 1)
            || memory.is_some_and(|requested| {
                applied.JobMemoryLimit == 0 || applied.JobMemoryLimit > requested
            })
        {
            return Err(io::Error::other(
                "Windows did not apply the confinement job limits",
            ));
        }
        if let Some(percent) = cpu_rate_percent {
            let requested = u32::from(percent) * 100;
            let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                    | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                ..Default::default()
            };
            cpu.Anonymous.CpuRate = requested;
            // SAFETY: The job handle and exact CPU-rate structure are valid.
            checked(unsafe {
                SetInformationJobObject(
                    job.0.as_raw_handle(),
                    JobObjectCpuRateControlInformation,
                    (&cpu as *const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
                    size_of_val(&cpu) as u32,
                )
            })?;
            let applied = job.cpu_rate()?;
            if applied.ControlFlags != cpu.ControlFlags
                || unsafe { applied.Anonymous.CpuRate } != requested
            {
                return Err(io::Error::other(
                    "Windows did not apply the requested hard CPU rate",
                ));
            }
        }
        Ok(job)
    }

    fn limits(&self) -> io::Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: The output structure matches JobObjectExtendedLimitInformation.
        checked(unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&limits) as u32,
                null_mut(),
            )
        })?;
        Ok(limits)
    }

    fn active_processes(&self) -> io::Result<u32> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: Writable output buffer matches the requested information class.
        checked(unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of_val(&accounting) as u32,
                null_mut(),
            )
        })?;
        Ok(accounting.ActiveProcesses)
    }

    fn cpu_rate(&self) -> io::Result<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION> {
        let mut rate = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION::default();
        // SAFETY: The output buffer matches JobObjectCpuRateControlInformation.
        checked(unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectCpuRateControlInformation,
                (&mut rate as *mut JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
                size_of_val(&rate) as u32,
                null_mut(),
            )
        })?;
        Ok(rate)
    }

    fn terminate(&self) -> io::Result<()> {
        // SAFETY: This job exclusively contains this worker and its descendants.
        checked(unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) })
    }

    fn wait_empty(&self, deadline: Instant) -> io::Result<()> {
        loop {
            if self.active_processes()? == 0 {
                return Ok(());
            }

            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Confinement job still populated",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(test)]
    fn terminate_and_wait(&self, timeout: Duration) -> io::Result<()> {
        self.terminate()?;
        self.wait_empty(Instant::now() + timeout)
    }
}

fn supported_limits(
    profile: &ProcessProfile,
    policy: WindowsSandboxHostPolicy,
    role: ProgramRole,
) -> Result<(Option<usize>, Option<u8>, bool)> {
    profile.validate()?;
    let mut memory = None;
    let cpu_rate_percent = profile.windows_cpu_rate_percent();
    let mut deny_children = false;
    for request in &profile.controls {
        match request.control {
            ProcessControl::MemoryLimit(bytes) => {
                let bytes = usize::try_from(bytes)
                    .map_err(|_| new_error!("Windows job memory limit exceeds SIZE_T"))?;
                memory = Some(memory.map_or(bytes, |old: usize| old.min(bytes)));
            }
            ProcessControl::DenyChildProcesses => deny_children = true,
            ProcessControl::DenyNetwork if policy.is_windows_vm_host() && request.required => {
                let subject = if role == ProgramRole::FunctionWorker {
                    "A VM-host-authorized Windows function worker"
                } else {
                    "A Windows VM host outside AppContainer"
                };
                return Err(new_error!(
                    "{subject} cannot enforce required network denial"
                ));
            }
            ProcessControl::DenyNetwork => {}
            ProcessControl::CpuBudget { .. } if request.required => {
                return Err(new_error!(
                    "Windows job CPU rate cannot enforce an exact quota/period CPU budget"
                ));
            }
            ProcessControl::CpuBudget { .. } => {}
        }
    }
    Ok((memory, cpu_rate_percent, deny_children))
}

/// Evidence is only reported as applied after the configured CreateProcess succeeds.
#[derive(Clone, Debug)]
pub(super) struct WindowsEvidence {
    pub(super) requested_policy: WindowsSandboxHostPolicy,
    pub(super) policy: WindowsSandboxHostPolicy,
    pub(super) vm_host_authorized: bool,
    pub(super) appcontainer_name: Option<String>,
    pub(super) appcontainer_sid: Option<String>,
    pub(super) program_digest: String,
    pub(super) controls: Vec<ControlOutcome>,
}

/// Resources for exactly one native process tree.
///
/// The owner must retain these through whole-job exit, including launch errors
/// after CreateProcess succeeds. Dropping is a final bounded cleanup fallback.
pub(super) struct WindowsResources {
    role: ProgramRole,
    job: ConfinementJob,
    image: Option<StagedImage>,
    container: Option<Arc<AppContainer>>,
    vm_host_authorized: bool,
    deny_children: bool,
    configured: AtomicBool,
    retain: AtomicBool,
    evidence: WindowsEvidence,
}

impl WindowsResources {
    #[cfg(test)]
    pub(super) fn new(
        definition: &ProcessDefinition,
        program: &ValidatedProgram,
        role: ProgramRole,
    ) -> Result<Self> {
        let container = match definition.windows_sandbox_host_policy() {
            WindowsSandboxHostPolicy::AppContainer => Some(Arc::new(AppContainer::new()?)),
            WindowsSandboxHostPolicy::WindowsVmHost => None,
        };
        Self::with_container(definition, program, role, container)
    }

    fn with_container(
        definition: &ProcessDefinition,
        program: &ValidatedProgram,
        role: ProgramRole,
        container: Option<Arc<AppContainer>>,
    ) -> Result<Self> {
        let profile = definition.profile();
        let unrestricted = profile.is_unrestricted();
        let policy = definition.windows_sandbox_host_policy();
        let trusted_sandbox = policy.is_windows_vm_host();
        let vm_authorized_worker = role == ProgramRole::FunctionWorker
            && policy == WindowsSandboxHostPolicy::AppContainer
            && container.is_none();
        if !unrestricted
            && ((trusted_sandbox && role != ProgramRole::SandboxHost)
                || (container.is_none() && !trusted_sandbox && !vm_authorized_worker)
                || (container.is_some() && trusted_sandbox))
        {
            return Err(new_error!("Windows process policy and principal mismatch"));
        }
        if !unrestricted && container.is_none() && current_process_is_elevated()? {
            return Err(new_error!(
                "Windows VM hosts require a non-elevated controller process. \
                 Start an ordinary PowerShell session and retry"
            ));
        }
        if program.artifact().descriptor() != definition.program().descriptor()
            || program.config().role != role
            || program.config().target.os != "windows"
            || program.config().target.architecture != std::env::consts::ARCH
        {
            return Err(new_error!(
                "Windows program identity, role or target mismatch"
            ));
        }
        let mut actual = program.config().functions.clone();
        let mut expected = definition.functions().to_vec();
        actual.sort_by(|a, b| a.name().cmp(b.name()));
        expected.sort_by(|a, b| a.name().cmp(b.name()));
        if actual != expected {
            return Err(new_error!("Windows program contract mismatch"));
        }
        let effective_policy = if container.is_none() {
            WindowsSandboxHostPolicy::Trusted
        } else {
            WindowsSandboxHostPolicy::AppContainer
        };
        let (memory, cpu_rate_percent, deny_children) =
            supported_limits(&profile, effective_policy, role)?;
        let image = StagedImage::new(program, container.as_deref())?;
        let job = ConfinementJob::new(memory, cpu_rate_percent, deny_children)?;
        #[cfg(test)]
        if let Some(container) = &container {
            // Query the retained real job before preparing its successor.
            let mut previous = container.previous_job.lock().unwrap();
            if let Some(previous) = previous.as_ref() {
                let active = previous.active_processes()?;
                assert_eq!(
                    active, 0,
                    "Retired Windows job still populated before replacement"
                );
                eprintln!(
                    "replacement barrier: SID {} previous job ActiveProcesses={active}",
                    container.sid
                );
            }
            *previous = Some(ConfinementJob(job.0.try_clone()?));
        }
        let memory = memory
            .map(|_| job.limits().map(|limits| limits.JobMemoryLimit))
            .transpose()?;
        let mut baseline = if unrestricted {
            "Unrestricted caller-user process; private immutable staging; kill-on-close ownership job; strict handle inheritance".to_owned()
        } else {
            match &container {
            Some(container) => format!(
                "AppContainer {} SID {}; empty capability allowlist; Mesh requires exact-SID IPC authorization; no inherited environment; null stdio; scoped read/execute image ACL; Windows AppContainer OS-resource baseline",
                container.name, container.sid
            ),
            None if role == ProgramRole::FunctionWorker => "VM-host-authorized function worker outside AppContainer; AppContainer filesystem and network isolation unavailable; caller network and same-user filesystem access remain; ordinary non-elevated same-user principal; kill-on-close job; strict handle inheritance; private immutable staging; no inherited environment; null stdio".to_owned(),
            None => format!(
                "{} outside AppContainer; AppContainer filesystem and network isolation unavailable; caller network and same-user filesystem access remain; kill-on-close job; strict handle inheritance; private immutable staging; no inherited environment; null stdio",
                super::WINDOWS_VM_HOST_MECHANISM
            ),
            }
        };
        if role == ProgramRole::SandboxHost || vm_authorized_worker {
            baseline.push_str("; one VM per process; HYPERLIGHT_MAX_SURROGATES=0");
        }
        if let Some(percent) = cpu_rate_percent {
            baseline.push_str(&format!(
                "; {}{percent}% of aggregate host processor capacity",
                super::WINDOWS_CPU_RATE_MECHANISM
            ));
        }
        let controls = profile.controls.into_iter().map(|requested| {
            let result = match requested.control {
                ProcessControl::MemoryLimit(_) => ControlResult::Applied {
                    effective: ProcessControl::MemoryLimit(memory.unwrap() as u64),
                    mechanism: format!(
                    "JOB_OBJECT_LIMIT_JOB_MEMORY: {} committed virtual-memory bytes across the job; not RSS",
                    memory.unwrap()
                ) + "; " + &baseline },
                ProcessControl::DenyNetwork if container.is_none() => ControlResult::NotApplied {
                    reason: if role == ProgramRole::FunctionWorker {
                        "VM-host-authorized function worker runs outside AppContainer with the caller's network access".to_owned()
                    } else {
                        "Windows VM host runs outside AppContainer with the caller's network access".to_owned()
                    },
                },
                ProcessControl::DenyNetwork => ControlResult::Applied {
                    effective: ProcessControl::DenyNetwork,
                    mechanism: format!("{baseline}; no network capabilities or loopback exemption"),
                },
                ProcessControl::DenyChildProcesses => ControlResult::Applied {
                    effective: ProcessControl::DenyChildProcesses,
                    mechanism: format!("{baseline}; PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY=RESTRICTED; job active-process limit=1"),
                },
                ProcessControl::CpuBudget { .. } => ControlResult::NotApplied {
                    reason: "Windows job CPU rate uses an OS-selected scheduling interval, not the requested quota/period; no CPU cap applied".to_owned(),
                },
            };
            ControlOutcome { requested, result }
        }).collect();
        let evidence = WindowsEvidence {
            requested_policy: policy,
            policy: effective_policy,
            vm_host_authorized: vm_authorized_worker,
            appcontainer_name: container.as_ref().map(|container| container.name.clone()),
            appcontainer_sid: container.as_ref().map(|container| container.sid.clone()),
            program_digest: program.artifact().digest().to_string(),
            controls,
        };
        Ok(Self {
            role,
            job,
            image: Some(image),
            container,
            vm_host_authorized: vm_authorized_worker,
            deny_children,
            configured: AtomicBool::new(false),
            retain: AtomicBool::new(false),
            evidence,
        })
    }

    pub(super) fn evidence(&self) -> &WindowsEvidence {
        &self.evidence
    }

    fn configure(&self, builder: &mut ProcessBuilder<'_>) -> io::Result<()> {
        if self
            .configured
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(io::Error::other(
                "A Windows confinement profile cannot launch another process",
            ));
        }
        let image = self
            .image
            .as_ref()
            .ok_or_else(|| io::Error::other("Image already cleaned"))?;
        builder
            .owned_job(self.job.0.try_clone()?)
            .application_name(&image.executable)
            .current_directory(
                image
                    .directory
                    .as_ref()
                    .ok_or_else(|| io::Error::other("Image already cleaned"))?
                    .path(),
            )
            .inherit_env(false)
            .env("SystemRoot", known_folder(&FOLDERID_Windows)?)
            .env("LOCALAPPDATA", known_folder(&FOLDERID_LocalAppData)?)
            .stdin(Stdio::Null)
            .stdout(Stdio::Null)
            .stderr(Stdio::Null);
        match (self.evidence.policy, &self.container) {
            (WindowsSandboxHostPolicy::AppContainer, Some(container)) => {
                builder.app_container(container.pal_sid()?.as_ref());
            }
            (WindowsSandboxHostPolicy::WindowsVmHost, None) => {}
            _ => {
                return Err(io::Error::other(
                    "Windows process principal already cleaned",
                ));
            }
        }
        if self.role == ProgramRole::SandboxHost || self.vm_host_authorized {
            // This process owns one VM. Surrogate pooling would require extra children.
            builder.env("HYPERLIGHT_MAX_SURROGATES", "0");
        }
        if let Some(scratch) = &image.scratch {
            builder.env("TEMP", scratch).env("TMP", scratch);
        }
        if self.deny_children {
            builder.child_process_policy(ChildProcessPolicy::Disallow);
        }
        Ok(())
    }

    /// A root exit is insufficient. This observes the job's active process count.
    #[cfg(test)]
    pub(super) fn terminate_tree(&self, timeout: Duration) -> Result<()> {
        self.job.terminate_and_wait(timeout)?;
        Ok(())
    }

    pub(super) fn cleanup(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        self.job.terminate()?;
        self.job.wait_empty(deadline)?;
        self.release_resources(deadline)?;
        if let Some(container) = self.container.take()
            && let Ok(container) = Arc::try_unwrap(container)
        {
            container.remove()?;
        }
        Ok(())
    }

    fn retain_resources(&mut self) {
        if let Some(container) = &self.container {
            container.retained.store(true, Ordering::Release);
        }
        if let Some(mut image) = self.image.take()
            && let Some(directory) = image.directory.take()
        {
            let path = directory.keep();
            tracing::error!(?path, profile = ?self.evidence.appcontainer_name,
                "Retaining Windows process resources after unconfirmed cleanup");
        }
    }
}

struct WindowsProfile(Arc<WindowsResources>);

impl SandboxProfile for WindowsProfile {
    fn apply(&mut self, builder: &mut ProcessBuilder<'_>) {
        // Mesh uses try_apply. An older caller must fail before creation.
        self.0
            .configure(builder)
            .expect("Windows confinement setup failed");
    }

    fn try_apply(&mut self, builder: &mut ProcessBuilder<'_>) -> anyhow::Result<()> {
        self.0.configure(builder)?;
        Ok(())
    }
}

impl ProcessGuard for WindowsResources {
    fn start_launch(&self) {
        self.retain.store(true, Ordering::Release);
    }

    fn terminate_domain(&self) -> Result<()> {
        self.job.terminate()?;
        Ok(())
    }

    fn wait_empty(&self, deadline: Instant) -> Result<()> {
        self.job.wait_empty(deadline)?;
        Ok(())
    }

    fn release_resources(&self, deadline: Instant) -> Result<()> {
        self.job.wait_empty(deadline)?;
        if let Some(image) = &self.image {
            image.remove(deadline).map_err(|error| {
                new_error!("Removing staged image {:?}: {error}", image.executable)
            })?;
        }
        self.retain.store(false, Ordering::Release);
        Ok(())
    }
}

pub(super) fn prepare(
    role: ProgramRole,
    definition: &ProcessDefinition,
    program: &ValidatedProgram,
    principals: &WindowsPrincipals,
) -> Result<PreparedProcess> {
    let profile = definition.profile();
    let container = if profile.is_unrestricted() {
        None
    } else {
        principals.principal(role, definition.name())?
    };
    let resources = Arc::new(WindowsResources::with_container(
        definition, program, role, container,
    )?);
    let evidence = resources.evidence();
    tracing::debug!(
        requested_policy = ?evidence.requested_policy,
        policy = ?evidence.policy,
        vm_host_authorized = evidence.vm_host_authorized,
        appcontainer_name = ?evidence.appcontainer_name,
        appcontainer_sid = ?evidence.appcontainer_sid,
        program_digest = %evidence.program_digest,
        "Prepared Windows confinement resources before process creation"
    );
    let controls = evidence.controls.clone();
    let windows_policy = (!profile.is_unrestricted()).then_some(WindowsProcessPolicyReport {
        requested: evidence.requested_policy,
        effective: evidence.policy,
        vm_host_authorized: evidence.vm_host_authorized,
    });
    let mut config = ProcessConfig::new_with_sandbox(
        definition.name(),
        Box::new(WindowsProfile(resources.clone())),
    )
    .process_name(&resources.image.as_ref().unwrap().executable)
    .skip_worker_arg(true);
    for peer in principals.peers(role) {
        let sid = peer.pal_sid()?;
        config = if resources.container.is_some() {
            config.app_container_peer(sid.as_ref())
        } else {
            config.trusted_host_app_container_peer(sid.as_ref())
        };
    }
    Ok(PreparedProcess {
        config,
        guard: resources,
        controls,
        windows_policy,
        resources: Vec::new(),
        export_authority: None,
        resource_generation: None,
    })
}

impl Drop for WindowsResources {
    fn drop(&mut self) {
        if self.retain.load(Ordering::Acquire) {
            let termination = self.job.terminate();
            tracing::error!(
                ?termination,
                "Original-root completion has not authorized resource release"
            );
            self.retain_resources();
            return;
        }
        if let Err(error) = self.cleanup() {
            tracing::error!(
                %error,
                appcontainer = ?self.evidence.appcontainer_name,
                staged_image = ?self.image.as_ref().map(|image| &image.executable),
                "Windows process-tree cleanup incomplete"
            );
            self.retain_resources();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::TcpListener;

    use windows_sys::Win32::Security::{
        SECURITY_ATTRIBUTES, TOKEN_APPCONTAINER_INFORMATION, TokenAppContainerSid,
    };
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        QueryFullProcessImageNameW, WaitForSingleObject,
    };

    use super::*;
    use crate::process::RequestedControl;
    use crate::process::program::{LocalProgramStore, ProgramConfig, ProgramFile, ProgramTarget};

    fn fixture_bytes() -> Vec<u8> {
        let path = std::env::var_os("HYPERLIGHT_WINDOWS_CONFINEMENT_WORKER")
            .expect("Build tests/fixtures/windows_confinement_worker.rs and set its absolute path");
        std::fs::read(path).unwrap()
    }

    struct ObservedRoot {
        handle: OwnedHandle,
        image: PathBuf,
        appcontainer_sid: Option<String>,
    }

    impl ObservedRoot {
        fn new(report: &super::super::ProcessReport) -> Self {
            // SAFETY: Query-only access to the reported ready root. This handle never signals it.
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    report.root_process_id.try_into().unwrap(),
                )
            };
            assert!(!raw.is_null(), "{}", io::Error::last_os_error());
            // SAFETY: OpenProcess transferred this owned handle.
            let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
            let mut path = vec![0u16; 32768];
            let mut length = path.len() as u32;
            // SAFETY: The live handle has query access. Buffer length is in UTF-16 characters.
            checked(unsafe {
                QueryFullProcessImageNameW(
                    handle.as_raw_handle(),
                    0,
                    path.as_mut_ptr(),
                    &mut length,
                )
            })
            .unwrap();
            let image = PathBuf::from(OsString::from_wide(&path[..length as usize]));
            let mut token = null_mut();
            // SAFETY: The live process handle has query access and output is writable.
            checked(unsafe { OpenProcessToken(handle.as_raw_handle(), TOKEN_QUERY, &mut token) })
                .unwrap();
            // SAFETY: OpenProcessToken transferred this owned handle.
            let token = unsafe { OwnedHandle::from_raw_handle(token) };
            let mut length = 0;
            // SAFETY: The zero-size probe writes only the required buffer length.
            unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenAppContainerSid,
                    null_mut(),
                    0,
                    &mut length,
                )
            };
            assert!(length as usize >= size_of::<TOKEN_APPCONTAINER_INFORMATION>());
            let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
            // SAFETY: The buffer has the required size and pointer alignment.
            checked(unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenAppContainerSid,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            })
            .unwrap();
            // SAFETY: The successful query initialized the structure and its buffer-backed SID.
            let sid = unsafe {
                (*buffer.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer
            };
            let appcontainer_sid = if sid.is_null() {
                None
            } else {
                Some(sid_string(sid).unwrap())
            };
            Self {
                handle,
                image,
                appcontainer_sid,
            }
        }

        fn assert_released(&self) {
            // SAFETY: The observation handle remains owned and has synchronize access.
            assert_eq!(
                unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) },
                0
            );
            assert!(
                !self.image.parent().unwrap().exists(),
                "Staged image remains: {:?}",
                self.image
            );
        }
    }

    fn profile_temp(resources: &WindowsResources) -> PathBuf {
        known_folder(&FOLDERID_LocalAppData)
            .unwrap()
            .join("Packages")
            .join(
                resources
                    .container
                    .as_ref()
                    .unwrap()
                    .name
                    .to_ascii_lowercase(),
            )
            .join("AC")
            .join("Temp")
    }

    #[test]
    fn image_cleanup_retry_respects_deadline_and_error_kind() {
        let mut calls = 0;
        retry_image_removal(Instant::now(), || {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1);

        calls = 0;
        retry_image_removal(Instant::now() + Duration::from_secs(1), || {
            calls += 1;
            if calls == 1 {
                Err(io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION as i32))
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(calls, 2);

        calls = 0;
        let error = retry_image_removal(Instant::now(), || {
            calls += 1;
            Err(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32))
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
        assert!(
            retry_image_removal(Instant::now() + Duration::from_secs(1), || {
                Err(io::Error::other("Permanent failure"))
            })
            .is_err()
        );
    }

    fn resources(executable: &[u8], deny_children: bool) -> WindowsResources {
        resources_with_policy(
            executable,
            deny_children,
            WindowsSandboxHostPolicy::AppContainer,
        )
    }

    fn resources_with_policy(
        executable: &[u8],
        deny_children: bool,
        policy: WindowsSandboxHostPolicy,
    ) -> WindowsResources {
        resources_for_role(
            executable,
            deny_children,
            policy,
            ProgramRole::SandboxHost,
            false,
        )
    }

    fn resources_for_role(
        executable: &[u8],
        deny_children: bool,
        policy: WindowsSandboxHostPolicy,
        role: ProgramRole,
        vm_host_authorized: bool,
    ) -> WindowsResources {
        let root = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(root.path());
        let target = ProgramTarget::current(BTreeMap::new());
        let config = ProgramConfig {
            schema_version: 1,
            role,
            target: target.clone(),
            functions: if role == ProgramRole::FunctionWorker {
                vec![
                    super::super::program::FunctionContractDefinition::from_contract(
                        &super::super::HostFunctionContract::<(), u32>::new(
                            "ProcessId",
                            super::super::Idempotency::Idempotent,
                        ),
                    ),
                ]
            } else {
                Vec::new()
            },
        };
        let runtime = ProgramFile::new("/runtime.dat", b"immutable-runtime".to_vec()).unwrap();
        let artifact = store
            .package_with_runtime(&config, executable, &[runtime])
            .unwrap();
        let mut controls = vec![
            RequestedControl {
                control: ProcessControl::MemoryLimit(64 << 20),
                required: true,
            },
            RequestedControl {
                control: ProcessControl::DenyNetwork,
                required: policy == WindowsSandboxHostPolicy::AppContainer && !vm_host_authorized,
            },
        ];
        if deny_children {
            controls.push(RequestedControl {
                control: ProcessControl::DenyChildProcesses,
                required: true,
            });
        }
        let definition = ProcessDefinition::new(
            "native-probe",
            artifact.clone(),
            &ProcessProfile::new(controls)
                .windows_cpu_rate_limit_percent(50)
                .unwrap(),
            config.functions.clone(),
        )
        .unwrap()
        .with_windows_sandbox_host_policy(policy);
        let validated = store.validate(&artifact, &target).unwrap();
        if vm_host_authorized {
            WindowsResources::with_container(&definition, &validated, role, None).unwrap()
        } else {
            WindowsResources::new(&definition, &validated, role).unwrap()
        }
    }

    #[test]
    fn trusted_host_has_no_appcontainer_identity_and_reports_network_omission() {
        let worker = resources_with_policy(
            b"unlaunched-fixture",
            true,
            WindowsSandboxHostPolicy::Trusted,
        );
        assert!(worker.container.is_none());
        assert!(worker.evidence.appcontainer_name.is_none());
        assert!(worker.evidence.appcontainer_sid.is_none());
        assert_eq!(worker.evidence.policy, WindowsSandboxHostPolicy::Trusted);
        assert!(matches!(
            worker.evidence.controls[0].result,
            ControlResult::Applied {
                effective: ProcessControl::MemoryLimit(_),
                ..
            }
        ));
        assert!(matches!(
            worker.evidence.controls[1].result,
            ControlResult::NotApplied { .. }
        ));
        assert!(matches!(
            worker.evidence.controls[2].result,
            ControlResult::Applied {
                effective: ProcessControl::DenyChildProcesses,
                ..
            }
        ));
        assert!(worker.evidence.controls.iter().any(|outcome| matches!(
            &outcome.result,
            ControlResult::Applied { mechanism, .. }
                if mechanism.contains("50% of aggregate host processor capacity")
        )));
        let mut builder = ProcessBuilder::new("unlaunched-fixture");
        worker.configure(&mut builder).unwrap();
        assert!(builder.app_container_sid().is_none());
    }

    #[test]
    fn vm_authorized_worker_reports_reduced_isolation() {
        let worker = resources_for_role(
            b"unlaunched-fixture",
            true,
            WindowsSandboxHostPolicy::AppContainer,
            ProgramRole::FunctionWorker,
            true,
        );
        assert!(worker.container.is_none());
        assert!(worker.vm_host_authorized);
        assert!(worker.evidence.vm_host_authorized);
        assert_eq!(
            worker.evidence.requested_policy,
            WindowsSandboxHostPolicy::AppContainer
        );
        assert_eq!(worker.evidence.policy, WindowsSandboxHostPolicy::Trusted);
        assert!(matches!(
            worker.evidence.controls[1].result,
            ControlResult::NotApplied { ref reason }
                if reason.contains("VM-host-authorized function worker")
        ));
    }

    #[test]
    fn trusted_host_rejects_required_network_denial() {
        let profile = ProcessProfile::new([RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: true,
        }]);
        assert!(
            supported_limits(
                &profile,
                WindowsSandboxHostPolicy::Trusted,
                ProgramRole::SandboxHost
            )
            .is_err()
        );
        assert!(
            supported_limits(
                &profile,
                WindowsSandboxHostPolicy::AppContainer,
                ProgramRole::SandboxHost
            )
            .is_ok()
        );
    }

    #[test]
    fn hard_cpu_rate_is_applied_and_read_back() {
        let job = ConfinementJob::new(None, Some(37), false).unwrap();
        let rate = job.cpu_rate().unwrap();
        assert_eq!(
            rate.ControlFlags,
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        );
        assert_eq!(unsafe { rate.Anonymous.CpuRate }, 3700);
    }

    #[test]
    fn released_appcontainer_cannot_become_trusted() {
        let mut worker = resources(b"unlaunched-fixture", true);
        worker.cleanup().unwrap();
        let mut builder = ProcessBuilder::new("unlaunched-fixture");
        assert!(worker.configure(&mut builder).is_err());
    }

    #[test]
    fn principal_plan_is_a_sandbox_owned_star() {
        use super::super::program::FunctionContractDefinition;
        use super::super::{HostFunctionContract, Idempotency};

        let directory = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(directory.path());
        let target = ProgramTarget::current(Default::default());
        let definition = |name: &'static str, role, functions: Vec<FunctionContractDefinition>| {
            let artifact = store
                .package(
                    &ProgramConfig {
                        schema_version: 1,
                        role,
                        target: target.clone(),
                        functions: functions.clone(),
                    },
                    b"unlaunched-fixture",
                )
                .unwrap();
            ProcessDefinition::new(
                name,
                artifact,
                &ProcessProfile::new([RequestedControl {
                    control: ProcessControl::DenyNetwork,
                    required: true,
                }]),
                functions,
            )
            .unwrap()
        };
        let workers = ["first", "second"].map(|name| {
            let contract = HostFunctionContract::<(), i32>::new(name, Idempotency::Idempotent);
            definition(
                name,
                ProgramRole::FunctionWorker,
                vec![FunctionContractDefinition::from_contract(&contract)],
            )
        });
        let topology = ProcessTopologyDefinition::new(
            Some(definition("sandbox", ProgramRole::SandboxHost, vec![])),
            workers.into(),
        )
        .unwrap();
        let plan = WindowsPrincipals::new(&topology, &Default::default()).unwrap();
        let sandbox = plan
            .principal(ProgramRole::SandboxHost, "sandbox")
            .unwrap()
            .unwrap();
        let first = plan
            .principal(ProgramRole::FunctionWorker, "first")
            .unwrap()
            .unwrap();
        let second = plan
            .principal(ProgramRole::FunctionWorker, "second")
            .unwrap()
            .unwrap();
        assert_ne!(first.sid, second.sid);
        assert_ne!(first.sid, sandbox.sid);
        assert_eq!(
            plan.peers(ProgramRole::SandboxHost)
                .iter()
                .map(|peer| &peer.sid)
                .collect::<Vec<_>>(),
            [&first.sid, &second.sid]
        );
        assert_eq!(
            plan.peers(ProgramRole::FunctionWorker)
                .iter()
                .map(|peer| &peer.sid)
                .collect::<Vec<_>>(),
            [&sandbox.sid]
        );
        assert!(Arc::ptr_eq(
            &first,
            &plan
                .principal(ProgramRole::FunctionWorker, "first")
                .unwrap()
                .unwrap()
        ));
        assert!(
            plan.principal(ProgramRole::FunctionWorker, "sandbox")
                .is_err()
        );
        let fresh = WindowsPrincipals::new(&topology, &Default::default()).unwrap();
        for (name, principal) in &plan.workers {
            assert_ne!(
                principal.as_ref().unwrap().sid,
                fresh.workers[name].as_ref().unwrap().sid
            );
        }
        assert_ne!(
            sandbox.sid,
            fresh.sandbox.as_ref().unwrap().1.as_ref().unwrap().sid
        );

        let trusted = ProcessTopologyDefinition::new(
            Some(
                topology
                    .sandbox()
                    .unwrap()
                    .clone()
                    .with_windows_sandbox_host_policy(WindowsSandboxHostPolicy::Trusted),
            ),
            topology.workers().to_vec(),
        )
        .unwrap();
        let trusted = WindowsPrincipals::new(&trusted, &Default::default()).unwrap();
        assert!(
            trusted
                .principal(ProgramRole::SandboxHost, "sandbox")
                .unwrap()
                .is_none()
        );
        assert_eq!(trusted.peers(ProgramRole::SandboxHost).len(), 2);
        assert!(trusted.peers(ProgramRole::FunctionWorker).is_empty());
        assert!(
            trusted
                .principal(ProgramRole::SandboxHost, "wrong-owner")
                .is_err()
        );

        let authorized = std::collections::BTreeSet::from(["first".to_owned()]);
        let authorized = WindowsPrincipals::new(&topology, &authorized).unwrap();
        assert!(
            authorized
                .principal(ProgramRole::FunctionWorker, "first")
                .unwrap()
                .is_none()
        );
        assert!(
            authorized
                .principal(ProgramRole::FunctionWorker, "second")
                .unwrap()
                .is_some()
        );
        assert_eq!(authorized.peers(ProgramRole::SandboxHost).len(), 1);
    }

    fn spawn(resources: &WindowsResources, args: &[String]) -> io::Result<pal::windows::Process> {
        let executable = &resources.image.as_ref().unwrap().executable;
        // Probe arguments contain no embedded quotes or trailing backslashes.
        let quoted = args
            .iter()
            .map(|arg| {
                assert!(!arg.contains('"') && !arg.ends_with('\\'));
                format!("\"{arg}\"")
            })
            .collect::<Vec<_>>()
            .join(" ");
        let mut builder = ProcessBuilder::new(format!("\"{}\" {quoted}", executable.display()));
        resources.configure(&mut builder)?;
        use std::os::windows::io::AsHandle;
        let stderr = io::stderr();
        builder.stderr(Stdio::Handle(stderr.as_handle()));
        builder.spawn()
    }

    fn wait_root(process: &pal::windows::Process) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(code) = process.try_wait().unwrap() {
                return code;
            }
            assert!(Instant::now() < deadline, "Native probe timed out");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn rejects_windows_path_aliases() {
        for path in [
            "/a/../b",
            "/NUL.dll",
            "/COM1",
            "/a.",
            "/a ",
            "/x:y",
            "/a\\b",
            "/LPT².txt",
            "//a",
        ] {
            assert!(runtime_path(path).is_err(), "{path}");
        }

        assert_eq!(
            runtime_path("/lib/a.dll").unwrap(),
            PathBuf::from("lib/a.dll")
        );
    }

    #[test]
    fn provider_discovers_current_executable_system_imports_without_packaging_them() {
        let executable = std::env::current_exe().unwrap();
        let bytes = std::fs::read(&executable).unwrap();
        let adjacent = capture_adjacent_dependencies(&bytes, executable.parent()).unwrap();
        let files = runtime_closure(&bytes, &adjacent).unwrap();
        assert!(files.iter().all(|file| {
            executable
                .parent()
                .unwrap()
                .join(&file.image_path()[1..])
                .is_file()
        }));
    }

    #[test]
    fn runtime_closure_rejects_aggregate_size_bound() {
        let executable = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let file = super::super::program::ProgramFile::new("/data.bin", vec![1]).unwrap();
        let error =
            runtime_closure_with_limits(&executable, &[file], usize::MAX, executable.len() as u64)
                .unwrap_err();
        assert!(error.to_string().contains("exceeds 256 MiB"));
    }

    #[test]
    fn exact_period_cpu_budget_fails_required() {
        let profile = ProcessProfile::new([RequestedControl {
            control: ProcessControl::CpuBudget {
                quota: Duration::from_millis(10),
                period: Duration::from_millis(100),
            },
            required: true,
        }]);
        assert!(
            supported_limits(
                &profile,
                WindowsSandboxHostPolicy::AppContainer,
                ProgramRole::SandboxHost
            )
            .is_err()
        );
    }

    #[test]
    fn task_profiles_are_unique_and_removable() {
        let first = AppContainer::new().unwrap();
        let second = AppContainer::new().unwrap();
        assert_ne!(first.sid, second.sid);
        first.remove().unwrap();
        second.remove().unwrap();
    }

    #[test]
    fn empty_job_has_whole_tree_exit_evidence() {
        let job = ConfinementJob::new(Some(64 * 1024 * 1024), Some(50), true).unwrap();
        assert_eq!(job.active_processes().unwrap(), 0);
        job.terminate_and_wait(Duration::from_secs(1)).unwrap();
    }

    /// The upstream harness queries the actual worker tokens and working
    /// directories, exchanges Mesh messages, then reaps one root before
    /// verifying that its independently confined sibling still replies.
    #[test]
    #[ignore = "requires the latest HYPERLIGHT_MESH_APPCONTAINER_FIXTURE compiler artifact"]
    fn native_mesh_actual_token_echo_and_sibling_survival() {
        qualify_mesh("appcontainer-qualification", 2);
    }

    #[test]
    #[ignore = "requires the latest HYPERLIGHT_MESH_APPCONTAINER_FIXTURE compiler artifact"]
    fn native_mesh_star_and_receiver_replacement() {
        qualify_mesh("appcontainer-star-qualification", 3);
    }

    #[test]
    #[ignore = "requires the latest HYPERLIGHT_MESH_APPCONTAINER_FIXTURE compiler artifact"]
    fn native_mesh_trusted_host_star_and_wrong_sid_denial() {
        qualify_mesh("trusted-host-star-qualification", 4);
    }

    fn qualify_mesh(mode: &str, count: usize) {
        let fixture = PathBuf::from(
            std::env::var_os("HYPERLIGHT_MESH_APPCONTAINER_FIXTURE")
                .expect("Set the latest invitation_startup compiler-artifact executable"),
        );
        assert!(fixture.is_absolute());
        let bytes = std::fs::read(&fixture).unwrap();
        let mut workers: Vec<_> = (0..count)
            .map(|index| {
                let policy = if mode == "trusted-host-star-qualification" && index == 0 {
                    WindowsSandboxHostPolicy::Trusted
                } else {
                    WindowsSandboxHostPolicy::AppContainer
                };
                resources_with_policy(&bytes, true, policy)
            })
            .collect();
        let identities: BTreeSet<_> = workers
            .iter()
            .map(|worker| &worker.evidence.appcontainer_sid)
            .collect();
        assert_eq!(identities.len(), count);
        // This outer job owns the fixture and all its children, not production worker limits.
        let job = ConfinementJob::new(None, None, false).unwrap();
        let mut command = ProcessBuilder::new(format!("\"{}\" {mode}", fixture.display()));
        command
            .application_name(&fixture)
            .owned_job(job.0.try_clone().unwrap());
        let mut directories = Vec::new();
        for (offset, worker) in workers.iter().enumerate() {
            let index = offset + 1;
            let image = worker.image.as_ref().unwrap();
            let directory = image.executable.parent().unwrap();
            // Exact byte equality pins both locked copies to the selected build.
            assert_eq!(std::fs::read(&image.executable).unwrap(), bytes);
            if let Some(sid) = &worker.evidence.appcontainer_sid {
                command.env(format!("MESH_AC_TEST_SID_{index}"), sid);
            }
            command
                .env(format!("MESH_AC_TEST_EXE_{index}"), &image.executable)
                .env(format!("MESH_AC_TEST_DIR_{index}"), directory);
            directories.push(directory.to_owned());
        }
        let process = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = process.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        job.terminate_and_wait(Duration::from_secs(10)).unwrap();
        wait_root(&process);
        for worker in &mut workers {
            worker.cleanup().unwrap();
        }
        assert!(directories.iter().all(|directory| !directory.exists()));
        assert!(workers.iter().all(|worker| worker.container.is_none()));
        assert_eq!(status, Some(0), "Actual-token Mesh qualification: {mode}");
    }

    #[test]
    #[ignore = "requires the explicitly compiled HYPERLIGHT_WINDOWS_CONFINEMENT_WORKER"]
    fn native_access_child_environment_and_memory_denial() {
        let bytes = fixture_bytes();
        let mut sibling = resources(&bytes, true);
        let sibling_root = spawn(&sibling, &["idle".into()]).unwrap();
        let secret = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(secret.path(), b"host-only-secret").unwrap();
        assert_eq!(std::fs::read(secret.path()).unwrap(), b"host-only-secret");
        // SAFETY: Establish host commitment headroom before testing the job cap.
        let allocation =
            unsafe { VirtualAlloc(null(), 128 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        assert!(
            !allocation.is_null(),
            "Host cannot commit the probe allocation"
        );
        // SAFETY: allocation is the base of the allocation immediately above.
        assert_ne!(unsafe { VirtualFree(allocation, 0, MEM_RELEASE) }, 0);
        let mut worker = resources(&bytes, true);
        let own_temp = profile_temp(&worker);
        assert!(own_temp.is_dir());
        assert_ne!(
            std::env::var_os("TEMP").map(PathBuf::from).as_ref(),
            Some(&own_temp)
        );
        assert_ne!(
            std::env::var_os("TMP").map(PathBuf::from).as_ref(),
            Some(&own_temp)
        );
        let sibling_secret = profile_temp(&sibling).join("hyperlight-sibling-canary");
        std::fs::write(&sibling_secret, b"sibling-private").unwrap();
        let root = spawn(
            &worker,
            &[
                "probe".into(),
                secret.path().to_string_lossy().into_owned(),
                sibling
                    .image
                    .as_ref()
                    .unwrap()
                    .executable
                    .to_string_lossy()
                    .into_owned(),
                own_temp.to_string_lossy().into_owned(),
                sibling_secret.to_string_lossy().into_owned(),
            ],
        )
        .unwrap();
        assert_eq!(wait_root(&root), 0, "See native probe exit-code checks");
        worker.cleanup().unwrap();
        assert!(sibling_root.try_wait().unwrap().is_none());
        assert_eq!(sibling.job.active_processes().unwrap(), 1);
        sibling.terminate_tree(Duration::from_secs(5)).unwrap();
        wait_root(&sibling_root);
        sibling.cleanup().unwrap();
    }

    #[test]
    #[ignore = "requires the explicitly compiled HYPERLIGHT_WINDOWS_CONFINEMENT_WORKER"]
    fn native_handle_allowlist_preserves_object_identity() {
        use std::os::windows::io::AsHandle;

        use windows_sys::Win32::Foundation::{
            CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INVALID_HANDLE,
        };

        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let event = || {
            // SAFETY: Initialized attributes deliberately create an inheritable event.
            let raw = unsafe { CreateEventW(&attributes, 1, 0, null()) };
            assert!(!raw.is_null());
            // SAFETY: CreateEventW transferred ownership.
            unsafe { OwnedHandle::from_raw_handle(raw) }
        };
        let allowed = event();
        let unrelated = event();
        let mut worker = resources(&fixture_bytes(), true);
        let executable = &worker.image.as_ref().unwrap().executable;
        let mut builder = ProcessBuilder::new(format!("\"{}\" idle", executable.display()));
        worker.configure(&mut builder).unwrap();
        builder.handle(&allowed).suspended(true);
        let root = builder.spawn().unwrap();
        let snapshot = |raw| {
            let mut duplicate = null_mut();
            // SAFETY: Both process handles are live. No source handle is closed.
            // Query from the parent avoids the child's strict-invalid-handle trap.
            if unsafe {
                DuplicateHandle(
                    root.as_handle().as_raw_handle(),
                    raw,
                    GetCurrentProcess(),
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(ERROR_INVALID_HANDLE as i32)
                );
                None
            } else {
                // SAFETY: DuplicateHandle returned an owned handle in this process.
                Some(unsafe { OwnedHandle::from_raw_handle(duplicate) })
            }
        };
        let inherited =
            snapshot(allowed.as_raw_handle()).expect("Explicit handle was not inherited");
        // SAFETY: Both handles are live in this process.
        assert_ne!(
            unsafe { CompareObjectHandles(inherited.as_raw_handle(), allowed.as_raw_handle()) },
            0
        );
        if let Some(candidate) = snapshot(unrelated.as_raw_handle()) {
            // SAFETY: Both handles are live. Numeric reuse is not inheritance.
            assert_eq!(
                unsafe {
                    CompareObjectHandles(candidate.as_raw_handle(), unrelated.as_raw_handle())
                },
                0
            );
        }
        worker.terminate_tree(Duration::from_secs(5)).unwrap();
        wait_root(&root);
        worker.cleanup().unwrap();
    }

    #[test]
    #[ignore = "requires the explicitly compiled HYPERLIGHT_WINDOWS_CONFINEMENT_WORKER"]
    fn native_network_denial() {
        let bytes = fixture_bytes();
        let bind: std::net::IpAddr = std::env::var("HYPERLIGHT_WINDOWS_NETWORK_BIND")
            .expect("Set HYPERLIGHT_WINDOWS_NETWORK_BIND to a reachable non-loopback local address")
            .parse()
            .unwrap();
        assert!(!bind.is_loopback() && !bind.is_unspecified());
        let listener = TcpListener::bind((bind, 0)).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let unrestricted = || {
            std::process::Command::new(
                std::env::var_os("HYPERLIGHT_WINDOWS_CONFINEMENT_WORKER").unwrap(),
            )
            .args(["connect", &address])
            .status()
            .unwrap()
            .success()
        };
        assert!(
            unrestricted(),
            "Unrestricted child cannot reach the live listener"
        );
        let mut worker = resources(&bytes, true);
        let root = spawn(&worker, &["network".into(), address.clone()]).unwrap();
        let exit = wait_root(&root);
        worker.cleanup().unwrap();
        assert!(
            unrestricted(),
            "Listener stopped serving the unrestricted child"
        );
        assert_eq!(
            exit, 0,
            "Network denial needs corroborating isolation diagnostics"
        );
    }

    #[test]
    #[ignore = "requires the built HYPERLIGHT_WINDOWS_PROCESS_WORKER and prebuilt test guest"]
    fn guest_calls_production_windows_worker_and_reconstructs_snapshot() {
        check_windows_guest_placement(None);
    }

    #[test]
    #[ignore = "requires built Windows workers and prebuilt test guest"]
    fn required_appcontainer_sandbox_host_does_not_fallback() {
        check_windows_guest_placement(Some(WindowsSandboxHostPolicy::AppContainer));
    }

    #[test]
    #[ignore = "requires built Windows workers, exact-peer Mesh support and prebuilt test guest"]
    fn trusted_sandbox_host_with_confined_functions_and_snapshot_reauthorization() {
        check_windows_guest_placement(Some(WindowsSandboxHostPolicy::Trusted));
    }

    #[test]
    #[ignore = "requires the explicitly compiled Windows confinement probe"]
    fn native_trusted_sandbox_host_can_access_whp() {
        let mut worker =
            resources_with_policy(&fixture_bytes(), true, WindowsSandboxHostPolicy::Trusted);
        let root = spawn(&worker, &["whp".to_owned()]).unwrap();
        let exit = wait_root(&root);
        worker.cleanup().unwrap();
        assert_eq!(exit, 0, "Explicitly trusted sandbox-host WHP probe failed");
    }

    #[test]
    #[ignore = "requires the explicitly compiled Windows confinement probe"]
    fn native_single_vm_environment_is_scoped_to_sandbox_host() {
        for (role, expected) in [
            (ProgramRole::SandboxHost, "single"),
            (ProgramRole::FunctionWorker, "absent"),
        ] {
            let mut worker = resources_for_role(
                &fixture_bytes(),
                true,
                WindowsSandboxHostPolicy::AppContainer,
                role,
                false,
            );
            let root = spawn(&worker, &["surrogate-mode".into(), expected.into()]).unwrap();
            let exit = wait_root(&root);
            worker.cleanup().unwrap();
            assert_eq!(exit, 0, "{role:?} child environment");
        }
    }

    #[test]
    #[ignore = "requires the explicitly compiled Windows confinement probe"]
    fn native_vm_authorized_worker_uses_launchable_ordinary_token() {
        let mut worker = resources_for_role(
            &fixture_bytes(),
            true,
            WindowsSandboxHostPolicy::AppContainer,
            ProgramRole::FunctionWorker,
            true,
        );
        let root = spawn(&worker, &["surrogate-mode".into(), "single".into()]).unwrap();
        let exit = wait_root(&root);
        worker.cleanup().unwrap();
        assert_eq!(exit, 0, "VM-authorized worker token and environment");
    }

    #[test]
    #[ignore = "requires the built Windows sandbox worker and prebuilt test guest"]
    fn trusted_sandbox_host_with_executable_local_function() {
        use crate::process::program::FunctionContractDefinition;
        use crate::process::{HostFunctionContract, Idempotency, ProcessOptions};

        const PRINT: HostFunctionContract<(String,), i32> =
            HostFunctionContract::new("HostPrint", Idempotency::Idempotent);
        let executable =
            std::fs::read(std::env::var_os("HYPERLIGHT_WINDOWS_SANDBOX_WORKER").unwrap()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(directory.path());
        let target = ProgramTarget::current(Default::default());
        let artifact = store
            .package(
                &ProgramConfig {
                    schema_version: 1,
                    role: ProgramRole::SandboxHost,
                    target: target.clone(),
                    functions: vec![FunctionContractDefinition::from_contract(&PRINT)],
                },
                &executable,
            )
            .unwrap();
        let profile = ProcessProfile::new([
            RequestedControl {
                control: ProcessControl::MemoryLimit(512 << 20),
                required: true,
            },
            RequestedControl {
                control: ProcessControl::DenyChildProcesses,
                required: true,
            },
        ]);
        let mut sandbox =
            crate::SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
                .sandbox_process(
                    ProcessOptions::with_program_artifact("sandbox", artifact, profile)
                        .windows_sandbox_host_policy(WindowsSandboxHostPolicy::Trusted),
                )
                .sandbox_host_function(PRINT)
                .allow_trusted_windows_sandbox_host()
                .process_programs(store.clone(), target.clone())
                .build()
                .unwrap();
        let reports = sandbox.process_reports();
        assert_eq!(reports.len(), 1);
        let root = ObservedRoot::new(&reports[0]);
        assert!(root.appcontainer_sid.is_none());
        assert_eq!(
            sandbox
                .call::<i32>("PrintOutput", "executable-local callback".to_owned())
                .unwrap(),
            reports[0].root_process_id,
        );
        let before = sandbox.call::<i32>("GetStatic", ()).unwrap();
        let snapshot = sandbox.snapshot().unwrap();
        assert_eq!(sandbox.call::<i32>("AddToStatic", 7).unwrap(), before + 7);
        sandbox.restore(snapshot.clone()).unwrap();
        assert_eq!(sandbox.call::<i32>("GetStatic", ()).unwrap(), before);
        let mut sibling = crate::SandboxBuilder::from_snapshot(snapshot)
            .allow_trusted_windows_sandbox_host()
            .process_programs(store, target)
            .build()
            .unwrap();
        let sibling_report = sibling.process_reports().remove(0);
        let sibling_root = ObservedRoot::new(&sibling_report);
        assert_ne!(reports[0].root_process_id, sibling_report.root_process_id);
        drop(sandbox);
        root.assert_released();
        assert_eq!(
            sibling
                .call::<i32>("PrintOutput", "independent reconstruction".to_owned())
                .unwrap(),
            sibling_report.root_process_id,
        );
        drop(sibling);
        sibling_root.assert_released();
    }

    #[test]
    #[ignore = "requires the explicitly compiled Windows confinement probe"]
    fn native_whp_capability_under_confinement() {
        let executable = std::env::var_os("HYPERLIGHT_WINDOWS_CONFINEMENT_WORKER").unwrap();
        let baseline = std::process::Command::new(executable)
            .arg("whp")
            .status()
            .unwrap();
        assert!(baseline.success(), "Unrestricted WHP baseline failed");
        let mut worker = resources(&fixture_bytes(), true);
        let root = spawn(&worker, &["whp".to_owned()]).unwrap();
        let exit = wait_root(&root);
        worker.cleanup().unwrap();
        assert_eq!(exit, 0, "Confined WHP capability probe failed");
    }

    // Bounded resource-transfer experiment. This is not a supported placement.
    mod migration_transfer_probe {
        use std::os::windows::io::AsHandle;

        use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
        use windows_sys::Win32::System::Threading::{SetEvent, WaitForSingleObject};

        use super::*;

        #[link(
            name = "WinHvPlatform.dll",
            kind = "raw-dylib",
            modifiers = "+verbatim"
        )]
        unsafe extern "system" {
            fn WHvCreatePartition(partition: *mut *mut c_void) -> i32;
            fn WHvSetPartitionProperty(
                partition: *mut c_void,
                code: u32,
                value: *const c_void,
                size: u32,
            ) -> i32;
            fn WHvSetupPartition(partition: *mut c_void) -> i32;
            fn WHvStartPartitionMigration(
                partition: *mut c_void,
                migration: *mut *mut c_void,
            ) -> i32;
            fn WHvCompletePartitionMigration(partition: *mut c_void) -> i32;
            fn WHvDeletePartition(partition: *mut c_void) -> i32;
        }

        struct SourcePartition(*mut c_void);

        impl Drop for SourcePartition {
            fn drop(&mut self) {
                // SAFETY: This owned source object remains deletable after completion.
                // Delete also cancels any migration that did not complete.
                let result = unsafe { WHvDeletePartition(self.0) };
                eprintln!("MIGRATION source: WHvDeletePartition={result:#010x}");
                assert!(result >= 0, "Source partition cleanup failed");
            }
        }

        fn checked(step: &str, result: i32) -> std::result::Result<(), String> {
            eprintln!("MIGRATION source: {step}={result:#010x}");
            if result < 0 {
                Err(format!("{step} failed: {result:#010x}"))
            } else {
                Ok(())
            }
        }

        #[test]
        #[ignore = "bounded native migration experiment with the explicitly compiled probe"]
        fn native_whp_partition_transfer_under_unchanged_confinement() {
            let mut worker = resources(&fixture_bytes(), true);
            let result = (|| -> std::result::Result<(), String> {
                let mut partition = null_mut();
                // SAFETY: Writable output receives a new, exclusively owned partition.
                checked("WHvCreatePartition", unsafe {
                    WHvCreatePartition(&mut partition)
                })?;
                let source = SourcePartition(partition);
                let count = 1u32;
                // SAFETY: ProcessorCount is a UINT32. No VP or guest memory exists here.
                checked("WHvSetPartitionProperty(ProcessorCount)", unsafe {
                    WHvSetPartitionProperty(source.0, 0x1fff, (&count as *const u32).cast(), 4)
                })?;
                // SAFETY: The empty source partition has its required count configured.
                checked("WHvSetupPartition", unsafe { WHvSetupPartition(source.0) })?;
                let mut migration = null_mut();
                // SAFETY: The configured partition is live and the output is writable.
                checked("WHvStartPartitionMigration", unsafe {
                    WHvStartPartitionMigration(source.0, &mut migration)
                })?;
                // SAFETY: Start returned an owned standard Win32 HANDLE.
                let migration = unsafe { OwnedHandle::from_raw_handle(migration) };
                let mut transferable = null_mut();
                // SAFETY: Duplicate only our migration HANDLE within this process.
                if unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        migration.as_raw_handle(),
                        GetCurrentProcess(),
                        &mut transferable,
                        0,
                        1,
                        DUPLICATE_SAME_ACCESS,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error().to_string());
                }
                // SAFETY: DuplicateHandle transferred ownership of the duplicate.
                let transferable = unsafe { OwnedHandle::from_raw_handle(transferable) };
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: null_mut(),
                    bInheritHandle: 1,
                };
                let event = || -> std::result::Result<OwnedHandle, String> {
                    // SAFETY: Initialized attributes request an unnamed inheritable event.
                    let raw = unsafe { CreateEventW(&attributes, 1, 0, null()) };
                    if raw.is_null() {
                        return Err(io::Error::last_os_error().to_string());
                    }
                    // SAFETY: CreateEventW transferred ownership.
                    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
                };
                let accepted = event()?;
                let completed = event()?;
                let executable = &worker.image.as_ref().unwrap().executable;
                let mut builder = ProcessBuilder::new(format!(
                    "\"{}\" whp-migration {} {} {}",
                    executable.display(),
                    transferable.as_raw_handle() as usize,
                    accepted.as_raw_handle() as usize,
                    completed.as_raw_handle() as usize,
                ));
                worker
                    .configure(&mut builder)
                    .map_err(|error| error.to_string())?;
                let stderr = io::stderr();
                builder
                    .handle(&transferable)
                    .handle(&accepted)
                    .handle(&completed)
                    .stderr(Stdio::Handle(stderr.as_handle()));
                let root = builder.spawn().map_err(|error| error.to_string())?;
                let deadline = Instant::now() + Duration::from_secs(8);
                let transferred = loop {
                    // SAFETY: accepted is a retained live event owned by this test.
                    if unsafe { WaitForSingleObject(accepted.as_raw_handle(), 0) } == 0 {
                        break true;
                    }
                    if root
                        .try_wait()
                        .map_err(|error| error.to_string())?
                        .is_some()
                        || Instant::now() >= deadline
                    {
                        break false;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                };
                let completion = if transferred {
                    // SAFETY: Destination signaled successful Accept for this migration.
                    let result = checked("WHvCompletePartitionMigration", unsafe {
                        WHvCompletePartitionMigration(source.0)
                    });
                    if result.is_ok() {
                        // SAFETY: completed is the retained event in the immutable allowlist.
                        if unsafe { SetEvent(completed.as_raw_handle()) } == 0 {
                            return Err(io::Error::last_os_error().to_string());
                        }
                    }
                    result
                } else {
                    Err("Destination did not accept the migration".into())
                };
                if completion.is_err() {
                    worker
                        .terminate_tree(Duration::from_secs(5))
                        .map_err(|error| error.to_string())?;
                }
                let exit = wait_root(&root);
                eprintln!("MIGRATION destination: process exit={exit}");
                completion?;
                if exit != 0 {
                    return Err(format!("Destination probe exit={exit}"));
                }
                Ok(())
            })();
            let cleanup = worker.cleanup();
            eprintln!("MIGRATION confinement cleanup={cleanup:?}");
            cleanup.unwrap();
            result.unwrap();
        }
    }

    fn check_windows_guest_placement(policy: Option<WindowsSandboxHostPolicy>) {
        use crate::process::program::FunctionContractDefinition;
        use crate::process::{
            HostFunctionContract, HostFunctionProcess, Idempotency, ProcessOptions,
        };

        const ADD: HostFunctionContract<(i32, i32), i32> =
            HostFunctionContract::new("HostAdd", Idempotency::Idempotent);
        const PID: HostFunctionContract<(), u32> =
            HostFunctionContract::new("ProcessId", Idempotency::Idempotent);
        const PRINT: HostFunctionContract<(String,), i32> =
            HostFunctionContract::new("HostPrint", Idempotency::Idempotent);
        let executable = std::fs::read(
            std::env::var_os("HYPERLIGHT_WINDOWS_PROCESS_WORKER")
                .expect("Build the process_worker example"),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(directory.path());
        let target = ProgramTarget::current(Default::default());
        let artifact = store
            .package(
                &ProgramConfig {
                    schema_version: 1,
                    role: ProgramRole::FunctionWorker,
                    target: target.clone(),
                    functions: vec![
                        FunctionContractDefinition::from_contract(&ADD),
                        FunctionContractDefinition::from_contract(&PID),
                    ],
                },
                &executable,
            )
            .unwrap();
        let profile = ProcessProfile::new([
            RequestedControl {
                control: ProcessControl::MemoryLimit(256 << 20),
                required: true,
            },
            RequestedControl {
                control: ProcessControl::DenyNetwork,
                required: true,
            },
            RequestedControl {
                control: ProcessControl::DenyChildProcesses,
                required: true,
            },
            RequestedControl {
                control: ProcessControl::CpuBudget {
                    quota: Duration::from_millis(50),
                    period: Duration::from_millis(100),
                },
                required: false,
            },
        ]);
        let mut builder =
            crate::SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
                .host_function_process(
                    HostFunctionProcess::new(ProcessOptions::with_program_artifact(
                        "arithmetic",
                        artifact,
                        profile.clone(),
                    ))
                    .function(ADD)
                    .function(PID),
                )
                .process_programs(store.clone(), target.clone());
        if let Some(policy) = policy {
            let executable = std::fs::read(
                std::env::var_os("HYPERLIGHT_WINDOWS_SANDBOX_WORKER")
                    .expect("Build the sandbox_worker example"),
            )
            .unwrap();
            let artifact = store
                .package(
                    &ProgramConfig {
                        schema_version: 1,
                        role: ProgramRole::SandboxHost,
                        target: target.clone(),
                        functions: vec![FunctionContractDefinition::from_contract(&PRINT)],
                    },
                    &executable,
                )
                .unwrap();
            let profile = ProcessProfile::new(profile.controls.into_iter().map(|mut request| {
                if policy == WindowsSandboxHostPolicy::Trusted
                    && request.control == ProcessControl::DenyNetwork
                {
                    request.required = false;
                }
                if matches!(request.control, ProcessControl::MemoryLimit(_)) {
                    request.control = ProcessControl::MemoryLimit(512 << 20);
                }
                request
            }));
            builder = builder
                .sandbox_process(
                    ProcessOptions::with_program_artifact("sandbox", artifact, profile)
                        .windows_sandbox_host_policy(policy),
                )
                .sandbox_host_function(PRINT);
            if policy == WindowsSandboxHostPolicy::Trusted {
                builder = builder.allow_trusted_windows_sandbox_host();
            }
        }
        if policy == Some(WindowsSandboxHostPolicy::AppContainer) {
            let error = builder
                .build()
                .expect_err("AppContainer WHP access is denied on this host");
            assert!(error.to_string().contains("0x80070005"), "{error}");
            return;
        }
        let mut sandbox = builder.build().unwrap();
        assert_eq!(sandbox.call::<i32>("Add", (10_i32, 32_i32)).unwrap(), 42);
        let reports = sandbox.process_reports();
        assert_eq!(reports.len(), if policy.is_some() { 2 } else { 1 });
        let observed: Vec<_> = reports.iter().map(ObservedRoot::new).collect();
        for (report, root) in reports.iter().zip(&observed) {
            assert_eq!(
                root.appcontainer_sid.is_some(),
                report.role == ProgramRole::FunctionWorker
            );
        }
        assert_eq!(reports[0].controls.len(), 4);
        for control in &reports[0].controls {
            if control.requested.required {
                assert!(matches!(control.result, ControlResult::Applied { .. }));
            } else {
                assert!(matches!(control.result, ControlResult::NotApplied { .. }));
            }
        }
        let original = reports.last().unwrap().root_process_id;
        let before = sandbox.call::<i32>("GetStatic", ()).unwrap();
        let snapshot = sandbox.snapshot().unwrap();
        assert_eq!(sandbox.call::<i32>("AddToStatic", 7).unwrap(), before + 7);
        let export = tempfile::tempdir().unwrap();
        let digest = snapshot
            .save_with_programs(
                export.path(),
                &crate::sandbox::snapshot::OciTag::new("placement").unwrap(),
                &store,
            )
            .unwrap();
        let imported = Arc::new(
            crate::sandbox::snapshot::Snapshot::checked_load(export.path(), digest).unwrap(),
        );
        assert_eq!(snapshot.process_topology(), imported.process_topology());
        let embedded = LocalProgramStore::new(export.path());
        let mut fresh = crate::SandboxBuilder::from_snapshot(imported.clone())
            .process_programs(embedded.clone(), target.clone());
        if policy == Some(WindowsSandboxHostPolicy::Trusted) {
            let error = crate::SandboxBuilder::from_snapshot(imported.clone())
                .process_programs(embedded, target.clone())
                .build()
                .expect_err("Snapshot metadata cannot authorize trusted execution");
            assert!(
                error.to_string().contains("explicit runtime permission"),
                "{error}"
            );
            fresh = fresh.allow_trusted_windows_sandbox_host();
        }
        let mut fresh = fresh.build().unwrap();
        let sibling_reports = fresh.process_reports();
        let sibling_roots: Vec<_> = sibling_reports.iter().map(ObservedRoot::new).collect();
        assert_ne!(
            observed.last().unwrap().appcontainer_sid,
            sibling_roots.last().unwrap().appcontainer_sid
        );
        assert_ne!(
            fresh.process_reports().last().unwrap().root_process_id,
            original
        );
        assert_eq!(fresh.call::<i32>("Add", (20_i32, 22_i32)).unwrap(), 42);
        assert_eq!(fresh.call::<i32>("GetStatic", ()).unwrap(), before);
        sandbox.restore(snapshot.clone()).unwrap();
        assert_eq!(sandbox.call::<i32>("GetStatic", ()).unwrap(), before);
        assert_eq!(
            sandbox.process_reports().last().unwrap().root_process_id,
            original
        );
        assert_eq!(sandbox.call::<i32>("Add", (40_i32, 2_i32)).unwrap(), 42);

        // Inject through the owned original-root object, never a PID lookup.
        sandbox.terminate_worker_for_test(0).unwrap();
        assert_eq!(sandbox.call::<i32>("Add", (39_i32, 3_i32)).unwrap(), 42);
        let recovered = sandbox.process_reports();
        assert_ne!(recovered.last().unwrap().root_process_id, original);
        if policy.is_some() {
            assert_eq!(recovered[0].root_process_id, reports[0].root_process_id);
        }
        let replacement = ObservedRoot::new(recovered.last().unwrap());
        assert_eq!(
            replacement.appcontainer_sid,
            observed.last().unwrap().appcontainer_sid
        );
        observed.last().unwrap().assert_released();
        assert_eq!(sandbox.call::<i32>("GetStatic", ()).unwrap(), before);
        assert_eq!(fresh.call::<i32>("Add", (38_i32, 4_i32)).unwrap(), 42);
        assert_eq!(
            fresh
                .process_reports()
                .iter()
                .map(|report| report.root_process_id)
                .collect::<Vec<_>>(),
            sibling_reports
                .iter()
                .map(|report| report.root_process_id)
                .collect::<Vec<_>>(),
        );
        if policy.is_some() {
            assert!(
                sandbox
                    .call::<i32>("PrintOutput", "__exit_sandbox".to_owned())
                    .is_err()
            );
            assert!(sandbox.status().is_unrecoverable());
            assert!(sandbox.restore(snapshot).is_err());
        }
        drop(sandbox);
        for root in &observed {
            root.assert_released();
        }
        replacement.assert_released();
        assert_eq!(fresh.call::<i32>("Add", (37_i32, 5_i32)).unwrap(), 42);
        drop(fresh);
        for root in &sibling_roots {
            root.assert_released();
        }
    }

    #[test]
    #[ignore = "requires the explicitly compiled HYPERLIGHT_WINDOWS_CONFINEMENT_WORKER"]
    fn whole_tree_kill_preserves_independent_sibling() {
        let bytes = fixture_bytes();
        let mut first = resources(&bytes, false);
        let mut second = resources(&bytes, false);
        let first_root = spawn(&first, &["tree".into()]).unwrap();
        let second_root = spawn(&second, &["idle".into()]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while first.job.active_processes().unwrap() < 2 {
            assert!(
                first_root.try_wait().unwrap().is_none(),
                "Tree child could not start"
            );
            assert!(
                Instant::now() < deadline,
                "Tree child did not join its confinement job"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        // Root-only termination demonstrably leaves a descendant.
        first_root.kill(1).unwrap();
        wait_root(&first_root);
        drop(first_root);
        assert_eq!(first.job.active_processes().unwrap(), 1);
        first.cleanup().unwrap();
        assert_eq!(first.job.active_processes().unwrap(), 0);
        assert!(second_root.try_wait().unwrap().is_none());
        assert_eq!(second.job.active_processes().unwrap(), 1);
        second.terminate_tree(Duration::from_secs(5)).unwrap();
        wait_root(&second_root);
        second.cleanup().unwrap();
    }

    #[test]
    fn invalid_executable_fails_before_workload_and_cleans_staging() {
        let mut worker = resources(b"not an executable", true);
        let image = worker
            .image
            .as_ref()
            .unwrap()
            .directory
            .as_ref()
            .unwrap()
            .path()
            .to_owned();
        assert!(spawn(&worker, &[]).is_err());
        assert!(
            spawn(&worker, &[])
                .err()
                .unwrap()
                .to_string()
                .contains("another process")
        );
        assert_eq!(worker.job.active_processes().unwrap(), 0);
        worker.cleanup().unwrap();
        assert!(!image.exists());
        assert!(worker.container.is_none());
    }
}
