/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use core::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crossbeam_channel::{Receiver, Sender, TryRecvError, unbounded};
use rust_embed::RustEmbed;
use tracing::{Span, error, info, instrument, warn};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectA, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA,
};
use windows::core::PCSTR;

use super::surrogate_process::SurrogateProcess;
use super::wrappers::{HandleWrapper, PSTRWrapper};
use crate::HyperlightError::WindowsAPIError;
use crate::{Result, log_then_return, new_error};

// Use the rust-embed crate to embed the hyperlights_surrogate.exe
// binary in the hyperlight-host library to make dependency management easier.
// $HYPERLIGHT_SURROGATE_DIR is set by hyperlight-host's build.rs script.
// https://docs.rs/rust-embed/latest/rust_embed/
#[derive(RustEmbed)]
#[folder = "$HYPERLIGHT_SURROGATE_DIR"]
#[include = "hyperlight_surrogate.exe"]
struct Asset;

/// The name of the embedded surrogate asset (used as the key for `Asset::get`).
const EMBEDDED_SURROGATE_NAME: &str = "hyperlight_surrogate.exe";

/// The absolute hard limit on surrogate processes imposed by the
/// `WHvMapGpaRange2` API (512 process handles per calling process).
const HARD_MAX_SURROGATE_PROCESSES: usize = 512;

/// Environment variable controlling how many surrogate processes are
/// pre-created when the manager starts. Must be between 1 and
/// `HARD_MAX_SURROGATE_PROCESSES` (512). Defaults to 512 if unset.
const INITIAL_SURROGATES_ENV_VAR: &str = "HYPERLIGHT_INITIAL_SURROGATES";

/// Environment variable controlling the maximum number of surrogate processes
/// that can exist (including those created on demand). Must be >=
/// `HYPERLIGHT_INITIAL_SURROGATES` and <= `HARD_MAX_SURROGATE_PROCESSES`
/// (512). Defaults to 512 if unset.
const MAX_SURROGATES_ENV_VAR: &str = "HYPERLIGHT_MAX_SURROGATES";

/// Returns the on-disk filename for the surrogate binary, incorporating the
/// first 8 hex characters of the BLAKE3 hash of the embedded binary so that
/// different hyperlight versions produce different filenames and can coexist
/// without file-deletion races.
fn surrogate_binary_name() -> Result<String> {
    let exe = Asset::get(EMBEDDED_SURROGATE_NAME)
        .ok_or_else(|| new_error!("could not find embedded surrogate binary"))?;
    let hash = blake3::hash(exe.data.as_ref());
    let short_hash = &hash.to_hex()[..8];
    Ok(format!("hyperlight_surrogate_{short_hash}.exe"))
}

/// Pure validation/clamping logic for surrogate process counts.
///
/// `raw_initial` and `raw_max` are the parsed values from the environment
/// (or `None` when the variable is unset or unparsable).
///
/// Resolution order:
/// 1. `max` is clamped to `1..=HARD_MAX_SURROGATE_PROCESSES`, defaulting
///    to `HARD_MAX_SURROGATE_PROCESSES` when `None`.
/// 2. `initial` is clamped to `1..=max`, defaulting to `max` when `None`.
///    This guarantees `initial <= max` without an extra conditional.
fn compute_surrogate_counts(raw_initial: Option<usize>, raw_max: Option<usize>) -> (usize, usize) {
    let max = raw_max
        .map(|n| n.clamp(1, HARD_MAX_SURROGATE_PROCESSES))
        .unwrap_or(HARD_MAX_SURROGATE_PROCESSES);

    // Clamp initial to 1..=max so it can never exceed the authoritative limit.
    let initial = raw_initial.map(|n| n.clamp(1, max)).unwrap_or(max);

    (initial, max)
}

/// Returns the (initial, max) surrogate process counts from environment
/// variables, applying validation and clamping.
///
/// - `HYPERLIGHT_INITIAL_SURROGATES`: clamped to `1..=max`, default `max`.
/// - `HYPERLIGHT_MAX_SURROGATES`: clamped to `1..=512`, default 512.
fn surrogate_process_counts() -> (usize, usize) {
    let raw_initial = std::env::var(INITIAL_SURROGATES_ENV_VAR)
        .ok()
        .and_then(|v| v.parse::<usize>().ok());
    let raw_max = std::env::var(MAX_SURROGATES_ENV_VAR)
        .ok()
        .and_then(|v| v.parse::<usize>().ok());

    let (initial, max) = compute_surrogate_counts(raw_initial, raw_max);

    // Log clamping warnings here (not in the pure function) so the
    // messages can reference the env var names that provide context.
    if let Some(n) = raw_initial
        && n != initial
    {
        warn!("{INITIAL_SURROGATES_ENV_VAR}={n} was clamped to {initial}");
    }
    if let Some(n) = raw_max
        && n != max
    {
        warn!("{MAX_SURROGATES_ENV_VAR}={n} was clamped to {max}");
    }

    (initial, max)
}

/// `SurrogateProcessManager` manages hyperlight_surrogate processes. These
/// processes are required to allow multiple WHP Partitions to be created in a
/// single process.
///
/// The API WHvMapGpaRange
/// (https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvmapgparange)
/// returns the following error when called more than once from the same
/// process:
///
/// "Cannot create the partition for the virtualization infrastructure driver
/// because another partition with the same name already exists. (0xC0370008)
/// ERROR_VID_PARTITION_ALREADY_EXISTS"
///
/// There is, however, another API (WHvMapGpaRange2) that has a second
/// parameter which is a handle to a process. This process merely has to exist,
/// the memory being mapped from the host to the virtual machine is
/// allocated/freed  in this process using CreateFileMapping/MapViewOfFile.
/// Memory for the HyperVisor partition is copied to and from the host process
/// from/into the surrogate process in Sandbox before and after the VCPU is run.
///
/// This struct deals with the creation/destruction of these surrogate
/// processes (hyperlight_surrogate.exe) , pooling of the process handles, the
/// distribution of these handles from the pool to a Hyperlight Sandbox
/// instance and the return of the handle to the pool once a Sandbox instance
/// is destroyed, it also allocates and frees memory in the surrogate process
/// on allocation/return to/from a Sandbox instance.
/// It is intended to be used as a singleton and is thread safe.
///
/// There is a limit of 512 partitions per process. By default 512 processes
/// are pre-created at startup, but this can be reduced via
/// `HYPERLIGHT_INITIAL_SURROGATES`. Additional processes are created on
/// demand up to the limit set by `HYPERLIGHT_MAX_SURROGATES` (also
/// defaulting to 512). If the pool is empty and the max has been reached,
/// callers will block until a process is returned.
///
/// This class is `Send + Sync`, and internally manages the pool of
/// surrogate processes in a concurrency-safe way.
pub(crate) struct SurrogateProcessManager {
    job_handle: HandleWrapper,
    /// `process_receiver` and `process_sender` allow us to synchronize the
    /// operations of reserving a surrogate process from the pool, or
    /// returning a surrogate process to the pool.
    ///
    /// Note these are `crossbeam_queue` types rather than the roughly
    /// equivalent and identically-named `std::sync::mpsc` ones. The former
    /// are `Send + Sync`, while the latter are `Send + !Sync`. We need
    /// both `Send + Sync` so we can do the following:
    ///
    /// - Embed this type into `SurrogateProcess`
    ///     - Required so `SurrogateProcess`es can drop themselves by
    ///       returning themselves to the originating `SurrogateProcessManager`
    /// - ... `SurrogateProcess`es are stored within `HypervWindowsDriver`s
    /// - ... and `HypervWindowsDriver`s must `impl Hypervisor`
    /// - ... and the `Hypervisor` trait requires `Send + Sync`
    process_receiver: Receiver<HandleWrapper>,
    process_sender: Sender<HandleWrapper>,
    /// Path to the on-disk surrogate binary (hash-stamped).
    surrogate_process_path: PathBuf,
    /// Maximum number of surrogate processes allowed to exist.
    max_processes: usize,
    /// Number of surrogate processes that have been created so far.
    /// Used to decide whether we can spawn more on demand.
    created_count: AtomicUsize,
}

impl SurrogateProcessManager {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn new() -> Result<Self> {
        let binary_name = surrogate_binary_name()?;
        ensure_surrogate_process_exe(&binary_name)?;
        let surrogate_process_path = get_surrogate_process_dir()?.join(&binary_name);

        let (initial, max) = surrogate_process_counts();

        let (sender, receiver) = unbounded();
        let job_handle = create_job_object()?;
        let surrogate_process_manager = SurrogateProcessManager {
            job_handle,
            process_receiver: receiver,
            process_sender: sender,
            surrogate_process_path,
            max_processes: max,
            created_count: AtomicUsize::new(0),
        };

        surrogate_process_manager.create_initial_surrogate_processes(initial)?;

        Ok(surrogate_process_manager)
    }
    /// Gets a surrogate process from the pool. If the pool is empty and
    /// fewer than `max_processes` have been created, a new process is
    /// spawned on demand. If the pool is empty and the maximum has been
    /// reached, this call blocks until a process is returned.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_surrogate_process(&self) -> Result<SurrogateProcess> {
        // Fast path: try to grab an already-pooled process.
        match self.process_receiver.try_recv() {
            Ok(handle) => {
                let surrogate_process_handle: HANDLE = handle.into();
                return Ok(SurrogateProcess::new(surrogate_process_handle));
            }
            Err(TryRecvError::Empty) => {
                // Pool is empty — try to grow on demand below.
            }
            Err(TryRecvError::Disconnected) => {
                return Err(new_error!("surrogate process channel disconnected"));
            }
        }

        // On-demand growth: atomically claim a slot if one is available.
        // We use a CAS loop so that concurrent callers don't overshoot
        // the maximum.
        loop {
            let current = self.created_count.load(Ordering::Acquire);
            if current >= self.max_processes {
                // At the limit — fall through to the blocking recv below.
                break;
            }
            if self
                .created_count
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                info!(
                    "on-demand surrogate process creation ({}/{})",
                    current + 1,
                    self.max_processes
                );
                let handle =
                    match create_surrogate_process(&self.surrogate_process_path, self.job_handle) {
                        Ok(h) => h,
                        Err(e) => {
                            // Rollback the slot claim so capacity isn't
                            // permanently lost on transient failures.
                            self.created_count.fetch_sub(1, Ordering::AcqRel);
                            return Err(e);
                        }
                    };
                let surrogate_process_handle: HANDLE = handle.into();
                return Ok(SurrogateProcess::new(surrogate_process_handle));
            }
            // CAS failed — another thread beat us; retry.
        }

        // Maximum reached — block until a process is returned to the pool.
        let surrogate_process_handle: HANDLE = self.process_receiver.recv()?.into();
        Ok(SurrogateProcess::new(surrogate_process_handle))
    }

    /// Returns a surrogate process to the pool of surrogate processes.
    /// This should be called from within a surrogate process's drop
    /// implementation, after process resources have been freed.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn return_surrogate_process(&self, proc_handle: HandleWrapper) -> Result<()> {
        Ok(self.process_sender.send(proc_handle)?)
    }

    /// Pre-creates the initial batch of surrogate processes at startup.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn create_initial_surrogate_processes(&self, initial_count: usize) -> Result<()> {
        info!(
            "pre-creating {} surrogate processes ({}={:?}, {}={:?})",
            initial_count,
            INITIAL_SURROGATES_ENV_VAR,
            std::env::var(INITIAL_SURROGATES_ENV_VAR).ok(),
            MAX_SURROGATES_ENV_VAR,
            std::env::var(MAX_SURROGATES_ENV_VAR).ok(),
        );
        for _ in 0..initial_count {
            let surrogate_process =
                create_surrogate_process(&self.surrogate_process_path, self.job_handle)?;
            self.process_sender.send(surrogate_process)?;
            self.created_count.fetch_add(1, Ordering::AcqRel);
        }

        Ok(())
    }
}

impl Drop for SurrogateProcessManager {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn drop(&mut self) {
        let handle: HANDLE = self.job_handle.into();
        if unsafe {
            // Terminating the job object will terminate all the surrogate
            // processes.

            TerminateJobObject(handle, 0)
        }
        .is_err()
        {
            error!("surrogate job objects were not all terminated");
        }
    }
}

lazy_static::lazy_static! {
    // see the large comment inside `SurrogateProcessManager` describing
    // our reasoning behind using `lazy_static`.
    static ref SURROGATE_PROCESSES_MANAGER: std::result::Result<SurrogateProcessManager, &'static str> =
        match SurrogateProcessManager::new() {
            Ok(manager) => Ok(manager),
            Err(e) => {
                error!("Failed to create SurrogateProcessManager: {:?}", e);
                Err("Failed to create SurrogateProcessManager")
            }
        };
}

/// Gets the singleton SurrogateProcessManager. This should be called when a new HyperV on Windows Driver is created.
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn get_surrogate_process_manager() -> Result<&'static SurrogateProcessManager> {
    match &*SURROGATE_PROCESSES_MANAGER {
        Ok(manager) => Ok(manager),
        Err(e) => {
            error!("Failed to get SurrogateProcessManager: {:?}", e);
            Err(new_error!("Failed to get SurrogateProcessManager {}", e))
        }
    }
}

// Creates a job object that will terminate all the surrogate processes when the struct instance is dropped.
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
fn create_job_object() -> Result<HandleWrapper> {
    let security_attributes: SECURITY_ATTRIBUTES = Default::default();

    let job_object = unsafe { CreateJobObjectA(Some(&security_attributes), PCSTR::null())? };

    let mut job_object_information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
            LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            ..Default::default()
        },
        ..Default::default()
    };
    let job_object_information_ptr: *mut c_void =
        &mut job_object_information as *mut _ as *mut c_void;
    if let Err(e) = unsafe {
        SetInformationJobObject(
            job_object,
            JobObjectExtendedLimitInformation,
            job_object_information_ptr,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } {
        log_then_return!(WindowsAPIError(e.clone()));
    }

    Ok(job_object.into())
}

#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
fn get_surrogate_process_dir() -> Result<PathBuf> {
    let binding = std::env::current_exe()?;
    let path = binding
        .parent()
        .ok_or_else(|| new_error!("could not get parent directory of current executable"))?;

    Ok(path.to_path_buf())
}

/// Ensures the surrogate binary exists on disk at the hash-stamped path.
///
/// Because the filename embeds the content hash, two different hyperlight
/// versions will write to *different* files. This avoids the
/// delete-while-running race that occurred when an older version's running
/// processes held a lock on the same filename.
///
/// Uses `File::create_new` for atomic create-or-fail semantics, avoiding
/// a TOCTOU race with `exists()` + `create()`. If the write fails after
/// creating the file, the partial file is deleted so future runs do not
/// mistake it for a valid binary.
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
fn ensure_surrogate_process_exe(binary_name: &str) -> Result<()> {
    let dir = get_surrogate_process_dir()?;
    let surrogate_process_path = dir.join(binary_name);

    // Resolve the embedded asset before touching the filesystem so a
    // missing asset can't leave a zero-byte ghost file on disk.
    let exe = Asset::get(EMBEDDED_SURROGATE_NAME)
        .ok_or_else(|| new_error!("could not find embedded surrogate binary"))?;

    // Atomic create-or-fail: if the file already exists, `create_new`
    // returns `AlreadyExists` and we skip extraction. The filename
    // embeds the content hash, so an existing file is guaranteed to
    // have the correct content.
    match File::create_new(&surrogate_process_path) {
        Ok(mut f) => {
            info!(
                "{} does not exist, extracting to {}",
                binary_name,
                &surrogate_process_path.display()
            );

            if let Err(e) = f.write_all(exe.data.as_ref()) {
                // Clean up the partial file so future runs don't skip
                // extraction thinking a valid binary is already present.
                // Drop the file handle first — on Windows, open handles
                // prevent deletion.
                drop(f);
                let _ = std::fs::remove_file(&surrogate_process_path);
                return Err(e.into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another thread/process already extracted the file — nothing to do.
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}

/// Creates a surrogate process and adds it to the job object.
/// Process is created suspended, its only used as a host for memory
/// the memory is allocated and freed when the process is returned to the pool.
/// The process memory is written to before and read after running the virtual
/// processor in the HyperV partition.
/// All manipulation of the memory is done in memory allocated to the Sandbox
/// which is then copied to and from the surrogate process.
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
fn create_surrogate_process(
    surrogate_process_path: &Path,
    job_handle: HandleWrapper,
) -> Result<HandleWrapper> {
    let mut process_information: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let process_attributes: SECURITY_ATTRIBUTES = Default::default();
    let thread_attributes: SECURITY_ATTRIBUTES = Default::default();
    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let cmd_line = surrogate_process_path.to_str().ok_or(new_error!(
        "failed to convert surrogate process path to a string"
    ))?;
    let p_cmd_line = &PSTRWrapper::try_from(cmd_line)?;

    if let Err(e) = unsafe {
        CreateProcessA(
            PCSTR::null(),
            Some(p_cmd_line.into()),
            Some(&process_attributes),
            Some(&thread_attributes),
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &startup_info,
            &mut process_information,
        )
    } {
        log_then_return!(WindowsAPIError(e.clone()));
    }

    let job_handle: HANDLE = job_handle.into();
    let process_handle: HANDLE = process_information.hProcess;
    unsafe {
        if let Err(e) = AssignProcessToJobObject(job_handle, process_handle) {
            log_then_return!(WindowsAPIError(e.clone()));
        }
    }

    Ok(process_handle.into())
}
#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::thread;
    use std::time::{Duration, Instant};

    use rand::{RngExt, rng};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::JobObjects::IsProcessInJob;
    use windows_result::BOOL;

    use super::*;
    use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};
    #[test]
    fn test_surrogate_process_manager() {
        let mut threads = Vec::new();
        // create more threads than surrogate processes as we want to test that
        // the manager can handle multiple threads requesting processes at the
        // same time when there are not enough processes available.
        let surrogate_process_manager = get_surrogate_process_manager().unwrap();
        let max_processes = surrogate_process_manager.max_processes;
        for t in 0..max_processes * 2 {
            let thread_handle = thread::spawn(move || -> Result<()> {
                let surrogate_process_manager_res = get_surrogate_process_manager();
                let mut rng = rng();
                assert!(surrogate_process_manager_res.is_ok());
                let surrogate_process_manager = surrogate_process_manager_res.unwrap();
                let job_handle = surrogate_process_manager.job_handle;
                // for each of the parent loop iterations, try to get a
                // surrogate process, make sure we actually got one,
                // then put it back
                for p in 0..max_processes {
                    let timer = Instant::now();
                    let surrogate_process = {
                        let res = surrogate_process_manager.get_surrogate_process()?;
                        let elapsed = timer.elapsed();
                        // Print out the time it took to get the process if its greater than 150ms (this is just to allow us to see that threads are blocking on the process queue)
                        if (elapsed.as_millis() as u64) > 150 {
                            println!("Get Process Time Thread {} Process {}: {:?}", t, p, elapsed);
                        }
                        res
                    };

                    let mut result: BOOL = Default::default();
                    let process_handle: HANDLE = surrogate_process.process_handle.into();
                    let job_handle: HANDLE = job_handle.into();
                    unsafe {
                        assert!(
                            IsProcessInJob(process_handle, Some(job_handle), &mut result).is_ok()
                        );
                        assert!(result.as_bool());
                    }

                    // in real use the process will not get returned immediately
                    let n: u64 = rng.random_range(1..16);
                    thread::sleep(Duration::from_millis(n));
                    // dropping the surrogate process, as we do in the line
                    // below, will return it to the surrogate process manager
                    drop(surrogate_process);
                }
                Ok(())
            });
            threads.push(thread_handle);
        }

        for thread_handle in threads {
            assert!(thread_handle.join().is_ok());
        }

        assert_number_of_surrogate_processes(max_processes);
    }

    #[track_caller]
    fn assert_number_of_surrogate_processes(expected_count: usize) {
        const MAX_RETRIES: u32 = 30;
        let mut attempt = 0;
        loop {
            let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
            assert!(snapshot_handle.is_ok());
            let snapshot_handle = snapshot_handle.unwrap();
            let mut process_entry = PROCESSENTRY32 {
                dwSize: size_of::<PROCESSENTRY32>() as u32,
                ..Default::default()
            };
            let mut result = unsafe { Process32First(snapshot_handle, &mut process_entry).is_ok() };
            let mut count = 0;
            while result {
                if let Ok(process_name) =
                    unsafe { CStr::from_ptr(process_entry.szExeFile.as_ptr()).to_str() }
                    && process_name.starts_with("hyperlight_surrogate_")
                    && process_name.ends_with(".exe")
                {
                    count += 1;
                }

                unsafe {
                    result = Process32Next(snapshot_handle, &mut process_entry).is_ok();
                }
            }

            // When waiting for processes to exit (expected_count == 0),
            // retry with a delay since termination isn't instantaneous.
            attempt += 1;
            if expected_count == 0 && count > 0 && attempt < MAX_RETRIES {
                thread::sleep(Duration::from_secs(1));
            } else {
                assert_eq!(count, expected_count);
                break;
            }
        }
    }

    #[test]
    fn windows_guard_page() {
        // NOTE, functions like ReadProcessMemory do not trigger guard pages, the function fails instead
        const SIZE: usize = 4096;
        let mgr = get_surrogate_process_manager().unwrap();
        let mem = ExclusiveSharedMemory::new(SIZE).unwrap();

        let mut process = mgr.get_surrogate_process().unwrap();
        let surrogate_address = process
            .map(
                HandleWrapper::from(mem.get_mmap_file_handle()),
                mem.raw_ptr() as usize,
                mem.raw_mem_size(),
                &crate::mem::memory_region::SurrogateMapping::SandboxMemory,
            )
            .unwrap();

        let buffer = vec![0u8; SIZE];
        let bytes_read: Option<*mut usize> = None;
        let process_handle: HANDLE = process.process_handle.into();

        unsafe {
            // read the first guard page, should fail
            let success = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                surrogate_address,
                buffer.as_ptr() as *mut c_void,
                SIZE,
                bytes_read,
            );
            assert!(success.is_err());

            // read the memory, should be OK
            let success = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                surrogate_address.wrapping_add(SIZE),
                buffer.as_ptr() as *mut c_void,
                SIZE,
                bytes_read,
            );
            assert!(success.is_ok());

            // read the second guard page, should fail
            let success = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                surrogate_address.wrapping_add(2 * SIZE),
                buffer.as_ptr() as *mut c_void,
                SIZE,
                bytes_read,
            );
            assert!(success.is_err());
        }
    }

    /// Tests that [`SurrogateMapping::ReadOnlyFile`] skips guard pages entirely.
    ///
    /// When mapping with `ReadOnlyFile`, the first and last pages should be
    /// accessible (no `PAGE_NOACCESS` guard pages set), unlike `SandboxMemory`
    /// which marks them as guard pages.
    #[test]
    fn readonly_file_mapping_skips_guard_pages() {
        const SIZE: usize = 4096;
        let mgr = get_surrogate_process_manager().unwrap();
        let mem = ExclusiveSharedMemory::new(SIZE).unwrap();

        let mut process = mgr.get_surrogate_process().unwrap();
        let surrogate_address = process
            .map(
                HandleWrapper::from(mem.get_mmap_file_handle()),
                mem.raw_ptr() as usize,
                mem.raw_mem_size(),
                &crate::mem::memory_region::SurrogateMapping::ReadOnlyFile,
            )
            .unwrap();

        let buffer = vec![0u8; SIZE];
        let bytes_read: Option<*mut usize> = None;
        let process_handle: HANDLE = process.process_handle.into();

        unsafe {
            // read the first page — should succeed (no guard page for ReadOnlyFile)
            let success = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                surrogate_address,
                buffer.as_ptr() as *mut c_void,
                SIZE,
                bytes_read,
            );
            assert!(
                success.is_ok(),
                "First page should be readable with ReadOnlyFile (no guard page)"
            );

            // read the middle page — should also succeed
            let success = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                surrogate_address.wrapping_add(SIZE),
                buffer.as_ptr() as *mut c_void,
                SIZE,
                bytes_read,
            );
            assert!(
                success.is_ok(),
                "Middle page should be readable with ReadOnlyFile"
            );

            // read the last page — should succeed (no guard page for ReadOnlyFile)
            let success = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                surrogate_address.wrapping_add(2 * SIZE),
                buffer.as_ptr() as *mut c_void,
                SIZE,
                bytes_read,
            );
            assert!(
                success.is_ok(),
                "Last page should be readable with ReadOnlyFile (no guard page)"
            );
        }
    }

    /// Tests that the reference counting in [`SurrogateProcess::map`] works
    /// correctly — repeated maps to the same `host_base` increment the count
    /// and return the same surrogate address, regardless of the mapping type
    /// passed on subsequent calls.
    #[test]
    fn surrogate_map_ref_counting() {
        let mgr = get_surrogate_process_manager().unwrap();
        let mem = ExclusiveSharedMemory::new(4096).unwrap();

        let mut process = mgr.get_surrogate_process().unwrap();
        let handle = HandleWrapper::from(mem.get_mmap_file_handle());
        let host_base = mem.raw_ptr() as usize;
        let host_size = mem.raw_mem_size();

        // First map — creates the mapping
        let addr1 = process
            .map(
                handle,
                host_base,
                host_size,
                &crate::mem::memory_region::SurrogateMapping::SandboxMemory,
            )
            .unwrap();

        // Second map — should reuse (ref count incremented)
        let addr2 = process
            .map(
                handle,
                host_base,
                host_size,
                &crate::mem::memory_region::SurrogateMapping::SandboxMemory,
            )
            .unwrap();

        assert_eq!(
            addr1, addr2,
            "Repeated map should return the same surrogate address"
        );

        // First unmap — decrements ref count but should NOT actually unmap
        process.unmap(host_base);

        // The mapping should still be present (ref count was 2, now 1)
        assert!(
            process.mappings.contains_key(&host_base),
            "Mapping should still exist after first unmap (ref count > 0)"
        );

        // Second unmap — ref count hits 0, actually unmaps
        process.unmap(host_base);
        assert!(
            !process.mappings.contains_key(&host_base),
            "Mapping should be removed after ref count reaches 0"
        );
    }

    /// Tests `ensure_surrogate_process_exe` for:
    /// 1. Correct extraction — file content matches the embedded binary.
    /// 2. Re-extraction after deletion — a missing file is recreated.
    /// 3. Idempotent when already present — second call succeeds without
    ///    error (exercises the `AlreadyExists` fast path).
    /// 4. Deterministic naming — same embedded binary always produces
    ///    the same hash-stamped filename.
    ///
    /// Uses a test-specific filename to avoid conflicting with the
    /// singleton's surrogate processes, which hold a PE loader lock
    /// on the real hash-stamped exe.
    #[test]
    fn test_ensure_surrogate_exe() {
        let test_binary_name = "hyperlight_surrogate_test_extraction.exe";
        let dir = get_surrogate_process_dir().expect("should get surrogate dir");
        let path = dir.join(test_binary_name);

        // Ensure a clean slate.
        let _ = std::fs::remove_file(&path);

        // --- First call: extracts the binary ---
        ensure_surrogate_process_exe(test_binary_name).expect("first call should succeed");
        assert!(path.exists(), "binary should exist after extraction");

        // --- Verify extracted content matches embedded binary ---
        let on_disk = std::fs::read(&path).expect("should read extracted file");
        let embedded = Asset::get(EMBEDDED_SURROGATE_NAME).expect("embedded asset should exist");
        assert_eq!(
            on_disk,
            embedded.data.as_ref(),
            "extracted file content should match embedded binary"
        );

        // --- Second call: file exists, should skip (AlreadyExists path) ---
        ensure_surrogate_process_exe(test_binary_name)
            .expect("second call should succeed when file already exists");

        // --- Delete and re-extract ---
        std::fs::remove_file(&path).expect("should be able to delete test binary");
        assert!(!path.exists(), "binary should be gone after deletion");

        ensure_surrogate_process_exe(test_binary_name)
            .expect("should succeed re-extracting after deletion");
        assert!(path.exists(), "binary should be re-created after deletion");

        // Clean up test artifact.
        let _ = std::fs::remove_file(&path);

        // --- Verify deterministic naming ---
        let binary_name = surrogate_binary_name().expect("should succeed");
        let binary_name_2 = surrogate_binary_name().expect("second call should also succeed");
        assert_eq!(
            binary_name, binary_name_2,
            "surrogate_binary_name should be deterministic"
        );
    }

    /// Verifies `compute_surrogate_counts()` returns sensible defaults
    /// when inputs are `None`, and correct clamped values otherwise.
    ///
    /// This exercises the pure validation/clamping function directly,
    /// avoiding process-global env var mutation which previously caused
    /// a race with the `lazy_static` singleton initialisation in
    /// parallel test runs.
    #[test]
    fn test_compute_surrogate_counts() {
        // --- Both unset (or unparsable) → defaults ---
        let (initial, max) = compute_surrogate_counts(None, None);
        assert_eq!(
            initial, HARD_MAX_SURROGATE_PROCESSES,
            "default initial should be {HARD_MAX_SURROGATE_PROCESSES}"
        );
        assert_eq!(
            max, HARD_MAX_SURROGATE_PROCESSES,
            "default max should be {HARD_MAX_SURROGATE_PROCESSES}"
        );

        // --- Only initial set ---
        let (initial, max) = compute_surrogate_counts(Some(32), None);
        assert_eq!(initial, 32, "initial should honour provided value");
        assert_eq!(
            max, HARD_MAX_SURROGATE_PROCESSES,
            "max should default when unset"
        );

        // --- Both set, max > initial ---
        let (initial, max) = compute_surrogate_counts(Some(8), Some(64));
        assert_eq!(initial, 8);
        assert_eq!(max, 64);

        // --- Both set, max < initial → initial clamped DOWN to max ---
        let (initial, max) = compute_surrogate_counts(Some(100), Some(10));
        assert_eq!(max, 10, "max is authoritative and should not be inflated");
        assert_eq!(
            initial, 10,
            "initial should be clamped down to max when it exceeds it"
        );

        // --- initial below minimum → clamped to 1 ---
        let (initial, max) = compute_surrogate_counts(Some(0), None);
        assert_eq!(initial, 1, "initial should be clamped to minimum of 1");
        assert_eq!(
            max, HARD_MAX_SURROGATE_PROCESSES,
            "max should default when unset"
        );

        // --- initial above hard limit → clamped to 512 ---
        let (initial, max) = compute_surrogate_counts(Some(9999), None);
        assert_eq!(
            initial, HARD_MAX_SURROGATE_PROCESSES,
            "initial should be clamped to {HARD_MAX_SURROGATE_PROCESSES}"
        );
        assert_eq!(max, HARD_MAX_SURROGATE_PROCESSES);

        // --- Only max set → initial defaults then clamped down to max ---
        let (initial, max) = compute_surrogate_counts(None, Some(256));
        assert_eq!(max, 256, "max should honour provided value");
        assert_eq!(
            initial, 256,
            "initial should be clamped down to max when it defaults above it"
        );

        // --- max below minimum → clamped to 1, initial follows ---
        let (initial, max) = compute_surrogate_counts(None, Some(0));
        assert_eq!(max, 1, "max should be clamped to minimum of 1");
        assert_eq!(initial, 1, "initial should be clamped down to max");

        // --- max above hard limit → clamped to 512 ---
        let (initial, max) = compute_surrogate_counts(None, Some(9999));
        assert_eq!(
            max, HARD_MAX_SURROGATE_PROCESSES,
            "max should be clamped to {HARD_MAX_SURROGATE_PROCESSES}"
        );
        assert_eq!(initial, HARD_MAX_SURROGATE_PROCESSES);

        // --- Both at boundary values ---
        let (initial, max) = compute_surrogate_counts(Some(1), Some(1));
        assert_eq!(initial, 1);
        assert_eq!(max, 1);

        let (initial, max) = compute_surrogate_counts(
            Some(HARD_MAX_SURROGATE_PROCESSES),
            Some(HARD_MAX_SURROGATE_PROCESSES),
        );
        assert_eq!(initial, HARD_MAX_SURROGATE_PROCESSES);
        assert_eq!(max, HARD_MAX_SURROGATE_PROCESSES);
    }

    /// Smoke-tests `surrogate_process_counts()` with the default test
    /// environment (neither env var set). This does NOT mutate env vars —
    /// it just verifies the env-reading wrapper returns the expected
    /// defaults under normal conditions.
    #[test]
    fn test_surrogate_process_counts_defaults() {
        // In the standard CI / dev environment, neither HYPERLIGHT_INITIAL_SURROGATES
        // nor HYPERLIGHT_MAX_SURROGATES is set, so we expect the hard-max defaults.
        // If the env vars ARE set externally (e.g. a developer's shell), this test
        // gracefully adapts: it only asserts the invariant initial <= max <= 512.
        let (initial, max) = surrogate_process_counts();
        assert!(
            (1..=HARD_MAX_SURROGATE_PROCESSES).contains(&initial),
            "initial {initial} should be in 1..={HARD_MAX_SURROGATE_PROCESSES}"
        );
        assert!(
            (1..=HARD_MAX_SURROGATE_PROCESSES).contains(&max),
            "max {max} should be in 1..={HARD_MAX_SURROGATE_PROCESSES}"
        );
        assert!(initial <= max, "initial ({initial}) must be <= max ({max})");
    }
}
