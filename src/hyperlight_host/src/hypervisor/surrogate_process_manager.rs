/*
Copyright 2024 The Hyperlight Authors.

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

use crossbeam_channel::{unbounded, Receiver, Sender};
use hyperlight_common::mem::PAGE_SIZE_USIZE;
use rust_embed::RustEmbed;
use tracing::{error, info, instrument, Span};
use windows::core::{s, PCSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectA, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Memory::{
    MapViewOfFileNuma2, VirtualProtectEx, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::NUMA_NO_PREFERRED_NODE;
use windows::Win32::System::Threading::{
    CreateProcessA, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
};

use super::surrogate_process::SurrogateProcess;
use super::wrappers::{HandleWrapper, PSTRWrapper};
use crate::HyperlightError::WindowsAPIError;
use crate::{log_then_return, new_error, Result};

// Use the rust-embed crate to embed the hyperlights_surrogate.exe
// binary in the hyperlight-host library to make dependency management easier.
// $HYPERLIGHT_SURROGATE_DIR is set by hyperlight-host's build.rs script.
// https://docs.rs/rust-embed/latest/rust_embed/
#[derive(RustEmbed)]
#[folder = "$HYPERLIGHT_SURROGATE_DIR"]
#[include = "hyperlight_surrogate.exe"]
struct Asset;

/// This is the name of the surrogate process binary that will be used to create surrogate processes.
/// The process does nothing , it just sleeps forever. Its only purpose is to provide a host for memory that will be mapped
/// into the guest using the `WHvMapGpaRange2` API.
pub(crate) const SURROGATE_PROCESS_BINARY_NAME: &str = "hyperlight_surrogate.exe";

/// The maximum number of surrogate processes that can be created.
/// (This is a factor of limitations in the `WHvMapGpaRange2` API which only allows 512 different process handles).
const NUMBER_OF_SURROGATE_PROCESSES: usize = 512;

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
/// There is a limit of 512 partitions per process therefore this class will
/// create a maximum of 512 processes, and if the pool is empty when a Sandbox
/// is created it will wait for a free process.
///
/// This class is `Send + Sync`, and internally manages the pool of 512
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
}

impl SurrogateProcessManager {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn new() -> Result<Self> {
        ensure_surrogate_process_exe()?;
        let surrogate_process_path =
            get_surrogate_process_dir()?.join(SURROGATE_PROCESS_BINARY_NAME);

        let (sender, receiver) = unbounded();
        let job_handle = create_job_object()?;
        let surrogate_process_manager = SurrogateProcessManager {
            job_handle,
            process_receiver: receiver,
            process_sender: sender,
        };

        surrogate_process_manager
            .create_surrogate_processes(&surrogate_process_path, job_handle)?;
        Ok(surrogate_process_manager)
    }
    /// Gets a surrogate process from the pool of surrogate processes and
    /// allocates memory in the process. This should be called when a new
    /// HyperV on Windows Driver is created.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_surrogate_process(
        &self,
        raw_size: usize,
        raw_source_address: *const c_void,
        mmap_file_handle: HandleWrapper,
    ) -> Result<SurrogateProcess> {
        let surrogate_process_handle: HANDLE = self.process_receiver.recv()?.into();
        let mapping_file_handle: HANDLE = mmap_file_handle.into();

        // Allocate the memory by creating a view over the memory mapped file

        // Use MapViewOfFile2 to map memoy into the surrogate process, the MapViewOfFile2 API is implemented in as an inline function in a windows header file
        // (see https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile2#remarks) so we use the same API it uses in the header file here instead of
        // MapViewOfFile2 which does not exist in the rust crate (see https://github.com/microsoft/windows-rs/issues/2595)
        let allocated_address = unsafe {
            MapViewOfFileNuma2(
                mapping_file_handle,
                surrogate_process_handle,
                0,
                Some(raw_source_address),
                raw_size,
                0,
                PAGE_READWRITE.0,
                NUMA_NO_PREFERRED_NODE,
            )
        };

        if allocated_address.Value.is_null() {
            // Safety: `MapViewOfFileNuma2` will set the last error code if it fails.
            let error = unsafe { windows::Win32::Foundation::GetLastError() };
            log_then_return!(
                "MapViewOfFileNuma2 failed with error code: {:?} for mem address {:?} ",
                error,
                raw_source_address
            );
        }

        if allocated_address.Value as *const c_void != raw_source_address {
            log_then_return!(
                "Address Mismatch Allocated: {:?} Requested: {:?}",
                allocated_address.Value,
                raw_source_address
            );
        }

        // set up guard pages

        // If the following calls to VirtualProtectEx are changed make sure to update the calls to VirtualProtect in shared_mem.rs

        let mut unused_out_old_prot_flags = PAGE_PROTECTION_FLAGS(0);

        // the first page of the raw_size is the guard page
        let first_guard_page_start = raw_source_address;
        if let Err(e) = unsafe {
            VirtualProtectEx(
                surrogate_process_handle,
                first_guard_page_start,
                PAGE_SIZE_USIZE,
                PAGE_NOACCESS,
                &mut unused_out_old_prot_flags,
            )
        } {
            log_then_return!(WindowsAPIError(e.clone()));
        }

        // the last page of the raw_size is the guard page
        let last_guard_page_start = unsafe { raw_source_address.add(raw_size - PAGE_SIZE_USIZE) };
        if let Err(e) = unsafe {
            VirtualProtectEx(
                surrogate_process_handle,
                last_guard_page_start,
                PAGE_SIZE_USIZE,
                PAGE_NOACCESS,
                &mut unused_out_old_prot_flags,
            )
        } {
            log_then_return!(WindowsAPIError(e.clone()));
        }

        Ok(SurrogateProcess::new(
            allocated_address.Value,
            surrogate_process_handle,
        ))
    }

    /// Returns a surrogate process to the pool of surrogate processes.
    /// This should be called from within a surrogate process's drop
    /// implementation, after process resources have been freed.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn return_surrogate_process(&self, proc_handle: HandleWrapper) -> Result<()> {
        Ok(self.process_sender.clone().send(proc_handle)?)
    }

    /// Creates all the surrogate process when the struct is first created.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn create_surrogate_processes(
        &self,
        surrogate_process_path: &Path,
        job_handle: HandleWrapper,
    ) -> Result<()> {
        for _ in 0..NUMBER_OF_SURROGATE_PROCESSES {
            let surrogate_process = create_surrogate_process(surrogate_process_path, job_handle)?;
            self.process_sender.clone().send(surrogate_process)?;
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

    let job_object = unsafe {
        CreateJobObjectA(
            Some(&security_attributes),
            s!("HyperlightSurrogateJobObject"),
        )?
    };

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

#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
fn ensure_surrogate_process_exe() -> Result<()> {
    let surrogate_process_path = get_surrogate_process_dir()?.join(SURROGATE_PROCESS_BINARY_NAME);
    let p = Path::new(&surrogate_process_path);

    let exe = Asset::get(SURROGATE_PROCESS_BINARY_NAME)
        .ok_or_else(|| new_error!("could not find embedded surrogate binary"))?;

    if p.exists() {
        // check to see if sha's match and if not delete the file so we'll extract
        // the embedded file below.
        let embedded_file_sha = sha256::digest(exe.data.as_ref());
        let file_on_disk_sha = sha256::try_digest(&p)?;

        if embedded_file_sha != file_on_disk_sha {
            println!(
                "sha of embedded surrogate '{}' does not match sha of file on disk '{}' - deleting surrogate binary at {}",
                embedded_file_sha,
                file_on_disk_sha,
                &surrogate_process_path.display()
            );
            std::fs::remove_file(p)?;
        }
    }

    if !p.exists() {
        info!(
            "{} does not exist, copying to {}",
            SURROGATE_PROCESS_BINARY_NAME,
            &surrogate_process_path.display()
        );

        let mut f = File::create(&surrogate_process_path)?;
        f.write_all(exe.data.as_ref())?;
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

    use hyperlight_common::mem::PAGE_SIZE_USIZE;
    use rand::{rng, Rng};
    use serial_test::serial;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::JobObjects::IsProcessInJob;
    use windows::Win32::System::Memory::{
        CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS, PAGE_READWRITE,
        SEC_COMMIT,
    };
    use windows_result::BOOL;

    use super::*;
    use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};
    #[test]
    #[serial]
    fn test_surrogate_process_manager() {
        let mut threads = Vec::new();
        // create more threads than surrogate processes as we want to test that
        // the manager can handle multiple threads requesting processes at the
        // same time when there are not enough processes available.
        for t in 0..NUMBER_OF_SURROGATE_PROCESSES * 2 {
            let thread_handle = thread::spawn(move || -> Result<()> {
                let surrogate_process_manager_res = get_surrogate_process_manager();
                let mut rng = rng();
                let size = PAGE_SIZE_USIZE * 3;
                assert!(surrogate_process_manager_res.is_ok());
                let surrogate_process_manager = surrogate_process_manager_res.unwrap();
                let job_handle = surrogate_process_manager.job_handle;
                // for each of the parent loop iterations, try to get a
                // surrogate process, make sure we actually got one,
                // then put it back
                for p in 0..NUMBER_OF_SURROGATE_PROCESSES {
                    let dwmaximumsizehigh = 0;
                    let dwmaximumsizelow = (size & 0xFFFFFFFF) as u32;
                    let handle = unsafe {
                        CreateFileMappingA(
                            INVALID_HANDLE_VALUE, // Causes the page file to be used as the backing store
                            None,
                            PAGE_READWRITE | SEC_COMMIT,
                            dwmaximumsizehigh,
                            dwmaximumsizelow,
                            PCSTR::null(),
                        )
                        .unwrap()
                    };

                    let addr = unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, 0) };

                    let timer = Instant::now();
                    let surrogate_process = {
                        let res = surrogate_process_manager.get_surrogate_process(
                            size,
                            addr.Value,
                            HandleWrapper::from(handle),
                        )?;
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
                    let res = unsafe { UnmapViewOfFile(addr) };
                    assert!(res.is_ok(), "Failed to UnmapViewOfFile: {:?}", res.err());

                    let res = unsafe { CloseHandle(handle) };
                    assert!(res.is_ok(), "Failed to CloseHandle: {:?}", res.err());
                }
                Ok(())
            });
            threads.push(thread_handle);
        }

        for thread_handle in threads {
            assert!(thread_handle.join().is_ok());
        }

        assert_number_of_surrogate_processes(NUMBER_OF_SURROGATE_PROCESSES);
    }

    #[track_caller]
    fn assert_number_of_surrogate_processes(expected_count: usize) {
        let sleep_count = 10;
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
                {
                    if process_name == SURROGATE_PROCESS_BINARY_NAME {
                        count += 1;
                    }
                }
                unsafe {
                    result = Process32Next(snapshot_handle, &mut process_entry).is_ok();
                }
            }

            // if the expected count is 0, we are waiting for the processes to exit, this doesnt happen immediately, so we wait for a bit

            if (expected_count == 0) && (count > 0) && (sleep_count < 30) {
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

        let process = mgr
            .get_surrogate_process(
                mem.raw_mem_size(),
                mem.raw_ptr() as *mut c_void,
                HandleWrapper::from(mem.get_mmap_file_handle()),
            )
            .unwrap();

        let buffer = vec![0u8; SIZE];
        let bytes_read: Option<*mut usize> = None;
        let process_handle: HANDLE = process.process_handle.into();

        unsafe {
            // read the first guard page, should fail
            let success = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                process.allocated_address,
                buffer.as_ptr() as *mut c_void,
                SIZE,
                bytes_read,
            );
            assert!(success.is_err());

            // read the memory, should be OK
            let success = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                process.allocated_address.add(SIZE),
                buffer.as_ptr() as *mut c_void,
                SIZE,
                bytes_read,
            );
            assert!(success.is_ok());

            // read the second guard page, should fail
            let success = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                process.allocated_address.add(2 * SIZE),
                buffer.as_ptr() as *mut c_void,
                SIZE,
                bytes_read,
            );
            assert!(success.is_err());
        }
    }
}
