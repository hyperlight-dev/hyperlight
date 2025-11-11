/*
Copyright 2025 The Hyperlight Authors.

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

use std::cmp::min;
use std::io::Write;

use chrono;
use elfcore::{
    ArchComponentState, ArchState, CoreDumpBuilder, CoreError, Elf64_Auxv, ProcessInfoSource,
    ReadProcessMemory, ThreadView, VaProtection, VaRegion,
};

use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::{Result, new_error};

/// This constant is used to identify the XSAVE state in the core dump
const NT_X86_XSTATE: u32 = 0x202;
/// This constant identifies the entry point of the program in an Auxiliary Vector
/// note of ELF. This tells a debugger whether the entry point of the program changed
/// so it can load the symbols correctly.
const AT_ENTRY: u64 = 9;
/// This constant is used to mark the end of the Auxiliary Vector note
const AT_NULL: u64 = 0;
/// The PID of the core dump process - this is a placeholder value
const CORE_DUMP_PID: i32 = 1;
/// The page size of the core dump
const CORE_DUMP_PAGE_SIZE: usize = 0x1000;

/// Structure to hold the crash dump context
/// This structure contains the information needed to create a core dump
#[derive(Debug)]
pub(crate) struct CrashDumpContext {
    regions: Vec<MemoryRegion>,
    regs: [u64; 27],
    xsave: Vec<u8>,
    entry: u64,
    binary: Option<String>,
    filename: Option<String>,
}

impl CrashDumpContext {
    pub(crate) fn new(
        regions: Vec<MemoryRegion>,
        regs: [u64; 27],
        xsave: Vec<u8>,
        entry: u64,
        binary: Option<String>,
        filename: Option<String>,
    ) -> Self {
        Self {
            regions,
            regs,
            xsave,
            entry,
            binary,
            filename,
        }
    }
}

/// Structure that contains the process information for the core dump
/// This serves as a source of information for `elfcore`'s [`CoreDumpBuilder`]
struct GuestView {
    regions: Vec<VaRegion>,
    threads: Vec<ThreadView>,
    aux_vector: Vec<elfcore::Elf64_Auxv>,
}

impl GuestView {
    fn new(ctx: &CrashDumpContext) -> Self {
        // Map the regions to the format `CoreDumpBuilder` expects
        let regions = ctx
            .regions
            .iter()
            .filter(|r| !r.host_region.is_empty())
            .map(|r| VaRegion {
                begin: r.guest_region.start as u64,
                end: r.guest_region.end as u64,
                offset: r.host_region.start as u64,
                protection: VaProtection {
                    is_private: false,
                    read: r.flags.contains(MemoryRegionFlags::READ),
                    write: r.flags.contains(MemoryRegionFlags::WRITE),
                    execute: r.flags.contains(MemoryRegionFlags::EXECUTE),
                },
                mapped_file_name: None,
            })
            .collect();

        let filename = ctx
            .filename
            .as_ref()
            .map_or("<unknown>".to_string(), |s| s.to_string());

        let cmd = ctx
            .binary
            .as_ref()
            .map_or("<unknown>".to_string(), |s| s.to_string());

        // The xsave state is checked as it can be empty
        let mut components = vec![];
        if !ctx.xsave.is_empty() {
            components.push(ArchComponentState {
                name: "XSAVE",
                note_type: NT_X86_XSTATE,
                note_name: b"LINUX",
                data: ctx.xsave.clone(),
            });
        }

        // Create the thread view
        // The thread view contains the information about the thread
        // NOTE: Some of these fields are not used in the current implementation
        let thread = ThreadView {
            flags: 0, // Kernel flags for the process
            tid: 1,
            uid: 0, // User ID
            gid: 0, // Group ID
            comm: filename,
            ppid: 0,    // Parent PID
            pgrp: 0,    // Process group ID
            nice: 0,    // Nice value
            state: 0,   // Process state
            utime: 0,   // User time
            stime: 0,   // System time
            cutime: 0,  // Children User time
            cstime: 0,  // Children User time
            cursig: 0,  // Current signal
            session: 0, // Session ID of the process
            sighold: 0, // Blocked signal
            sigpend: 0, // Pending signal
            cmd_line: cmd,

            arch_state: Box::new(ArchState {
                gpr_state: ctx.regs.to_vec(),
                components,
            }),
        };

        // Create the auxv vector
        // The first entry is AT_ENTRY, which is the entry point of the program
        // The entry point is the address where the program starts executing
        // This helps the debugger to know that the entry is changed by an offset
        // so the symbols can be loaded correctly.
        // The second entry is AT_NULL, which marks the end of the vector
        let auxv = vec![
            Elf64_Auxv {
                a_type: AT_ENTRY,
                a_val: ctx.entry,
            },
            Elf64_Auxv {
                a_type: AT_NULL,
                a_val: 0,
            },
        ];

        Self {
            regions,
            threads: vec![thread],
            aux_vector: auxv,
        }
    }
}

impl ProcessInfoSource for GuestView {
    fn pid(&self) -> i32 {
        CORE_DUMP_PID
    }
    fn threads(&self) -> &[elfcore::ThreadView] {
        &self.threads
    }
    fn page_size(&self) -> usize {
        CORE_DUMP_PAGE_SIZE
    }
    fn aux_vector(&self) -> Option<&[elfcore::Elf64_Auxv]> {
        Some(&self.aux_vector)
    }
    fn va_regions(&self) -> &[elfcore::VaRegion] {
        &self.regions
    }
    fn mapped_files(&self) -> Option<&[elfcore::MappedFile]> {
        // We don't have mapped files
        None
    }
}

/// Structure that reads the guest memory
/// This structure serves as a custom memory reader for `elfcore`'s
/// [`CoreDumpBuilder`]
struct GuestMemReader {
    regions: Vec<MemoryRegion>,
}

impl GuestMemReader {
    fn new(ctx: &CrashDumpContext) -> Self {
        Self {
            regions: ctx.regions.clone(),
        }
    }
}

impl ReadProcessMemory for GuestMemReader {
    fn read_process_memory(
        &mut self,
        base: usize,
        buf: &mut [u8],
    ) -> std::result::Result<usize, CoreError> {
        for r in self.regions.iter() {
            // Check if the base address is within the guest region
            if base >= r.guest_region.start && base < r.guest_region.end {
                let offset = base - r.guest_region.start;
                let region_slice = unsafe {
                    std::slice::from_raw_parts(
                        r.host_region.start as *const u8,
                        r.host_region.len(),
                    )
                };

                // Calculate how much we can copy
                let copy_size = min(buf.len(), region_slice.len() - offset);
                if copy_size == 0 {
                    return std::result::Result::Ok(0);
                }

                // Only copy the amount that fits in both buffers
                buf[..copy_size].copy_from_slice(&region_slice[offset..offset + copy_size]);

                // Return the number of bytes copied
                return std::result::Result::Ok(copy_size);
            }
        }

        // If we reach here, we didn't find a matching region
        std::result::Result::Ok(0)
    }
}

/// Create core dump file from the hypervisor information if the sandbox is configured
/// to allow core dumps.
///
/// This function generates an ELF core dump file capturing the hypervisor's state,
/// which can be used for debugging when crashes occur.
/// The location of the core dump file is determined by the `HYPERLIGHT_CORE_DUMP_DIR`
/// environment variable. If not set, it defaults to the system's temporary directory.
///
/// # Arguments
/// * `hv`: Reference to the hypervisor implementation
///
/// # Returns
/// * `Result<()>`: Success or error
pub(crate) fn generate_crashdump(ctx: Option<CrashDumpContext>) -> Result<()> {
    // Get env variable for core dump directory
    let core_dump_dir = std::env::var("HYPERLIGHT_CORE_DUMP_DIR").ok();

    // Compute file path on the filesystem
    let file_path = core_dump_file_path(core_dump_dir);

    let create_dump_file = || {
        // Create the file
        Ok(Box::new(
            std::fs::File::create(&file_path)
                .map_err(|e| new_error!("Failed to create core dump file: {:?}", e))?,
        ) as Box<dyn Write>)
    };

    if let Ok(nbytes) = checked_core_dump(ctx, create_dump_file) {
        if nbytes > 0 {
            println!("Core dump created successfully: {}", file_path);
            log::error!("Core dump file: {}", file_path);
        }
    } else {
        log::error!("Failed to create core dump file");
    }

    Ok(())
}

/// Computes the file path for the core dump file.
///
/// The file path is generated based on the current timestamp and an
/// output directory.
/// If the directory does not exist, it falls back to the system's temp directory.
/// If the variable is not set, it defaults to the system's temporary directory.
/// The filename is formatted as `hl_core_<timestamp>.elf`.
///
/// Arguments:
/// * `dump_dir`: The environment variable value to check for the output directory.
///
/// Returns:
/// * `String`: The file path for the core dump file.
fn core_dump_file_path(dump_dir: Option<String>) -> String {
    // Generate timestamp string for the filename using chrono
    let timestamp = chrono::Local::now()
        .format("%Y%m%d_T%H%M%S%.3f")
        .to_string();

    // Determine the output directory based on environment variable
    let output_dir = if let Some(dump_dir) = dump_dir {
        // Check if the directory exists
        // If it doesn't exist, fall back to the system temp directory
        // This is to ensure that the core dump can be created even if the directory is not set
        if std::path::Path::new(&dump_dir).exists() {
            std::path::PathBuf::from(dump_dir)
        } else {
            log::warn!(
                "Directory \"{}\" does not exist, falling back to temp directory",
                dump_dir
            );
            std::env::temp_dir()
        }
    } else {
        // Fall back to the system temp directory
        std::env::temp_dir()
    };

    // Create the filename with timestamp
    let filename = format!("hl_core_{}.elf", timestamp);
    let file_path = output_dir.join(filename);

    file_path.to_string_lossy().to_string()
}

/// Create core dump from Hypervisor context if the sandbox is configured to allow core dumps.
///
/// Arguments:
/// * `ctx`: Optional crash dump context from the hypervisor. This contains the information
///   needed to create the core dump. If `None`, no core dump will be created.
/// * `get_writer`: Closure that returns a writer to the output destination.
///
/// Returns:
/// * `Result<usize>`: The number of bytes written to the core dump file.
fn checked_core_dump(
    ctx: Option<CrashDumpContext>,
    get_writer: impl FnOnce() -> Result<Box<dyn Write>>,
) -> Result<usize> {
    let mut nbytes = 0;
    // If the HV returned a context it means we can create a core dump
    // This is the case when the sandbox has been configured at runtime to allow core dumps
    if let Some(ctx) = ctx {
        log::info!("Creating core dump file...");

        // Set up data sources for the core dump
        let guest_view = GuestView::new(&ctx);
        let memory_reader = GuestMemReader::new(&ctx);

        // Create and write core dump
        let core_builder = CoreDumpBuilder::from_source(guest_view, memory_reader);

        let writer = get_writer()?;
        // Write the core dump directly to the file
        nbytes = core_builder
            .write(writer)
            .map_err(|e| new_error!("Failed to write core dump: {:?}", e))?;
    }

    Ok(nbytes)
}

/// Test module for the crash dump functionality
#[cfg(test)]
mod test {
    use super::*;

    /// Test the core_dump_file_path function when the environment variable is set to an existing
    /// directory
    #[test]
    fn test_crashdump_file_path_valid() {
        // Get CWD
        let valid_dir = std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .to_string();

        // Call the function
        let path = core_dump_file_path(Some(valid_dir.clone()));

        // Check if the path is correct
        assert!(path.contains(&valid_dir));
    }

    /// Test the core_dump_file_path function when the environment variable is set to an invalid
    /// directory
    #[test]
    fn test_crashdump_file_path_invalid() {
        // Call the function
        let path = core_dump_file_path(Some("/tmp/not_existing_dir".to_string()));

        // Get the temp directory
        let temp_dir = std::env::temp_dir().to_string_lossy().to_string();

        // Check if the path is correct
        assert!(path.contains(&temp_dir));
    }

    /// Test the core_dump_file_path function when the environment is not set
    /// Check against the default temp directory by using the env::temp_dir() function
    #[test]
    fn test_crashdump_file_path_default() {
        // Call the function
        let path = core_dump_file_path(None);

        let temp_dir = std::env::temp_dir().to_string_lossy().to_string();

        // Check if the path is correct
        assert!(path.starts_with(&temp_dir));
    }

    /// Test core is not created when the context is None
    #[test]
    fn test_crashdump_not_created_when_context_is_none() {
        // Call the function with None context
        let result = checked_core_dump(None, || Ok(Box::new(std::io::empty())));

        // Check if the result is ok and the number of bytes is 0
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    /// Test the core dump creation with no regions fails
    #[test]
    fn test_crashdump_write_fails_when_no_regions() {
        // Create a dummy context
        let ctx = CrashDumpContext::new(
            vec![],
            [0; 27],
            vec![],
            0,
            Some("dummy_binary".to_string()),
            Some("dummy_filename".to_string()),
        );

        let get_writer = || Ok(Box::new(std::io::empty()) as Box<dyn Write>);

        // Call the function
        let result = checked_core_dump(Some(ctx), get_writer);

        // Check if the result is an error
        // This should fail because there are no regions
        assert!(result.is_err());
    }

    /// Check core dump with a dummy region to local vec
    /// This test checks if the core dump is created successfully
    #[test]
    fn test_crashdump_dummy_core_dump() {
        let dummy_vec = vec![0; 0x1000];
        let regions = vec![MemoryRegion {
            guest_region: 0x1000..0x2000,
            host_region: dummy_vec.as_ptr() as usize..dummy_vec.as_ptr() as usize + dummy_vec.len(),
            flags: MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            region_type: crate::mem::memory_region::MemoryRegionType::Code,
        }];
        // Create a dummy context
        let ctx = CrashDumpContext::new(
            regions,
            [0; 27],
            vec![],
            0x1000,
            Some("dummy_binary".to_string()),
            Some("dummy_filename".to_string()),
        );

        let get_writer = || Ok(Box::new(std::io::empty()) as Box<dyn Write>);

        // Call the function
        let result = checked_core_dump(Some(ctx), get_writer);

        // Check if the result is ok and the number of bytes is 0
        assert!(result.is_ok());
        // Check the number of bytes written is more than 0x1000 (the size of the region)
        assert_eq!(result.unwrap(), 0x2000);
    }
}
