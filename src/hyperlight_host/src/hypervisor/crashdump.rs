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

use std::cmp::min;

use chrono;
use elfcore::{
    ArchComponentState, ArchState, CoreDumpBuilder, CoreError, Elf64_Auxv, ProcessInfoSource,
    ReadProcessMemory, ThreadView, VaProtection, VaRegion,
};

use super::Hypervisor;
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
pub(crate) struct CrashDumpContext<'a> {
    regions: &'a [MemoryRegion],
    regs: [u64; 27],
    xsave: Vec<u8>,
    entry: u64,
    binary: Option<String>,
    filename: Option<String>,
}

impl<'a> CrashDumpContext<'a> {
    pub(crate) fn new(
        regions: &'a [MemoryRegion],
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
            regions: ctx.regions.to_vec(),
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

/// Create core dump file from the hypervisor information
///
/// This function generates an ELF core dump file capturing the hypervisor's state,
/// which can be used for debugging when crashes occur. The file is created in the
/// system's temporary directory with extension '.elf' and the path is printed to stdout and logs.
///
/// # Arguments
/// * `hv`: Reference to the hypervisor implementation
///
/// # Returns
/// * `Result<()>`: Success or error
pub(crate) fn crashdump_to_tempfile(hv: &dyn Hypervisor) -> Result<()> {
    log::info!("Creating core dump file...");

    // Get crash context from hypervisor
    let ctx = hv
        .crashdump_context()
        .map_err(|e| new_error!("Failed to get crashdump context: {:?}", e))?;

    // Set up data sources for the core dump
    let guest_view = GuestView::new(&ctx);
    let memory_reader = GuestMemReader::new(&ctx);

    // Create and write core dump
    let core_builder = CoreDumpBuilder::from_source(guest_view, memory_reader);

    // Generate timestamp string for the filename using chrono
    let timestamp = chrono::Local::now()
        .format("%Y%m%d_T%H%M%S%.3f")
        .to_string();

    // Determine the output directory based on environment variable
    let output_dir = if let Ok(dump_dir) = std::env::var("HYPERLIGHT_CORE_DUMP_DIR") {
        // Create the directory if it doesn't exist
        let path = std::path::Path::new(&dump_dir);
        if !path.exists() {
            std::fs::create_dir_all(path)
                .map_err(|e| new_error!("Failed to create core dump directory: {:?}", e))?;
        }
        std::path::PathBuf::from(dump_dir)
    } else {
        // Fall back to the system temp directory
        std::env::temp_dir()
    };

    // Create the filename with timestamp
    let filename = format!("hl_core_{}.elf", timestamp);
    let file_path = output_dir.join(filename);

    // Create the file
    let file = std::fs::File::create(&file_path)
        .map_err(|e| new_error!("Failed to create core dump file: {:?}", e))?;

    // Write the core dump directly to the file
    core_builder
        .write(&file)
        .map_err(|e| new_error!("Failed to write core dump: {:?}", e))?;

    let path_string = file_path.to_string_lossy().to_string();

    println!("Core dump created successfully: {}", path_string);
    log::error!("Core dump file: {}", path_string);

    Ok(())
}
