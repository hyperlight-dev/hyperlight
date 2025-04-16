use std::cmp::min;

use elfcore::{
    ArchComponentState, ArchState, CoreDumpBuilder, CoreError, Elf64_Auxv, Pid, ProcessInfoSource,
    ReadProcessMemory, ThreadView, VaProtection, VaRegion,
};
use tempfile::NamedTempFile;

use super::Hypervisor;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::{new_error, Result};

// amd64 notes
pub const NT_X86_XSTATE: u32 = 0x202;

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

struct GuestView {
    regions: Vec<VaRegion>,
    threads: Vec<ThreadView>,
    aux_vector: Vec<elfcore::Elf64_Auxv>,
}

impl GuestView {
    fn new(ctx: &CrashDumpContext) -> Self {
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
        let mut filename = ctx.filename.clone().unwrap_or("".to_string());
        filename.push('\0');
        println!("{:X?}", filename);
        let mut cmd = ctx.binary.clone().unwrap_or("".to_string());
        cmd.push('\0');
        println!("{:X?}", cmd);

        let thread = ThreadView {
            flags: 0, // Kernel flags for the process
            tid: Pid::from_raw(1),
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
                components: vec![ArchComponentState {
                    name: "XSAVE",
                    note_type: NT_X86_XSTATE,
                    note_name: b"LINUX",
                    data: ctx.xsave.clone(),
                }],
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
                a_type: 9, // AT_ENTRY
                a_val: ctx.entry,
            },
            Elf64_Auxv {
                a_type: 0, // AT_NULL
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
    fn get_pid(&self) -> Pid {
        Pid::from_raw(1)
    }
    fn get_threads(&self) -> &[elfcore::ThreadView] {
        &self.threads
    }
    fn get_page_size(&self) -> usize {
        0x1000
    }
    fn get_aux_vector(&self) -> Option<&[elfcore::Elf64_Auxv]> {
        Some(&self.aux_vector)
    }
    fn get_va_regions(&self) -> &[elfcore::VaRegion] {
        &self.regions
    }
    fn get_mapped_files(&self) -> Option<&[elfcore::MappedFile]> {
        None
    }
}

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
        let mut size = 0;

        for r in self.regions.iter() {
            if base >= r.guest_region.start && base < r.guest_region.end {
                let offset = base - r.guest_region.start;

                let region_slice = unsafe {
                    std::slice::from_raw_parts(
                        r.host_region.start as *const u8,
                        r.host_region.len(),
                    )
                };

                let start = offset;
                let end = offset + min(buf.len(), region_slice.len());
                buf.copy_from_slice(&region_slice[start..end]);
                size = end - start;
                break;
            }
        }

        std::result::Result::Ok(size)
    }
}

/// Create core dump file from the hypervisor information
pub(crate) fn crashdump_to_tempfile(hv: &dyn Hypervisor) -> Result<()> {
    let temp_file = NamedTempFile::with_prefix("hl")?;

    let ctx = hv
        .get_crashdump_context()
        .map_err(|e| new_error!("Could not create crashdump context: {:?}", e))?;

    let gv = GuestView::new(&ctx);
    let memory_reader = GuestMemReader::new(&ctx);

    let cdb = CoreDumpBuilder::from_source(
        Box::new(gv) as Box<dyn ProcessInfoSource>,
        Box::new(memory_reader) as Box<dyn ReadProcessMemory>,
    );

    cdb.write(&temp_file)
        .map_err(|e| new_error!("Write Error: {:?}", e))?;

    let persist_path = temp_file.path().with_extension("dmp");
    temp_file
        .persist(&persist_path)
        .map_err(|e| new_error!("Failed to persist crashdump file: {:?}", e))?;

    println!("Core dump file: {:?}", persist_path);
    log::error!("Core dump file: {:?}", persist_path);

    Ok(())
}
