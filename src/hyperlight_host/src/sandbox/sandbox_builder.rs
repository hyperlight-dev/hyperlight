use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::path::Path;
use std::time::Duration;
use hyperlight_common::mem::PAGE_SIZE_USIZE;
use crate::sandbox::SandboxConfiguration;
use crate::{log_build_details, new_error, UninitializedSandbox, Result, log_then_return, SandboxRunOptions};
use crate::mem::exe::ExeInfo;
use crate::mem::memory_region::MemoryRegionFlags;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};
#[cfg(gdb)]
use crate::sandbox::config::DebugInfo;

const DEFAULT_INPUT_OUTPUT_SECTION_SIZE: usize = 16 * 1024; // 16KB
const DEFAULT_INPUT_SECTION_NAME: &str = "input data";
const DEFAULT_OUTPUT_SECTION_NAME: &str = "output data";
const DEFAULT_GUEST_CODE_SECTION_NAME: &str = "guest code";
const DEFAULT_PAGING_STRUCTURES_SECTION_NAME: &str = "paging structures";
pub(crate) const BASE_ADDRESS: usize = 0x0;
pub(crate) const PDPT_OFFSET: usize = 0x1000;
pub(crate) const PD_OFFSET: usize = 0x2000;
pub(crate) const PT_OFFSET: usize = 0x3000;

#[derive(Debug, Clone)]
pub(crate) struct SandboxMemorySection {
    pub(crate) name: String,
    pub(crate) flags: MemoryRegionFlags,
    pub(crate) page_aligned_guest_offset: usize,
    pub(crate) host_address: Option<usize>,
    pub(crate) page_aligned_size: usize,
}

#[derive(Clone)]
pub(crate) struct SandboxMemorySections {
    pub(crate) sections: BTreeMap<usize, SandboxMemorySection>,
}

impl Debug for SandboxMemorySections {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.sections.iter()).finish()
    }
}

impl SandboxMemorySections {
    pub(crate) fn new() -> Self {
        Self {
            sections: BTreeMap::new(),
        }
    }

    pub(crate) fn get_guest_code_offset(&self) -> Option<usize> {
        self.sections.iter().find(|(_, section)| section.name == DEFAULT_GUEST_CODE_SECTION_NAME).map(|(_, section)| section.page_aligned_guest_offset)
    }

    pub(crate) fn get_paging_structures_offset(&self) -> Option<usize> {
        self.sections.iter().find(|(_, section)| section.name == DEFAULT_PAGING_STRUCTURES_SECTION_NAME).map(|(_, section)| section.page_aligned_guest_offset)
    }

    pub(crate) fn get_total_size(&self) -> usize {
        self.sections.values().map(|section| section.page_aligned_size).sum()
    }

    pub(crate) fn values(&self) -> impl Iterator<Item=&SandboxMemorySection> {
        self.sections.values()
    }

    pub(crate) fn insert(&mut self, offset: usize, section: SandboxMemorySection) {
        self.sections.insert(offset, section);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item=(&usize, &SandboxMemorySection)> {
        self.sections.iter()
    }
}

/// A `GuestBinary` is either a buffer containing the binary or a path to the binary
#[derive(Debug)]
pub enum GuestBinary {
    /// A buffer containing the guest binary
    Buffer(Vec<u8>),
    /// A path to the guest binary
    FilePath(String),
}

impl GuestBinary {
    fn to_exe_info(&self) -> Result<ExeInfo> {
        match self {
            GuestBinary::Buffer(buffer) => ExeInfo::from_buf(buffer),
            GuestBinary::FilePath(path) => ExeInfo::from_file(path),
        }
    }
}

/// TODO(danbugs:297): comment
pub struct SandboxBuilder {
    guest_binary: GuestBinary,
    memory_sections: SandboxMemorySections,
    max_initialization_time: Duration,
    max_execution_time: Duration,
    sandbox_run_options: SandboxRunOptions,
    init_rsp: Option<u64>,
    #[cfg(gdb)]
    guest_debug_info: Option<DebugInfo>,
}

impl SandboxBuilder {
    /// Create a new SandboxBuilder with a guest binary.
    /// - Sets the default maximum initialization time to 2000ms.
    /// - Sets the default maximum execution time to 1000ms.
    /// - Resolves the path of the guest binary if it is a file.
    /// - Sets the sandbox to run in Hyperlight mode by default.
    /// - Adds a memory section for the guest binary.
    pub fn new(guest_binary: GuestBinary) -> Result<SandboxBuilder> {
        // If the guest binary is a file, resolve the path
        let guest_binary = match guest_binary {
            GuestBinary::FilePath(binary_path) => {
                let path = Path::new(&binary_path)
                    .canonicalize()
                    .map_err(|e| new_error!("Guest binary not found: '{}': {}", binary_path, e))?;
                GuestBinary::FilePath(
                    path.into_os_string()
                        .into_string()
                        .map_err(|e| new_error!("Error converting OsString to String: {:?}", e))?,
                )
            }
            buffer @ GuestBinary::Buffer(_) => buffer,
        };

        let sandbox_builder = SandboxBuilder {
            memory_sections: SandboxMemorySections::new(),
            max_initialization_time: Duration::from_millis(SandboxConfiguration::DEFAULT_MAX_INITIALIZATION_TIME as u64),
            max_execution_time: Duration::from_millis(SandboxConfiguration::DEFAULT_MAX_EXECUTION_TIME as u64),
            guest_binary,
            sandbox_run_options: SandboxRunOptions::default(),
            init_rsp: None,
            #[cfg(gdb)]
            guest_debug_info: None,

        };

        let guest_binary_size = sandbox_builder.guest_binary.to_exe_info()?.loaded_size();

        Ok(sandbox_builder.add_memory_section_at_offset(DEFAULT_GUEST_CODE_SECTION_NAME, BASE_ADDRESS, guest_binary_size, MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE))
    }

    /// Sets the initial RSP value.
    pub fn set_init_rsp(mut self, init_rsp: u64) -> Self {
        self.init_rsp = Some(init_rsp);
        self
    }

    /// Set the maximum time the sandbox is allowed to take
    /// to initialize (in milliseconds). By default, the sandbox
    /// can take 2000ms to initialize.
    // TODO(danbugs): change this to make the default be that the
    // sandbox can take as long as it needs to initialize.
    pub fn set_max_initialization_time(mut self, max_initialization_time: u64) -> Self {
        self.max_initialization_time = Duration::from_millis(max_initialization_time);
        self
    }

    /// Set the maximum time the sandbox is allowed to take
    /// to execute a guest function (in milliseconds). By default,
    /// the sandbox can 1000ms to execute a guest function.
    // TODO(danbugs): change this to make the default be that the
    // sandbox can take as long as it needs to execute a guest function.
    pub fn set_max_execution_time(mut self, max_execution_time: u64) -> Self {
        self.max_initialization_time = Duration::from_millis(max_execution_time);
        self
    }

    /// Set the sandbox run mode. Options:
    /// - SandboxRunOptions::RunInHypervisor: Run the sandbox in a hypervisor.
    /// - SandboxRunOptions::RunInProcess(false): Run the sandbox in process (i.e., without a
    /// hypervisor), but also without using the Windows LoadLibrary to load the guest binary.
    /// - SandboxRunOptions::RunInProcess(true): Run the sandbox in process (i.e., without a
    /// hypervisor), and use the Windows LoadLibrary to load the guest binary.
    pub fn set_sandbox_run_options(mut self, sandbox_run_options: SandboxRunOptions) -> Result<Self> {
        let run_inprocess = sandbox_run_options.in_process();
        let use_loadlib = sandbox_run_options.use_loadlib();

        if run_inprocess && cfg!(not(inprocess)) {
            log_then_return!(
                "In process mode is only available in debug builds, and also requires cargo feature 'inprocess'"
            )
        }

        if use_loadlib && cfg!(not(all(inprocess, target_os = "windows"))) {
            log_then_return!("In process mode with LoadLibrary is only available on Windows")
        }

        self.sandbox_run_options = sandbox_run_options;
        Ok(self)
    }

    /// Set the debug information for the guest binary.
    #[cfg(gdb)]
    pub fn set_guest_debug_info(mut self, debug_info: DebugInfo) -> Self {
        self.guest_debug_info = Some(debug_info);
        self
    }

    /// Get paging section size
    fn get_total_page_table_size(&self) -> Result<usize> {
        let mut total_mapped_memory_size: usize = 0;

        // Iterate through the memory sections and add their sizes
        total_mapped_memory_size += self.get_total_page_aligned_memory_size();

        // Add the size of  the PML4, PDPT and PD
        total_mapped_memory_size += 3 * PAGE_SIZE_USIZE;

        // Add the maximum possible size of the PTs
        total_mapped_memory_size += 512 * PAGE_SIZE_USIZE;

        // Get the number of pages needed for the PTs
        let num_pages: usize = ((total_mapped_memory_size + crate::mem::mgr::AMOUNT_OF_MEMORY_PER_PT - 1)
            / crate::mem::mgr::AMOUNT_OF_MEMORY_PER_PT)
            + 1 // Round up
            + 3; // PML4, PDPT, PD

        Ok(num_pages * PAGE_SIZE_USIZE)
    }

    fn get_total_page_aligned_memory_size(&self) -> usize {
        let mut total_mapped_memory_size: usize = 0;
        for section in self.memory_sections.values() {
            total_mapped_memory_size += SandboxBuilder::round_up_to(section.page_aligned_size, PAGE_SIZE_USIZE);
        }

        total_mapped_memory_size
    }

    fn round_up_to(value: usize, multiple: usize) -> usize {
        (value + multiple - 1) & !(multiple - 1)
    }

    /// Finds the next available offset that can accommodate a given size.
    fn next_free_offset(&self, page_aligned_size: usize) -> usize {
        let mut current_offset = 0;

        for section in self.memory_sections.values() {
            let section_start = section.page_aligned_guest_offset; // this is page aligned
            let section_end = section.page_aligned_guest_offset + section.page_aligned_size; // this is also page aligned

            // Check if a gap exists before this section that is large enough
            if section_start >= current_offset + page_aligned_size {
                return current_offset; // Found a suitable gap
            }

            // Move to the next available offset after this section
            current_offset = section_end;
        }

        // If no gaps were found, place the section after the last one
        current_offset
    }


    /// Adds a memory section (sorted by offset) and prevents overlaps
    pub fn add_memory_section_at_offset(mut self, name: &str, offset: usize, size: usize, flags: MemoryRegionFlags) -> Self {
        let aligned_offset = SandboxBuilder::round_up_to(offset, PAGE_SIZE_USIZE);
        let aligned_size = SandboxBuilder::round_up_to(size, PAGE_SIZE_USIZE);
        let end = aligned_offset + aligned_size;

        // Check for overlapping sections
        for (_, existing_section) in self.memory_sections.iter() {
            let existing_end = existing_section.page_aligned_guest_offset + existing_section.page_aligned_size;
            if (aligned_offset >= existing_section.page_aligned_guest_offset && aligned_offset < existing_end)
                || (end > existing_section.page_aligned_guest_offset && end <= existing_end)
            {
                panic!(
                    "Memory overlap detected: '{}' ({}-{}) conflicts with '{}' ({}-{})",
                    name, aligned_offset, end, existing_section.name, existing_section.page_aligned_guest_offset, existing_end
                );
            }
        }

        let section = SandboxMemorySection {
            name: name.to_string(),
            page_aligned_guest_offset: aligned_offset,
            page_aligned_size: aligned_size,
            host_address: None,
            flags,
        };

        self.memory_sections.insert(aligned_offset, section);
        self
    }

    /// Adds a memory section without specifying an offset.
    /// Automatically finds the next available aligned offset.
    pub fn add_memory_section(mut self, name: &str, size: usize, flags: MemoryRegionFlags) -> Self {
        let page_aligned_size = SandboxBuilder::round_up_to(size, PAGE_SIZE_USIZE);
        let page_aligned_offset = self.next_free_offset(page_aligned_size);

        let section = SandboxMemorySection {
            name: name.to_string(),
            page_aligned_guest_offset: page_aligned_offset,
            page_aligned_size: page_aligned_size,
            host_address: None,
            flags,
        };

        self.memory_sections.insert(page_aligned_offset, section);
        self
    }

    /// Enables host functions by reserving two memory regions: input & output
    /// - If no input/output offset is provided, the next available offset is used
    /// - Default size is 16KB for both input and output sections
    pub fn enable_host_functions(mut self, input_offset: Option<usize>, input_size: Option<usize>,
                                 output_offset: Option<usize>, output_size: Option<usize>) -> Self {
        // Get size for input/output sections
        let input_size = SandboxBuilder::round_up_to(input_size.unwrap_or(DEFAULT_INPUT_OUTPUT_SECTION_SIZE), PAGE_SIZE_USIZE);
        let output_size = SandboxBuilder::round_up_to(output_size.unwrap_or(DEFAULT_INPUT_OUTPUT_SECTION_SIZE), PAGE_SIZE_USIZE);

        // Find next available offset if none is provided
        let input_offset = SandboxBuilder::round_up_to(input_offset.unwrap_or_else(|| self.next_free_offset(input_size)), PAGE_SIZE_USIZE);
        let output_offset = SandboxBuilder::round_up_to(output_offset.unwrap_or_else(|| SandboxBuilder::round_up_to(input_offset + input_size, PAGE_SIZE_USIZE)), PAGE_SIZE_USIZE);

        // Add Input Section
        self = self.add_memory_section_at_offset(DEFAULT_INPUT_SECTION_NAME, input_offset, input_size, MemoryRegionFlags::READ | MemoryRegionFlags::WRITE);
        // Add Output Section
        self = self.add_memory_section_at_offset(DEFAULT_OUTPUT_SECTION_NAME, output_offset, output_size, MemoryRegionFlags::READ | MemoryRegionFlags::WRITE);

        self
    }

    /// Loads the guest binary. There are three modes:
    /// 1. Run in process and use LoadLibrary (makes the memory executable)
    /// 2. Run in process and not use LoadLibrary (makes the memory executable)
    /// 3. Run in hypervisor
    ///
    /// - Sets the load address in shared memory.
    /// - Returns load address.
    fn load_guest_binary(&self, init_rsp: u64, memory_sections: SandboxMemorySections, mut exclusive_shared_memory: ExclusiveSharedMemory) -> Result<SandboxMemoryManager<ExclusiveSharedMemory>>
    {
        let run_inprocess = self.sandbox_run_options.in_process();
        let use_loadlib = self.sandbox_run_options.use_loadlib();
        let mut guest_binary_exe_info = self.guest_binary.to_exe_info()?;
        let guest_code_offset = memory_sections.get_guest_code_offset().ok_or_else(|| new_error!("Guest code section not found"))?;

        let mut sandbox_memory_manager = if run_inprocess && use_loadlib {
            #[cfg(target_os = "windows")]
            {
                // We are running in process and using LoadLibrary
                if !matches!(guest_binary_exe_info, ExeInfo::PE(_)) {
                    log_then_return!("LoadLibrary can only be used with PE files");
                }

                // Get guest binary path
                let guest_bin_path = match &self.guest_binary {
                    GuestBinary::FilePath(bin_path_str) => bin_path_str,
                    GuestBinary::Buffer(_) => {
                        log_then_return!("Guest binary should be a file to use LoadLibrary");
                    }
                };

                let lib = crate::mem::loaded_lib::LoadedLib::load(guest_bin_path)?;
                exclusive_shared_memory.make_memory_executable()?;

                SandboxMemoryManager::new(
                    exclusive_shared_memory,
                    RawPtr(lib.base_addr() as u64),
                    guest_binary_exe_info.entrypoint(),
                    memory_sections,
                    init_rsp,
                    Some(lib),
                )
            }
            #[cfg(target_os = "linux")]
            {
                log_then_return!("LoadLibrary is only available on Windows");
            }
        } else if run_inprocess && !use_loadlib {
            // We are running in process and not using LoadLibrary
            exclusive_shared_memory.make_memory_executable()?;
            let load_address = exclusive_shared_memory.base_addr() + guest_code_offset;

            guest_binary_exe_info.load(
                load_address,
                &mut exclusive_shared_memory.as_mut_slice()[guest_code_offset..],
            )?;

            SandboxMemoryManager::new(
                exclusive_shared_memory,
                RawPtr(load_address as u64),
                guest_binary_exe_info.entrypoint(),
                memory_sections,
                init_rsp,
                #[cfg(target_os = "windows")]
                None,
            )
        } else if !run_inprocess && !use_loadlib {
            guest_binary_exe_info.load(
                guest_code_offset,
                &mut exclusive_shared_memory.as_mut_slice()[guest_code_offset..],
            )?;

            SandboxMemoryManager::new(
                exclusive_shared_memory,
                RawPtr(guest_code_offset as u64),
                guest_binary_exe_info.entrypoint(),
                memory_sections,
                init_rsp,
                #[cfg(target_os = "windows")]
                None,
            )
        } else {
            log_then_return!("Invalid combination of run options: inprocess and use_loadlib")
        };

        // Write the code pointer to shared memory
        sandbox_memory_manager.shared_mem.write_u64(guest_code_offset, sandbox_memory_manager.load_addr.clone().try_into()?)?;

        Ok(sandbox_memory_manager)
    }

    fn map_host_addresses(&mut self, host_base_address: usize) {
        for (_, section) in self.memory_sections.clone().iter() {
            let host_address = host_base_address + section.page_aligned_guest_offset;
            self.memory_sections.sections.get_mut(&section.page_aligned_guest_offset).unwrap().host_address = Some(host_address);
        }
    }

    /// TODO(danbugs:297): comment
    pub fn build(self) -> Result<UninitializedSandbox> {
        log_build_details();

        // Hyperlight is only supported on Windows 11 and Windows Server 2022 and later
        #[cfg(target_os = "windows")]
        check_windows_version()?;

        // Set up sandbox configuration
        let mut sandbox_configuration = SandboxConfiguration::default();
        sandbox_configuration.set_max_initialization_time(self.max_initialization_time);
        sandbox_configuration.set_max_execution_time(self.max_execution_time);
        #[cfg(gdb)]
        if let Some(debug_info) = self.guest_debug_info {
            sandbox_configuration.set_guest_debug_info(debug_info);
        }

        // Add sandbox memory section for paging
        let paging_sections_size = self.get_total_page_table_size()?;
        let mut sandbox_builder = self.add_memory_section(DEFAULT_PAGING_STRUCTURES_SECTION_NAME, paging_sections_size, MemoryRegionFlags::READ | MemoryRegionFlags::WRITE);

        // Get ExclusiveSharedMemory region and load guest binary
        let exclusive_shared_memory = ExclusiveSharedMemory::new(sandbox_builder.get_total_page_aligned_memory_size())?;
        let host_base_address = exclusive_shared_memory.base_addr();
        // TODO(danbugs:297): improve error message
        let mut sandbox_memory_manager = sandbox_builder.load_guest_binary(sandbox_builder.init_rsp.unwrap(), sandbox_builder.memory_sections.clone(), exclusive_shared_memory)?;
        let load_address: usize = sandbox_memory_manager.load_addr.clone().try_into()?;

        // Write remaining memory sections to shared memory, excluding:
        // - guest code
        // - paging structures
        for (_, section) in sandbox_builder.memory_sections.iter() {
            if section.name == DEFAULT_GUEST_CODE_SECTION_NAME || section.name == DEFAULT_PAGING_STRUCTURES_SECTION_NAME {
                continue;
            }


            sandbox_memory_manager.shared_mem.write_u64(section.page_aligned_guest_offset, (section.page_aligned_guest_offset + load_address) as u64)?;
        }

        sandbox_builder.map_host_addresses(host_base_address);

        //TODO(danbugs:297): bring back host fxns and adding host_printer

        Ok(UninitializedSandbox::new(
            sandbox_memory_manager,
            sandbox_configuration,
            #[cfg(gdb)]
            sandbox_builder.guest_debug_info,
        ))
    }
}

// TODO(danbugs:297): impl
// #[cfg(mshv)]
// impl From<MemoryRegion> for mshv_user_mem_region {
//     fn from(region: MemoryRegion) -> Self {
//         let size = (region.guest_region.end - region.guest_region.start) as u64;
//         let guest_pfn = region.guest_region.start as u64 >> PAGE_SHIFT;
//         let userspace_addr = region.host_region.start as u64;
//
//         #[cfg(mshv2)]
//         {
//             let flags = region.flags.iter().fold(0, |acc, flag| {
//                 let flag_value = match flag {
//                     MemoryRegionFlags::NONE => HV_MAP_GPA_PERMISSIONS_NONE,
//                     MemoryRegionFlags::READ => HV_MAP_GPA_READABLE,
//                     MemoryRegionFlags::WRITE => HV_MAP_GPA_WRITABLE,
//                     MemoryRegionFlags::EXECUTE => HV_MAP_GPA_EXECUTABLE,
//                     _ => 0, // ignore any unknown flags
//                 };
//                 acc | flag_value
//             });
//             mshv_user_mem_region {
//                 guest_pfn,
//                 size,
//                 userspace_addr,
//                 flags,
//             }
//         }
//         #[cfg(mshv3)]
//         {
//             let flags: u8 = region.flags.iter().fold(0, |acc, flag| {
//                 let flag_value = match flag {
//                     MemoryRegionFlags::NONE => 1 << MSHV_SET_MEM_BIT_UNMAP,
//                     MemoryRegionFlags::READ => 0,
//                     MemoryRegionFlags::WRITE => 1 << MSHV_SET_MEM_BIT_WRITABLE,
//                     MemoryRegionFlags::EXECUTE => 1 << MSHV_SET_MEM_BIT_EXECUTABLE,
//                     _ => 0, // ignore any unknown flags
//                 };
//                 acc | flag_value
//             });
//
//             mshv_user_mem_region {
//                 guest_pfn,
//                 size,
//                 userspace_addr,
//                 flags,
//                 ..Default::default()
//             }
//         }
//     }
// }