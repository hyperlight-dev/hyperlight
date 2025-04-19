use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::path::Path;
use std::time::Duration;

use hyperlight_common::peb::{HyperlightPEB, RunMode};
use hyperlight_common::PAGE_SIZE;

use crate::mem::exe::ExeInfo;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};
#[cfg(gdb)]
use crate::sandbox::config::DebugInfo;
use crate::sandbox::SandboxConfiguration;
use crate::{
    log_build_details, log_then_return, new_error, Result, SandboxRunOptions, UninitializedSandbox,
};

#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;

#[cfg(mshv2)]
use mshv_bindings::{
    HV_MAP_GPA_EXECUTABLE, HV_MAP_GPA_PERMISSIONS_NONE, HV_MAP_GPA_READABLE, HV_MAP_GPA_WRITABLE,
};

#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;

#[cfg(mshv3)]
use mshv_bindings::{
    MSHV_SET_MEM_BIT_EXECUTABLE, MSHV_SET_MEM_BIT_UNMAP, MSHV_SET_MEM_BIT_WRITABLE,
};

const DEFAULT_GUEST_CODE_SECTION_NAME: &str = "guest code";
const DEFAULT_TMP_STACK_SECTION_NAME: &str = "tmp stack";
const DEFAULT_HYPERLIGHT_PEB_SECTION_NAME: &str = "HyperlightPEB";
const DEFAULT_CUSTOM_GUEST_MEMORY_SECTION_NAME: &str = "custom guest memory";
const DEFAULT_PAGING_STRUCTURES_SECTION_NAME: &str = "paging structures";
pub(crate) const BASE_ADDRESS: usize = 0x0;
pub(crate) const PDPT_OFFSET: usize = 0x1000; // this offset is from the PML4 base address
pub(crate) const PD_OFFSET: usize = 0x2000; // this offset is from the PML4 base address
pub(crate) const PT_OFFSET: usize = 0x3000; // this offset is from the PML4 base address
const DEFAULT_GUEST_MEMORY_SIZE: usize = 0x200_000; // 2MB

/// Represents a memory section in the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxMemorySection {
    /// Name of the memory section
    pub name: String,
    /// Flags for the memory section
    pub flags: MemoryRegionFlags,
    /// Offset of the memory section in the guest's address space
    pub page_aligned_guest_offset: usize,
    /// Host address of the memory section
    pub host_address: Option<usize>,
    /// Size of the memory section
    pub page_aligned_size: usize,
}

/// Holds the memory sections of the sandbox.
/// We use a BTreeMap to keep the sections sorted by offset.
#[derive(Clone)]
pub(crate) struct SandboxMemorySections {
    /// A map of memory sections, sorted by offset
    pub sections: BTreeMap<usize, SandboxMemorySection>,
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
        self.sections
            .iter()
            .find(|(_, section)| section.name == DEFAULT_GUEST_CODE_SECTION_NAME)
            .map(|(_, section)| section.page_aligned_guest_offset)
    }

    pub(crate) fn get_hyperlight_peb_section_offset(&self) -> Option<usize> {
        self.sections
            .iter()
            .find(|(_, section)| section.name == DEFAULT_HYPERLIGHT_PEB_SECTION_NAME)
            .map(|(_, section)| section.page_aligned_guest_offset)
    }

    pub(crate) fn get_hyperlight_peb_section_host_address(&self) -> Option<usize> {
        self.sections
            .iter()
            .find(|(_, section)| section.name == DEFAULT_HYPERLIGHT_PEB_SECTION_NAME)
            .map(|(_, section)| section.host_address.unwrap())
    }

    pub(crate) fn get_tmp_stack_section_offset(&self) -> Option<usize> {
        self.sections
            .iter()
            .find(|(_, section)| section.name == DEFAULT_TMP_STACK_SECTION_NAME)
            .map(|(_, section)| section.page_aligned_guest_offset)
    }

    pub(crate) fn get_paging_structures_offset(&self) -> Option<usize> {
        self.sections
            .iter()
            .find(|(_, section)| section.name == DEFAULT_PAGING_STRUCTURES_SECTION_NAME)
            .map(|(_, section)| section.page_aligned_guest_offset)
    }

    pub(crate) fn get_custom_guest_memory_section_offset(&self) -> usize {
        let offset = self
            .sections
            .iter()
            .find(|(_, section)| section.name == DEFAULT_CUSTOM_GUEST_MEMORY_SECTION_NAME)
            .map(|(_, section)| section.page_aligned_guest_offset);

        // if not set, we have a critical error and we should panic
        if offset.is_none() {
            panic!("Custom guest memory section not found");
        }

        offset.unwrap()
    }

    pub(crate) fn get_custom_guest_memory_section_host_address(&self) -> usize {
        let host_address = self
            .sections
            .iter()
            .find(|(_, section)| section.name == DEFAULT_CUSTOM_GUEST_MEMORY_SECTION_NAME)
            .map(|(_, section)| section.host_address.unwrap());

        // if not set, we have a critical error and we should panic
        if host_address.is_none() {
            panic!("Custom guest memory section not found");
        }

        host_address.unwrap()
    }

    pub(crate) fn get_custom_guest_memory_size(&self) -> usize {
        let size = self
            .sections
            .iter()
            .find(|(_, section)| section.name == DEFAULT_CUSTOM_GUEST_MEMORY_SECTION_NAME)
            .map(|(_, section)| section.page_aligned_size);

        // if not set, we have a critical error and we should panic
        if size.is_none() {
            panic!("Custom guest memory section not found");
        }

        size.unwrap()
    }

    pub(crate) fn get_total_size(&self) -> usize {
        self.sections
            .values()
            .map(|section| section.page_aligned_size)
            .sum()
    }

    pub(crate) fn read_hyperlight_peb(&self) -> Result<HyperlightPEB> {
        let peb_offset = self
            .get_hyperlight_peb_section_host_address()
            .ok_or(new_error!("Hyperlight PEB section not found"))?
            as *const HyperlightPEB;

        Ok(unsafe { peb_offset.read() })
    }

    pub(crate) fn write_hyperlight_peb(&mut self, peb: HyperlightPEB) -> Result<()> {
        let peb_offset = self
            .get_hyperlight_peb_section_host_address()
            .ok_or(new_error!("Hyperlight PEB section not found"))?
            as *mut HyperlightPEB;

        unsafe { peb_offset.copy_from(&peb, 1) };

        Ok(())
    }

    pub(crate) fn sections(&self) -> impl Iterator<Item = &SandboxMemorySection> {
        self.sections.values()
    }

    pub(crate) fn insert(&mut self, offset: usize, section: SandboxMemorySection) {
        self.sections.insert(offset, section);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&usize, &SandboxMemorySection)> {
        self.sections.iter()
    }
}

use bitflags::bitflags;
#[cfg(mshv)]
use mshv_bindings::hv_x64_memory_intercept_message;
#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::{self, WHV_MEMORY_ACCESS_TYPE};
bitflags! {
    /// flags representing memory permission for a memory region
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct MemoryRegionFlags: u32 {
        /// no permissions
        const NONE = 0;
        /// allow guest to read
        const READ = 1;
        /// allow guest to write
        const WRITE = 2;
        /// allow guest to execute
        const EXECUTE = 4;
        /// identifier that this is a stack guard page
        const STACK_GUARD = 8;
    }
}

impl std::fmt::Display for MemoryRegionFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            write!(f, "NONE")
        } else {
            let mut first = true;
            if self.contains(MemoryRegionFlags::READ) {
                write!(f, "READ")?;
                first = false;
            }
            if self.contains(MemoryRegionFlags::WRITE) {
                if !first {
                    write!(f, " | ")?;
                }
                write!(f, "WRITE")?;
                first = false;
            }
            if self.contains(MemoryRegionFlags::EXECUTE) {
                if !first {
                    write!(f, " | ")?;
                }
                write!(f, "EXECUTE")?;
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
impl TryFrom<WHV_MEMORY_ACCESS_TYPE> for MemoryRegionFlags {
    type Error = crate::HyperlightError;

    fn try_from(flags: WHV_MEMORY_ACCESS_TYPE) -> crate::Result<Self> {
        match flags {
            Hypervisor::WHvMemoryAccessRead => Ok(MemoryRegionFlags::READ),
            Hypervisor::WHvMemoryAccessWrite => Ok(MemoryRegionFlags::WRITE),
            Hypervisor::WHvMemoryAccessExecute => Ok(MemoryRegionFlags::EXECUTE),
            _ => Err(crate::HyperlightError::Error(
                "unknown memory access type".to_string(),
            )),
        }
    }
}

#[cfg(mshv)]
impl TryFrom<hv_x64_memory_intercept_message> for MemoryRegionFlags {
    type Error = crate::HyperlightError;

    fn try_from(msg: hv_x64_memory_intercept_message) -> Result<Self> {
        let access_type = msg.header.intercept_access_type;
        match access_type {
            0 => Ok(MemoryRegionFlags::READ),
            1 => Ok(MemoryRegionFlags::WRITE),
            2 => Ok(MemoryRegionFlags::EXECUTE),
            _ => Err(crate::HyperlightError::Error(
                "unknown memory access type".to_string(),
            )),
        }
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

/// A builder for creating a sandbox.
///
/// - Example usage:
/// ```norun
/// let sandbox_builder = SandboxBuilder::new(GuestBinary::FilePath("path/to/binary"))
///     .set_guest_memory_size(0x200_000)
///     .set_max_initialization_time(2000)
///     .set_max_execution_time(1000)
///     .set_sandbox_run_options(SandboxRunOptions::RunInHypervisor)
///     .set_guest_debug_info(DebugInfo { port: 8080 });
///
/// let uninitialized_sandbox = sandbox_builder.build()?;
/// ```
pub struct SandboxBuilder {
    guest_binary: GuestBinary,
    memory_sections: SandboxMemorySections,
    init_rsp: Option<u64>,
    guest_memory_size: usize,
    max_initialization_time: Duration,
    max_execution_time: Duration,
    sandbox_run_options: SandboxRunOptions,
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
            guest_binary,
            memory_sections: SandboxMemorySections::new(),
            init_rsp: None,
            guest_memory_size: DEFAULT_GUEST_MEMORY_SIZE,
            max_initialization_time: Duration::from_millis(
                SandboxConfiguration::DEFAULT_MAX_INITIALIZATION_TIME as u64,
            ),
            max_execution_time: Duration::from_millis(
                SandboxConfiguration::DEFAULT_MAX_EXECUTION_TIME as u64,
            ),
            sandbox_run_options: SandboxRunOptions::default(),
            #[cfg(gdb)]
            guest_debug_info: None,
        };

        let guest_binary_size = sandbox_builder.guest_binary.to_exe_info()?.loaded_size();

        Ok(sandbox_builder.add_memory_section(
            DEFAULT_GUEST_CODE_SECTION_NAME,
            guest_binary_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
        ))
    }

    /// Set the size of the guest memory. By default, the guest
    /// memory is 2MB.
    pub fn set_guest_memory_size(mut self, guest_memory_size: usize) -> Self {
        self.guest_memory_size = guest_memory_size;
        self
    }

    /// Set the maximum time the sandbox is allowed to take
    /// to initialize (in milliseconds). By default, the sandbox
    /// can take 2000ms to initialize.
    // TODO: change this to make the default be that the
    // sandbox can take as long as it needs to initialize.
    pub fn set_max_initialization_time(mut self, max_initialization_time: u64) -> Self {
        self.max_initialization_time = Duration::from_millis(max_initialization_time);
        self
    }

    /// Set the maximum time the sandbox is allowed to take
    /// to execute a guest function (in milliseconds). By default,
    /// the sandbox can 1000ms to execute a guest function.
    // TODO: change this to make the default be that the
    // sandbox can take as long as it needs to execute a guest function.
    pub fn set_max_execution_time(mut self, max_execution_time: u64) -> Self {
        self.max_initialization_time = Duration::from_millis(max_execution_time);
        self
    }

    /// Set the sandbox run mode. Options:
    /// - SandboxRunOptions::RunInHypervisor: Run the sandbox in a hypervisor.
    /// - SandboxRunOptions::RunInProcess(false): Run the sandbox in process (i.e., without a
    ///     hypervisor), but also without using the Windows LoadLibrary to load the guest binary.
    /// - SandboxRunOptions::RunInProcess(true): Run the sandbox in process (i.e., without a
    ///     hypervisor), and use the Windows LoadLibrary to load the guest binary.
    pub fn set_sandbox_run_options(
        mut self,
        sandbox_run_options: SandboxRunOptions,
    ) -> Result<Self> {
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

    /// Sets the initial RSP value.
    fn set_init_rsp(mut self, init_rsp: u64) -> Self {
        self.init_rsp = Some(init_rsp);
        self
    }

    /// Calculate the size of the page table structures.
    /// - Iterates through the memory sections and adds their sizes.
    /// - Adds the size of the PML4, PDPT, and PD.
    /// - Adds the maximum possible size of the PTs.
    /// - Gets the number of pages needed.
    fn calculate_page_table_size(&self) -> Result<usize> {
        let mut total_mapped_memory_size: usize = 0;

        // Iterate through the memory sections and add their sizes
        total_mapped_memory_size += self.memory_sections.get_total_size();

        // Add the size of  the PML4, PDPT and PD
        total_mapped_memory_size += 3 * PAGE_SIZE;

        // Add the maximum possible size of the PTs
        total_mapped_memory_size += 512 * PAGE_SIZE;

        // Get the number of pages needed
        let num_pages: usize = ((total_mapped_memory_size + crate::mem::mgr::AMOUNT_OF_MEMORY_PER_PT - 1)
            / crate::mem::mgr::AMOUNT_OF_MEMORY_PER_PT)
            + 1 // Round up
            + 3; // PML4, PDPT, PD

        Ok(num_pages * PAGE_SIZE)
    }

    fn round_up_to(value: usize, multiple: usize) -> usize {
        (value + multiple - 1) & !(multiple - 1)
    }

    /// Finds the next available offset that can accommodate a given size.
    fn next_free_offset(&self, page_aligned_size: usize) -> usize {
        let mut current_offset = 0;

        for section in self.memory_sections.sections() {
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

    /// Adds a memory section without specifying an offset.
    /// Automatically finds the next available aligned offset.
    fn add_memory_section(mut self, name: &str, size: usize, flags: MemoryRegionFlags) -> Self {
        let page_aligned_size = SandboxBuilder::round_up_to(size, PAGE_SIZE);
        let page_aligned_guest_offset = self.next_free_offset(page_aligned_size);

        let section = SandboxMemorySection {
            name: name.to_string(),
            page_aligned_guest_offset,
            page_aligned_size,
            host_address: None,
            flags,
        };

        self.memory_sections
            .insert(page_aligned_guest_offset, section);
        self
    }

    /// Build a default uninitialized sandbox.
    ///
    /// Default uninitialized sandboxes have the following memory layout:
    /// - +--------------------------+
    /// - |Custom guest memory (CGM) | (see note 1)
    /// - +--------------------------+
    /// - |CGM Guard page            | (4KB)
    /// - +--------------------------+ <- initial RSP
    /// - |Tmp stack                 | (16KB)
    /// - +--------------------------+
    /// - |Tmp stack guard page      | (4KB)
    /// - +--------------------------+
    /// - |HyperlightPEB             | (4KB)
    /// - +--------------------------+
    /// - |Guest code                | (binary size)
    /// - +--------------------------+ 0x0
    ///
    /// - Note 1: The guest stack size can be set manually via the `stack_size_override` parameter. If
    ///     not provided, the stack size is set to the default stack reserve size of the guest binary.
    fn set_memory_layout(mut self) -> Result<Self> {
        // Name of guard page regions
        const DEFAULT_TMP_STACK_GUARD_PAGE_NAME: &str = "tmp stack guard page";
        const DEFAULT_CUSTOM_GUEST_MEMORY_GUARD_PAGE_NAME: &str = "custom guest memory guard page";

        let tmp_stack_size = 0x200_000;
        let guest_memory_size = self.guest_memory_size;

        // (a) guest code added on `new`

        // (b) Hyperlight PEB section
        // - Hyperlight, when initializing a guest, provides it with the address and size of the PEB
        // region that this function creates. In this region, there is HyperlightPEB struct serialized
        // via Flatbuffers. The guest can deserialize this struct and populate it to inform the host
        // how it will operate.
        self = self.add_memory_section(
            DEFAULT_HYPERLIGHT_PEB_SECTION_NAME,
            PAGE_SIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
        );

        // (c) tmp stack guard page
        self = self.add_memory_section(
            DEFAULT_TMP_STACK_GUARD_PAGE_NAME,
            PAGE_SIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::STACK_GUARD,
        );

        // (d) tmp stack
        self = self.add_memory_section(
            DEFAULT_TMP_STACK_SECTION_NAME,
            tmp_stack_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
        );

        // - We need to create a tmp stack section to be able to set the initial RSP value.
        // The guest can later modify this to set up the stack however it wants.
        let init_rsp = self
            .memory_sections
            .get_tmp_stack_section_offset()
            .ok_or("tmp stack section not found")?
            + tmp_stack_size;
        self = self.set_init_rsp(init_rsp as u64);

        // (e) custom guest memory guard page
        // - Optimally, the guest will set up its own stack to leverage this stack guard page.
        self = self.add_memory_section(
            DEFAULT_CUSTOM_GUEST_MEMORY_GUARD_PAGE_NAME,
            PAGE_SIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::STACK_GUARD,
        );

        // (f) custom guest memory
        self = self.add_memory_section(
            DEFAULT_CUSTOM_GUEST_MEMORY_SECTION_NAME,
            guest_memory_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
        );

        Ok(self)
    }

    /// Loads the guest binary. There are three modes:
    /// 1. Run in process and use LoadLibrary (makes the memory executable)
    /// 2. Run in process and not use LoadLibrary (makes the memory executable)
    /// 3. Run in hypervisor
    ///
    /// - Sets the load address in shared memory.
    /// - Returns load address.
    fn load_guest_binary(
        &self,
        init_rsp: u64,
        memory_sections: SandboxMemorySections,
        mut exclusive_shared_memory: ExclusiveSharedMemory,
    ) -> Result<SandboxMemoryManager<ExclusiveSharedMemory>> {
        let run_inprocess = self.sandbox_run_options.in_process();
        let use_loadlib = self.sandbox_run_options.use_loadlib();
        let mut guest_binary_exe_info = self.guest_binary.to_exe_info()?;
        let guest_code_offset = memory_sections
            .get_guest_code_offset()
            .ok_or_else(|| new_error!("Guest code section not found"))?;

        let sandbox_memory_manager = if run_inprocess && use_loadlib {
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
                    lib.base_addr(),
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

        Ok(sandbox_memory_manager)
    }

    fn map_host_addresses(&mut self, host_base_address: usize) {
        for (_, section) in self.memory_sections.clone().iter() {
            let host_address = host_base_address + section.page_aligned_guest_offset;
            self.memory_sections
                .sections
                .get_mut(&section.page_aligned_guest_offset)
                .unwrap()
                .host_address = Some(host_address);
        }
    }

    /// Build the sandbox.
    ///
    /// Building includes the following steps:
    /// - Set up the sandbox configuration
    /// - Set up the sandbox memory layout
    /// - Configure paging structures
    /// - Allocate memory on the host
    /// - Set the run mode
    /// - Set the default guest stack and heap sizes
    /// - Map host addresses to guest addresses
    /// - Load the guest binary
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

        let sandbox_builder = self.set_memory_layout()?;

        // Add sandbox memory section for paging
        let paging_sections_size = sandbox_builder.calculate_page_table_size()?;
        let mut sandbox_builder = sandbox_builder.add_memory_section(
            DEFAULT_PAGING_STRUCTURES_SECTION_NAME,
            paging_sections_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
        );

        // Allocate memory on host
        let exclusive_shared_memory =
            ExclusiveSharedMemory::new(sandbox_builder.memory_sections.get_total_size())?;

        // Set run mode
        let run_mode = if sandbox_builder.sandbox_run_options.in_process() {
            #[cfg(target_os = "windows")]
            {
                RunMode::InProcessWindows
            }
            #[cfg(target_os = "linux")]
            {
                RunMode::InProcessLinux
            }
        } else {
            RunMode::Hypervisor
        };

        // Default guest stack and heap sizes
        let guest_stack_size = sandbox_builder.guest_binary.to_exe_info()?.stack_reserve();
        let guest_heap_size = sandbox_builder.guest_binary.to_exe_info()?.heap_reserve();

        // Map host addresses to guest addresses
        sandbox_builder.map_host_addresses(exclusive_shared_memory.base_addr());

        let hyperlight_peb = HyperlightPEB::new(
            run_mode,
            guest_heap_size,
            guest_stack_size,
            sandbox_builder
                .memory_sections
                .get_custom_guest_memory_section_host_address() as u64,
            sandbox_builder
                .memory_sections
                .get_custom_guest_memory_section_offset() as u64,
            sandbox_builder
                .memory_sections
                .get_custom_guest_memory_size() as u64,
        );

        let mut sandbox_memory_manager = sandbox_builder.load_guest_binary(
            sandbox_builder
                .init_rsp
                .ok_or(new_error!("SandboxBuilder: init_rsp not set"))?,
            sandbox_builder.memory_sections.clone(),
            exclusive_shared_memory,
        )?;

        sandbox_memory_manager
            .memory_sections
            .write_hyperlight_peb(hyperlight_peb)?;

        //TODO(danbugs:297): bring back host functions and adding host_printer

        Ok(UninitializedSandbox::new(
            sandbox_memory_manager,
            sandbox_configuration,
            #[cfg(gdb)]
            sandbox_builder.guest_debug_info,
        ))
    }
}

#[cfg(mshv)]
impl From<SandboxMemorySection> for mshv_bindings::mshv_user_mem_region {
    fn from(section: SandboxMemorySection) -> Self {
        let size = section.page_aligned_size as u64;
        let guest_pfn = (section.page_aligned_guest_offset as u64) >> 12;
        let userspace_addr = section.host_address.unwrap_or(0) as u64;

        #[cfg(mshv2)]
        {
            let mut flags = 0;
            if section.flags.contains(MemoryRegionFlags::READ) {
                flags |= HV_MAP_GPA_READABLE;
            }
            if section.flags.contains(MemoryRegionFlags::WRITE) {
                flags |= HV_MAP_GPA_WRITABLE;
            }
            if section.flags.contains(MemoryRegionFlags::EXECUTE) {
                flags |= HV_MAP_GPA_EXECUTABLE;
            }
            if section.flags.is_empty() || section.flags.contains(MemoryRegionFlags::NONE) {
                flags |= HV_MAP_GPA_PERMISSIONS_NONE;
            }

            mshv_bindings::mshv_user_mem_region {
                guest_pfn,
                size,
                userspace_addr,
                flags,
            }
        }
        #[cfg(mshv3)]
        {
            let mut flags: u8 = 0;
            if section.flags.contains(MemoryRegionFlags::WRITE) {
                flags |= 1 << MSHV_SET_MEM_BIT_WRITABLE;
            }
            if section.flags.contains(MemoryRegionFlags::EXECUTE) {
                flags |= 1 << MSHV_SET_MEM_BIT_EXECUTABLE;
            }
            if section.flags.is_empty() || section.flags.contains(MemoryRegionFlags::NONE) {
                flags |= 1 << MSHV_SET_MEM_BIT_UNMAP;
            }

            mshv_bindings::mshv_user_mem_region {
                guest_pfn,
                size,
                userspace_addr,
                flags,
                ..Default::default()
            }
        }
    }
}

// Check to see if the current version of Windows is supported
// Hyperlight is only supported on Windows 11 and Windows Server 2022 and later
#[cfg(target_os = "windows")]
fn check_windows_version() -> Result<()> {
    use windows_version::{is_server, OsVersion};
    const WINDOWS_MAJOR: u32 = 10;
    const WINDOWS_MINOR: u32 = 0;
    const WINDOWS_PACK: u32 = 0;

    // Windows Server 2022 has version numbers 10.0.20348 or greater
    if is_server() {
        if OsVersion::current() < OsVersion::new(WINDOWS_MAJOR, WINDOWS_MINOR, WINDOWS_PACK, 20348)
        {
            return Err(crate::new_error!(
                "Hyperlight Requires Windows Server 2022 or newer"
            ));
        }
    } else if OsVersion::current()
        < OsVersion::new(WINDOWS_MAJOR, WINDOWS_MINOR, WINDOWS_PACK, 22000)
    {
        return Err(crate::new_error!("Hyperlight Requires Windows 11 or newer"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use hyperlight_common::flatbuffer_wrappers::function_types::{
        ParameterValue, ReturnType, ReturnValue,
    };
    use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::GuestFunctionParameterTypeMismatch;
    use hyperlight_testing::simple_guest_as_string;

    use super::*;
    use crate::func::HostFunction2;
    use crate::sandbox_state::sandbox::EvolvableSandbox;
    use crate::sandbox_state::transition::Noop;
    use crate::HyperlightError;

    #[test]
    fn test_sandbox_builder() -> Result<()> {
        // Tests building an uninitialized sandbox w/ the sandbox builder
        let sandbox_builder =
            SandboxBuilder::new(GuestBinary::FilePath(simple_guest_as_string()?))?;

        // let sandbox_builder = sandbox_builder.set_guest_debug_info(DebugInfo { port: 8080 });

        let mut uninitialized_sandbox = sandbox_builder.build()?;

        // Tests registering a host function
        fn add(a: i32, b: i32) -> Result<i32> {
            Ok(a + b)
        }
        let host_function = Arc::new(Mutex::new(add));
        host_function.register(&mut uninitialized_sandbox, "HostAdd")?;

        // Tests evolving to a multi-use sandbox
        let mut multi_use_sandbox = uninitialized_sandbox.evolve(Noop::default())?;

        let result = multi_use_sandbox.call_guest_function_by_name(
            "Add",
            ReturnType::Int,
            Some(vec![ParameterValue::Int(1), ParameterValue::Int(41)]),
        )?;

        assert_eq!(result, ReturnValue::Int(42));

        Ok(())
    }

    #[test]
    fn test_sandbox_builder_in_process() -> Result<()> {
        // Tests building an uninitialized sandbox w/ the sandbox builder
        let sandbox_builder =
            SandboxBuilder::new(GuestBinary::FilePath(simple_guest_as_string()?))?
                .set_sandbox_run_options(SandboxRunOptions::RunInProcess(false))?;

        let mut uninitialized_sandbox = sandbox_builder.build()?;

        // Tests registering a host function
        fn add(a: i32, b: i32) -> Result<i32> {
            Ok(a + b)
        }
        let host_function = Arc::new(Mutex::new(add));
        host_function.register(&mut uninitialized_sandbox, "HostAdd")?;

        // Tests evolving to a multi-use sandbox
        let mut multi_use_sandbox = uninitialized_sandbox.evolve(Noop::default())?;

        let result = multi_use_sandbox.call_guest_function_by_name(
            "Add",
            ReturnType::Int,
            Some(vec![ParameterValue::Int(1), ParameterValue::Int(41)]),
        )?;

        assert_eq!(result, ReturnValue::Int(42));

        Ok(())
    }

    #[test]
    #[cfg(crashdump)]
    fn test_sandbox_builder_crashdump() -> Result<()> {
        // Capture list of files in /tmp before the test
        let tmp_dir = Path::new("/tmp");
        let before_files: std::collections::HashSet<_> = std::fs::read_dir(tmp_dir)
            .expect("Failed to read /tmp directory")
            .map(|e| e.unwrap().file_name())
            .collect();

        // Setup guest sandbox
        let sandbox_builder =
            SandboxBuilder::new(GuestBinary::FilePath(simple_guest_as_string()?))?;

        let mut uninitialized_sandbox = sandbox_builder.build()?;

        // Register host function
        fn add(a: i32, b: i32) -> Result<i32> {
            Ok(a + b)
        }
        let host_function = Arc::new(Mutex::new(add));
        host_function.register(&mut uninitialized_sandbox, "HostAdd")?;

        // Evolve to multi-use sandbox
        let mut multi_use_sandbox = uninitialized_sandbox.evolve(Noop::default())?;

        // Call the guest function expected to crash
        let result = multi_use_sandbox.call_guest_function_by_name(
            "StackOverflow",
            ReturnType::Void,
            Some(vec![ParameterValue::Int(512)]),
        );

        assert!(result.is_err());

        // Capture list of files in /tmp after the crash
        let after_files: std::collections::HashSet<_> = std::fs::read_dir(tmp_dir)
            .expect("Failed to read /tmp directory")
            .map(|e| e.unwrap().file_name())
            .collect();

        // Find the new files created
        let new_files: Vec<_> = after_files
            .difference(&before_files)
            .filter(|f| f.to_string_lossy().ends_with(".dmp"))
            .collect();

        assert!(!new_files.is_empty(), "No crashdump file was created.");

        // Check the crashdump file(s)
        for file_name in new_files {
            let file_path = tmp_dir.join(file_name);
            let metadata = std::fs::metadata(&file_path)?;
            assert!(
                metadata.len() > 0,
                "Crashdump file is empty: {:?}",
                file_path
            );
        }

        Ok(())
    }

    #[test]
    fn test_sandbox_builder_guest_function_fail() -> Result<()> {
        // Tests building an uninitialized sandbox w/ the sandbox builder
        let sandbox_builder =
            SandboxBuilder::new(GuestBinary::FilePath(simple_guest_as_string()?))?;

        let mut uninitialized_sandbox = sandbox_builder.build()?;

        // Tests registering a host function
        fn add(a: i32, b: i32) -> Result<i32> {
            Ok(a + b)
        }
        let host_function = Arc::new(Mutex::new(add));
        host_function.register(&mut uninitialized_sandbox, "HostAdd")?;

        // Tests evolving to a multi-use sandbox
        let mut multi_use_sandbox = uninitialized_sandbox.evolve(Noop::default())?;

        let result = multi_use_sandbox.call_guest_function_by_name(
            "Add",
            ReturnType::Int,
            // Purposefully passing the wrong parameter types
            Some(vec![ParameterValue::Float(1.0), ParameterValue::Int(41)]),
        );

        // Should get Error: GuestError(GuestFunctionParameterTypeMismatch, "Expected parameter type Int for parameter index 0 of function Add but got Float.")
        assert!(matches!(
            result,
            Err(HyperlightError::GuestError(
                GuestFunctionParameterTypeMismatch { .. },
                _,
            ))
        ));

        Ok(())
    }
}
