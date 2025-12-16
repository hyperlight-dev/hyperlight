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

use std::cmp::Ordering;

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::{
    FunctionCall, validate_guest_function_call_buffer,
};
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
#[cfg(feature = "init-paging")]
use hyperlight_common::vmem::{
    self, BasicMapping, Mapping, MappingKind, PAGE_TABLE_SIZE, PageTableEntry, PhysAddr,
};
use tracing::{Span, instrument};

use super::exe::ExeInfo;
use super::layout::SandboxMemoryLayout;
use super::memory_region::MemoryRegion;
#[cfg(feature = "init-paging")]
use super::memory_region::MemoryRegionFlags;
use super::ptr::{GuestPtr, RawPtr};
use super::ptr_offset::Offset;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::snapshot::Snapshot;
use crate::sandbox::uninitialized::GuestBlob;
use crate::{Result, log_then_return, new_error};

/// The size of stack guard cookies
pub(crate) const STACK_COOKIE_LEN: usize = 16;

/// A struct that is responsible for laying out and managing the memory
/// for a given `Sandbox`.
#[derive(Clone)]
pub(crate) struct SandboxMemoryManager<S> {
    /// Shared memory for the Sandbox
    pub(crate) shared_mem: S,
    /// The memory layout of the underlying shared memory
    pub(crate) layout: SandboxMemoryLayout,
    /// Pointer to where to load memory from
    pub(crate) load_addr: RawPtr,
    /// Offset for the execution entrypoint from `load_addr`
    pub(crate) entrypoint_offset: Offset,
    /// How many memory regions were mapped after sandbox creation
    pub(crate) mapped_rgns: u64,
    /// Stack cookie for stack guard verification
    pub(crate) stack_cookie: [u8; STACK_COOKIE_LEN],
    /// Buffer for accumulating guest abort messages
    pub(crate) abort_buffer: Vec<u8>,
}

#[cfg(feature = "init-paging")]
struct GuestPageTableBuffer {
    buffer: std::cell::RefCell<Vec<u8>>,
}

#[cfg(feature = "init-paging")]
impl vmem::TableOps for GuestPageTableBuffer {
    type TableAddr = (usize, usize); // (table_index, entry_index)

    unsafe fn alloc_table(&self) -> (usize, usize) {
        let mut b = self.buffer.borrow_mut();
        let table_index = b.len() / PAGE_TABLE_SIZE;
        let new_len = b.len() + PAGE_TABLE_SIZE;
        b.resize(new_len, 0);
        (table_index, 0)
    }

    fn entry_addr(addr: (usize, usize), offset: u64) -> (usize, usize) {
        let phys = Self::to_phys(addr) + offset;
        Self::from_phys(phys)
    }

    unsafe fn read_entry(&self, addr: (usize, usize)) -> PageTableEntry {
        let b = self.buffer.borrow();
        let byte_offset = addr.0 * PAGE_TABLE_SIZE + addr.1 * 8;
        unsafe {
            let ptr = b.as_ptr().add(byte_offset) as *const PageTableEntry;
            ptr.read_unaligned()
        }
    }

    unsafe fn write_entry(&self, addr: (usize, usize), x: PageTableEntry) {
        let mut b = self.buffer.borrow_mut();
        let byte_offset = addr.0 * PAGE_TABLE_SIZE + addr.1 * 8;
        unsafe {
            let ptr = b.as_mut_ptr().add(byte_offset) as *mut PageTableEntry;
            ptr.write_unaligned(x);
        }
    }

    fn to_phys(addr: (usize, usize)) -> PhysAddr {
        (addr.0 as u64 * PAGE_TABLE_SIZE as u64) + (addr.1 as u64 * 8)
    }

    fn from_phys(addr: PhysAddr) -> (usize, usize) {
        (
            addr as usize / PAGE_TABLE_SIZE,
            (addr as usize % PAGE_TABLE_SIZE) / 8,
        )
    }

    fn root_table(&self) -> (usize, usize) {
        (0, 0)
    }
}

#[cfg(feature = "init-paging")]
impl GuestPageTableBuffer {
    fn new() -> Self {
        GuestPageTableBuffer {
            buffer: std::cell::RefCell::new(vec![0u8; PAGE_TABLE_SIZE]),
        }
    }

    pub(crate) fn into_bytes(self) -> Box<[u8]> {
        self.buffer.into_inner().into_boxed_slice()
    }
}

impl<S> SandboxMemoryManager<S>
where
    S: SharedMemory,
{
    /// Create a new `SandboxMemoryManager` with the given parameters
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        layout: SandboxMemoryLayout,
        shared_mem: S,
        load_addr: RawPtr,
        entrypoint_offset: Offset,
        stack_cookie: [u8; STACK_COOKIE_LEN],
    ) -> Self {
        Self {
            layout,
            shared_mem,
            load_addr,
            entrypoint_offset,
            mapped_rgns: 0,
            stack_cookie,
            abort_buffer: Vec::new(),
        }
    }

    /// Get the stack cookie
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_stack_cookie(&self) -> &[u8; STACK_COOKIE_LEN] {
        &self.stack_cookie
    }

    /// Get mutable access to the abort buffer
    pub(crate) fn get_abort_buffer_mut(&mut self) -> &mut Vec<u8> {
        &mut self.abort_buffer
    }

    /// Get `SharedMemory` in `self` as a mutable reference
    #[cfg(any(gdb, test))]
    pub(crate) fn get_shared_mem_mut(&mut self) -> &mut S {
        &mut self.shared_mem
    }

    /// Set up the guest page tables in the given `SharedMemory` parameter
    /// `shared_mem`
    // TODO: This should perhaps happen earlier and use an
    // ExclusiveSharedMemory from the beginning.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    #[cfg(feature = "init-paging")]
    pub(crate) fn set_up_shared_memory(&mut self, regions: &mut [MemoryRegion]) -> Result<u64> {
        let rsp: u64 = self.layout.get_top_of_user_stack_offset() as u64
            + SandboxMemoryLayout::BASE_ADDRESS as u64
            + self.layout.stack_size as u64
            // TODO: subtracting 0x28 was a requirement for MSVC. It should no longer be
            // necessary now, but, for some reason, without this, the `multiple_parameters`
            // test from `sandbox_host_tests` fails. We should investigate this further.
            // See issue #498 for more details.
            - 0x28;

        self.shared_mem.with_exclusivity(|shared_mem| {
            let buffer = GuestPageTableBuffer::new();
            for region in regions.iter() {
                let readable = region.flags.contains(MemoryRegionFlags::READ);
                let writable = region.flags.contains(MemoryRegionFlags::WRITE)
                    // Temporary hack: the stack guard page is
                    // currently checked for in the host, rather than
                    // the guest, so we need to mark it writable in
                    // the Stage 1 translation so that the fault
                    // exception on a write is taken to the
                    // hypervisor, rather than the guest kernel
                    || region.flags.contains(MemoryRegionFlags::STACK_GUARD);
                let executable = region.flags.contains(MemoryRegionFlags::EXECUTE);
                let mapping = Mapping {
                    phys_base: region.guest_region.start as u64,
                    virt_base: region.guest_region.start as u64,
                    len: region.guest_region.len() as u64,
                    kind: MappingKind::BasicMapping(BasicMapping {
                        readable,
                        writable,
                        executable,
                    }),
                };
                unsafe { vmem::map(&buffer, mapping) };
            }
            shared_mem.copy_from_slice(&buffer.into_bytes(), SandboxMemoryLayout::PML4_OFFSET)?;
            Ok::<(), crate::HyperlightError>(())
        })??;

        Ok(rsp)
    }

    /// Create a snapshot with the given mapped regions
    pub(crate) fn snapshot(
        &mut self,
        sandbox_id: u64,
        mapped_regions: Vec<MemoryRegion>,
    ) -> Result<Snapshot> {
        Snapshot::new(&mut self.shared_mem, sandbox_id, mapped_regions)
    }

    /// This function restores a memory snapshot from a given snapshot.
    pub(crate) fn restore_snapshot(&mut self, snapshot: &Snapshot) -> Result<()> {
        self.shared_mem.restore_from_snapshot(snapshot)?;
        Ok(())
    }
}

impl SandboxMemoryManager<ExclusiveSharedMemory> {
    /// Load the binary represented by `pe_info` into memory, ensuring
    /// all necessary relocations are made prior to completing the load
    /// operation, then create a new `SharedMemory` to store the new PE
    /// file and a `SandboxMemoryLayout` to describe the layout of that
    /// new `SharedMemory`.
    ///
    /// Returns the following:
    ///
    /// - The newly-created `SharedMemory`
    /// - The `SandboxMemoryLayout` describing that `SharedMemory`
    /// - The offset to the entrypoint.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn load_guest_binary_into_memory(
        cfg: SandboxConfiguration,
        exe_info: ExeInfo,
        guest_blob: Option<&GuestBlob>,
    ) -> Result<(Self, super::exe::LoadInfo)> {
        let guest_blob_size = guest_blob.map(|b| b.data.len()).unwrap_or(0);
        let guest_blob_mem_flags = guest_blob.map(|b| b.permissions);

        let layout = SandboxMemoryLayout::new(
            cfg,
            exe_info.loaded_size(),
            usize::try_from(cfg.get_stack_size())?,
            usize::try_from(cfg.get_heap_size())?,
            guest_blob_size,
            guest_blob_mem_flags,
        )?;
        let mut shared_mem = ExclusiveSharedMemory::new(layout.get_memory_size()?)?;

        let load_addr: RawPtr = RawPtr::try_from(layout.get_guest_code_address())?;

        let entrypoint_offset = exe_info.entrypoint();

        // The load method returns a LoadInfo which can also be a different type once the
        // `mem_profile` feature is enabled.
        #[allow(clippy::let_unit_value)]
        let load_info = exe_info.load(
            load_addr.clone().try_into()?,
            &mut shared_mem.as_mut_slice()[layout.get_guest_code_offset()..],
        )?;

        let stack_cookie = rand::random::<[u8; STACK_COOKIE_LEN]>();
        let stack_offset = layout.get_top_of_user_stack_offset();
        shared_mem.copy_from_slice(&stack_cookie, stack_offset)?;

        Ok((
            Self::new(
                layout,
                shared_mem,
                load_addr,
                entrypoint_offset,
                stack_cookie,
            ),
            load_info,
        ))
    }

    /// Writes host function details to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_buffer_host_function_details(&mut self, buffer: &[u8]) -> Result<()> {
        let host_function_details = HostFunctionDetails::try_from(buffer).map_err(|e| {
            new_error!(
                "write_buffer_host_function_details: failed to convert buffer to HostFunctionDetails: {}",
                e
            )
        })?;

        let host_function_call_buffer: Vec<u8> = (&host_function_details).try_into().map_err(|_| {
            new_error!(
                "write_buffer_host_function_details: failed to convert HostFunctionDetails to Vec<u8>"
            )
        })?;

        let buffer_size = {
            let size_u64 = self
                .shared_mem
                .read_u64(self.layout.get_host_function_definitions_size_offset())?;
            usize::try_from(size_u64)
        }?;

        if host_function_call_buffer.len() > buffer_size {
            log_then_return!(
                "Host Function Details buffer is too big for the host_function_definitions buffer"
            );
        }

        self.shared_mem.copy_from_slice(
            host_function_call_buffer.as_slice(),
            self.layout.host_function_definitions_buffer_offset,
        )?;
        Ok(())
    }

    /// Write memory layout
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_memory_layout(&mut self) -> Result<()> {
        let mem_size = self.shared_mem.mem_size();
        self.layout.write(
            &mut self.shared_mem,
            SandboxMemoryLayout::BASE_ADDRESS,
            mem_size,
        )
    }

    /// Write init data
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_init_data(&mut self, user_memory: &[u8]) -> Result<()> {
        self.layout
            .write_init_data(&mut self.shared_mem, user_memory)?;
        Ok(())
    }

    /// Wraps ExclusiveSharedMemory::build
    pub fn build(
        self,
    ) -> (
        SandboxMemoryManager<HostSharedMemory>,
        SandboxMemoryManager<GuestSharedMemory>,
    ) {
        let (hshm, gshm) = self.shared_mem.build();
        (
            SandboxMemoryManager {
                shared_mem: hshm,
                layout: self.layout,
                load_addr: self.load_addr.clone(),
                entrypoint_offset: self.entrypoint_offset,
                mapped_rgns: self.mapped_rgns,
                stack_cookie: self.stack_cookie,
                abort_buffer: self.abort_buffer,
            },
            SandboxMemoryManager {
                shared_mem: gshm,
                layout: self.layout,
                load_addr: self.load_addr.clone(),
                entrypoint_offset: self.entrypoint_offset,
                mapped_rgns: self.mapped_rgns,
                stack_cookie: self.stack_cookie,
                abort_buffer: Vec::new(), // Guest doesn't need abort buffer
            },
        )
    }
}

impl SandboxMemoryManager<HostSharedMemory> {
    /// Check the stack guard of the memory in `shared_mem`, using
    /// `layout` to calculate its location.
    ///
    /// Return `true`
    /// if `shared_mem` could be accessed properly and the guard
    /// matches `cookie`. If it could be accessed properly and the
    /// guard doesn't match `cookie`, return `false`. Otherwise, return
    /// a descriptive error.
    ///
    /// This method could be an associated function instead. See
    /// documentation at the bottom `set_stack_guard` for description
    /// of why it isn't.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn check_stack_guard(&self) -> Result<bool> {
        let expected = self.stack_cookie;
        let offset = self.layout.get_top_of_user_stack_offset();
        let actual: [u8; STACK_COOKIE_LEN] = self.shared_mem.read(offset)?;
        let cmp_res = expected.iter().cmp(actual.iter());
        Ok(cmp_res == Ordering::Equal)
    }

    /// Get the address of the dispatch function in memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_pointer_to_dispatch_function(&self) -> Result<u64> {
        let guest_dispatch_function_ptr = self
            .shared_mem
            .read::<u64>(self.layout.get_dispatch_function_pointer_offset())?;

        // This pointer is written by the guest library but is accessible to
        // the guest engine so we should bounds check it before we return it.

        let guest_ptr = GuestPtr::try_from(RawPtr::from(guest_dispatch_function_ptr))?;
        guest_ptr.absolute()
    }

    /// Reads a host function call from memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_host_function_call(&mut self) -> Result<FunctionCall> {
        self.shared_mem.try_pop_buffer_into::<FunctionCall>(
            self.layout.output_data_buffer_offset,
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    /// Writes a host function call result to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_response_from_host_function_call(
        &mut self,
        res: &FunctionCallResult,
    ) -> Result<()> {
        let mut builder = FlatBufferBuilder::new();
        let data = res.encode(&mut builder);

        self.shared_mem.push_buffer(
            self.layout.input_data_buffer_offset,
            self.layout.sandbox_memory_config.get_input_data_size(),
            data,
        )
    }

    /// Writes a guest function call to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_guest_function_call(&mut self, buffer: &[u8]) -> Result<()> {
        validate_guest_function_call_buffer(buffer).map_err(|e| {
            new_error!(
                "Guest function call buffer validation failed: {}",
                e.to_string()
            )
        })?;

        self.shared_mem.push_buffer(
            self.layout.input_data_buffer_offset,
            self.layout.sandbox_memory_config.get_input_data_size(),
            buffer,
        )
    }

    /// Reads a function call result from memory.
    /// A function call result can be either an error or a successful return value.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_function_call_result(&mut self) -> Result<FunctionCallResult> {
        self.shared_mem.try_pop_buffer_into::<FunctionCallResult>(
            self.layout.output_data_buffer_offset,
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    /// Read guest log data from the `SharedMemory` contained within `self`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_guest_log_data(&mut self) -> Result<GuestLogData> {
        self.shared_mem.try_pop_buffer_into::<GuestLogData>(
            self.layout.output_data_buffer_offset,
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    pub(crate) fn clear_io_buffers(&mut self) {
        // Clear the output data buffer
        loop {
            let Ok(_) = self.shared_mem.try_pop_buffer_into::<Vec<u8>>(
                self.layout.output_data_buffer_offset,
                self.layout.sandbox_memory_config.get_output_data_size(),
            ) else {
                break;
            };
        }
        // Clear the input data buffer
        loop {
            let Ok(_) = self.shared_mem.try_pop_buffer_into::<Vec<u8>>(
                self.layout.input_data_buffer_offset,
                self.layout.sandbox_memory_config.get_input_data_size(),
            ) else {
                break;
            };
        }
    }
}

#[cfg(test)]
#[cfg(all(feature = "init-paging", target_arch = "x86_64"))]
mod tests {
    use hyperlight_common::vmem::arch::{PAGE_NX, PAGE_PRESENT, PAGE_RW};
    use hyperlight_testing::sandbox_sizes::{LARGE_HEAP_SIZE, MEDIUM_HEAP_SIZE, SMALL_HEAP_SIZE};
    use hyperlight_testing::simple_guest_as_string;

    use super::*;
    use crate::GuestBinary;
    use crate::mem::memory_region::MemoryRegionType;
    use crate::mem::shared_mem::GuestSharedMemory;
    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox::uninitialized::UninitializedSandbox;

    pub(crate) const PML4_OFFSET: usize = 0x0000;
    pub(super) const PDPT_OFFSET: usize = 0x1000;
    pub(super) const PD_OFFSET: usize = 0x2000;
    pub(super) const PT_OFFSET: usize = 0x3000;
    pub(super) const PD_GUEST_ADDRESS: usize = SandboxMemoryLayout::BASE_ADDRESS + PD_OFFSET;
    pub(super) const PDPT_GUEST_ADDRESS: usize = SandboxMemoryLayout::BASE_ADDRESS + PDPT_OFFSET;
    pub(super) const PT_GUEST_ADDRESS: usize = SandboxMemoryLayout::BASE_ADDRESS + PT_OFFSET;

    /// Helper to create a sandbox with page tables set up and return the manager
    fn create_sandbox_with_page_tables(
        config: Option<SandboxConfiguration>,
    ) -> Result<SandboxMemoryManager<GuestSharedMemory>> {
        let path = simple_guest_as_string().expect("failed to get simple guest path");
        let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(path), config)
            .expect("failed to create sandbox");

        // Build the shared memory to get GuestSharedMemory
        let (_host_mem, guest_mem) = sandbox.mgr.shared_mem.build();
        let mut mgr = SandboxMemoryManager {
            shared_mem: guest_mem,
            layout: sandbox.mgr.layout,
            load_addr: sandbox.mgr.load_addr,
            entrypoint_offset: sandbox.mgr.entrypoint_offset,
            mapped_rgns: sandbox.mgr.mapped_rgns,
            stack_cookie: sandbox.mgr.stack_cookie,
            abort_buffer: sandbox.mgr.abort_buffer,
        };

        // Get regions and set up page tables
        let mut regions = mgr.layout.get_memory_regions(&mgr.shared_mem)?;
        // set_up_shared_memory builds the page tables in shared memory
        mgr.set_up_shared_memory(&mut regions)?;

        Ok(mgr)
    }

    /// Verify a range of pages all have the same expected flags
    fn verify_page_range(
        excl_mem: &mut ExclusiveSharedMemory,
        start_addr: usize,
        end_addr: usize,
        expected_flags: u64,
        region_name: &str,
    ) -> Result<()> {
        let mut addr = start_addr;

        while addr < end_addr {
            let p = addr >> 21;
            let i = (addr >> 12) & 0x1ff;
            let pte_idx = p * 512 + i;
            let offset = PT_OFFSET + (pte_idx * 8);

            let pte_val = excl_mem.read_u64(offset)?;
            let expected_pte = (addr as u64) | expected_flags;

            if pte_val != expected_pte {
                return Err(new_error!(
                    "{} region: addr 0x{:x}: expected PTE 0x{:x}, got 0x{:x}",
                    region_name,
                    addr,
                    expected_pte,
                    pte_val
                ));
            }

            addr += 0x1000;
        }

        Ok(())
    }

    /// Get expected flags for a memory region type
    /// we dont set User RW flag since (at present) we do not run code in user mode.
    fn get_expected_flags(region: &MemoryRegion) -> u64 {
        match region.region_type {
            MemoryRegionType::Code => PAGE_PRESENT | PAGE_RW,
            MemoryRegionType::Stack => PAGE_PRESENT | PAGE_RW | PAGE_NX,
            #[cfg(feature = "executable_heap")]
            MemoryRegionType::Heap => PAGE_PRESENT | PAGE_RW,
            #[cfg(not(feature = "executable_heap"))]
            MemoryRegionType::Heap => PAGE_PRESENT | PAGE_RW | PAGE_NX,
            MemoryRegionType::GuardPage => PAGE_PRESENT | PAGE_RW | PAGE_NX,
            MemoryRegionType::InputData => PAGE_PRESENT | PAGE_RW | PAGE_NX,
            MemoryRegionType::OutputData => PAGE_PRESENT | PAGE_RW | PAGE_NX,
            MemoryRegionType::Peb => PAGE_PRESENT | PAGE_RW | PAGE_NX,
            MemoryRegionType::HostFunctionDefinitions => PAGE_PRESENT | PAGE_NX,
            MemoryRegionType::PageTables => PAGE_PRESENT | PAGE_RW | PAGE_NX,
            MemoryRegionType::InitData => translate_flags(region.flags),
        }
    }

    fn translate_flags(flags: MemoryRegionFlags) -> u64 {
        let mut page_flags = 0;

        page_flags |= PAGE_PRESENT | PAGE_RW; // Mark page as present and writeable

        if !flags.contains(MemoryRegionFlags::EXECUTE) {
            page_flags |= PAGE_NX; // Mark as non-executable if EXECUTE is not set
        }

        page_flags
    }

    /// Verify the complete paging structure for a sandbox configuration
    fn verify_paging_structure(name: &str, config: Option<SandboxConfiguration>) -> Result<()> {
        let mut mgr = create_sandbox_with_page_tables(config)?;

        let regions = mgr.layout.get_memory_regions(&mgr.shared_mem)?;
        let mem_size = mgr.layout.get_memory_size()?;

        // Calculate how many PD entries should exist based on memory size
        // Each PD entry covers 2MB (0x200000 bytes)
        // we write enough PD entries to cover all memory, so we need
        // enough entries to cover the actual memory size.
        let num_pd_entries_needed = mem_size.div_ceil(0x200000);

        mgr.shared_mem.with_exclusivity(|excl_mem| {
            // Verify PML4 entry (single entry pointing to PDPT)
            let pml4_val = excl_mem.read_u64(PML4_OFFSET)?;
            let expected_pml4 = PDPT_GUEST_ADDRESS as u64 | PAGE_PRESENT | PAGE_RW;
            if pml4_val != expected_pml4 {
                return Err(new_error!(
                    "{}: PML4[0] incorrect: expected 0x{:x}, got 0x{:x}",
                    name,
                    expected_pml4,
                    pml4_val
                ));
            }

            // Verify PDPT entry (single entry pointing to PD)
            let pdpt_val = excl_mem.read_u64(PDPT_OFFSET)?;
            let expected_pdpt = PD_GUEST_ADDRESS as u64 | PAGE_PRESENT | PAGE_RW;
            if pdpt_val != expected_pdpt {
                return Err(new_error!(
                    "{}: PDPT[0] incorrect: expected 0x{:x}, got 0x{:x}",
                    name,
                    expected_pdpt,
                    pdpt_val
                ));
            }

            // Verify PD entries that should be present (based on memory size)
            for i in 0..num_pd_entries_needed {
                let offset = PD_OFFSET + (i * 8);
                let pd_val = excl_mem.read_u64(offset)?;
                let expected_pt_addr = PT_GUEST_ADDRESS as u64 + (i as u64 * 4096);
                let expected_pd = expected_pt_addr | PAGE_PRESENT | PAGE_RW;
                if pd_val != expected_pd {
                    return Err(new_error!(
                        "{}: PD[{}] incorrect: expected 0x{:x}, got 0x{:x}",
                        name,
                        i,
                        expected_pd,
                        pd_val
                    ));
                }
            }

            // Verify remaining PD entries are not present (0)
            for i in num_pd_entries_needed..512 {
                let offset = PD_OFFSET + (i * 8);
                let pd_val = excl_mem.read_u64(offset)?;
                if pd_val != 0 {
                    return Err(new_error!(
                        "{}: PD[{}] should be 0 (not present), got 0x{:x}",
                        name,
                        i,
                        pd_val
                    ));
                }
            }

            // Verify PTEs for each memory region
            for region in &regions {
                let start = region.guest_region.start;
                let end = region.guest_region.end;
                let expected_flags = get_expected_flags(region);

                verify_page_range(
                    excl_mem,
                    start,
                    end,
                    expected_flags,
                    &format!("{} {:?}", name, region.region_type),
                )?;
            }

            Ok(())
        })??;

        Ok(())
    }

    /// Test the complete paging structure (PML4, PDPT, PD, and all PTEs) for
    /// sandboxes of different sizes: default, small (8MB), medium (64MB), and large (256MB)
    #[test]
    fn test_page_table_contents() {
        let test_cases: [(&str, Option<SandboxConfiguration>); 4] = [
            ("default", None),
            ("small (8MB heap)", {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(SMALL_HEAP_SIZE);
                Some(cfg)
            }),
            ("medium (64MB heap)", {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(MEDIUM_HEAP_SIZE);
                Some(cfg)
            }),
            ("large (256MB heap)", {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(LARGE_HEAP_SIZE);
                Some(cfg)
            }),
        ];

        for (name, config) in test_cases {
            verify_paging_structure(name, config)
                .unwrap_or_else(|e| panic!("Page table verification failed for {}: {}", name, e));
        }
    }
}
