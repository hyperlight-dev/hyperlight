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
#[cfg(feature = "init-paging")]
use std::cmp::Ordering;

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::{
    FunctionCall, validate_guest_function_call_buffer,
};
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
#[cfg(feature = "init-paging")]
use hyperlight_common::vmem;
#[cfg(feature = "init-paging")]
use hyperlight_common::vmem::{PAGE_TABLE_SIZE, PageTableEntry, PhysAddr};
use tracing::{Span, instrument};

use super::layout::SandboxMemoryLayout;
use super::memory_region::MemoryRegion;
use super::ptr::{GuestPtr, RawPtr};
use super::ptr_offset::Offset;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory};
use crate::sandbox::snapshot::Snapshot;
use crate::{Result, new_error};

/// The size of stack guard cookies
pub(crate) const STACK_COOKIE_LEN: usize = 16;

/// A struct that is responsible for laying out and managing the memory
/// for a given `Sandbox`.
#[derive(Clone)]
pub(crate) struct SandboxMemoryManager<S> {
    /// Shared memory for the Sandbox
    pub(crate) shared_mem: S,
    /// Scratch memory for the Sandbox
    pub(crate) scratch_mem: S,
    /// The memory layout of the underlying shared memory
    pub(crate) layout: SandboxMemoryLayout,
    /// Pointer to where to load memory from
    pub(crate) load_addr: RawPtr,
    /// Offset for the execution entrypoint from `load_addr`
    pub(crate) entrypoint_offset: Option<Offset>,
    /// How many memory regions were mapped after sandbox creation
    pub(crate) mapped_rgns: u64,
    /// Stack cookie for stack guard verification
    pub(crate) stack_cookie: [u8; STACK_COOKIE_LEN],
    /// Buffer for accumulating guest abort messages
    pub(crate) abort_buffer: Vec<u8>,
}

#[cfg(feature = "init-paging")]
pub(crate) struct GuestPageTableBuffer {
    buffer: std::cell::RefCell<Vec<u8>>,
    phys_base: usize,
}

#[cfg(feature = "init-paging")]
impl vmem::TableOps for GuestPageTableBuffer {
    type TableAddr = (usize, usize); // (table_index, entry_index)

    unsafe fn alloc_table(&self) -> (usize, usize) {
        let mut b = self.buffer.borrow_mut();
        let table_index = b.len() / PAGE_TABLE_SIZE;
        let new_len = b.len() + PAGE_TABLE_SIZE;
        b.resize(new_len, 0);
        (self.phys_base / PAGE_TABLE_SIZE + table_index, 0)
    }

    fn entry_addr(addr: (usize, usize), offset: u64) -> (usize, usize) {
        // Convert to physical address, add offset, convert back
        let phys = Self::to_phys(addr) + offset;
        Self::from_phys(phys)
    }

    unsafe fn read_entry(&self, addr: (usize, usize)) -> PageTableEntry {
        let b = self.buffer.borrow();
        let byte_offset =
            (addr.0 - self.phys_base / PAGE_TABLE_SIZE) * PAGE_TABLE_SIZE + addr.1 * 8;
        b.get(byte_offset..byte_offset + 8)
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map(u64::from_ne_bytes)
            .unwrap_or(0)
    }

    unsafe fn write_entry(
        &self,
        addr: (usize, usize),
        entry: PageTableEntry,
    ) -> Option<(usize, usize)> {
        let mut b = self.buffer.borrow_mut();
        let byte_offset =
            (addr.0 - self.phys_base / PAGE_TABLE_SIZE) * PAGE_TABLE_SIZE + addr.1 * 8;
        if let Some(slice) = b.get_mut(byte_offset..byte_offset + 8) {
            slice.copy_from_slice(&entry.to_ne_bytes());
        }
        None
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
        (self.phys_base / PAGE_TABLE_SIZE, 0)
    }
}

#[cfg(feature = "init-paging")]
impl GuestPageTableBuffer {
    pub(crate) fn new(phys_base: usize) -> Self {
        GuestPageTableBuffer {
            buffer: std::cell::RefCell::new(vec![0u8; PAGE_TABLE_SIZE]),
            phys_base,
        }
    }

    pub(crate) fn size(&self) -> usize {
        self.buffer.borrow().len()
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
        scratch_mem: S,
        load_addr: RawPtr,
        entrypoint_offset: Option<Offset>,
        stack_cookie: [u8; STACK_COOKIE_LEN],
    ) -> Self {
        Self {
            layout,
            shared_mem,
            scratch_mem,
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

    /// Create a snapshot with the given mapped regions
    pub(crate) fn snapshot(
        &mut self,
        sandbox_id: u64,
        mapped_regions: Vec<MemoryRegion>,
    ) -> Result<Snapshot> {
        Snapshot::new(
            &mut self.shared_mem,
            sandbox_id,
            self.layout,
            crate::mem::exe::LoadInfo::dummy(),
            mapped_regions,
        )
    }
}

impl SandboxMemoryManager<ExclusiveSharedMemory> {
    pub(crate) fn from_snapshot(s: &Snapshot) -> Result<Self> {
        let layout = *s.layout();
        let mut shared_mem = ExclusiveSharedMemory::new(s.mem_size())?;
        shared_mem.copy_from_slice(s.memory(), 0)?;
        let scratch_mem = ExclusiveSharedMemory::new(s.layout().get_scratch_size())?;
        let load_addr: RawPtr = RawPtr::try_from(layout.get_guest_code_address())?;
        let stack_cookie = rand::random::<[u8; STACK_COOKIE_LEN]>();
        let entrypoint_gva = s.preinitialise();
        let entrypoint_offset = entrypoint_gva.map(|x| (x - u64::from(&load_addr)).into());
        Ok(Self::new(
            layout,
            shared_mem,
            scratch_mem,
            load_addr,
            entrypoint_offset,
            stack_cookie,
        ))
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

    /// Wraps ExclusiveSharedMemory::build
    // Morally, this should not have to be a Result: this operation is
    // infallible. The source of the Result is
    // update_scratch_bookkeeping(), which calls functions that can
    // fail due to bounds checks (which are statically known to be ok
    // in this situation) or due to failing to take the scratch shared
    // memory lock, but the scratch shared memory is built in this
    // function, its lock does not escape before the end of the
    // function, and the lock is taken by no other code path, so we
    // know it is not contended.
    pub fn build(
        self,
    ) -> Result<(
        SandboxMemoryManager<HostSharedMemory>,
        SandboxMemoryManager<GuestSharedMemory>,
    )> {
        let (hshm, gshm) = self.shared_mem.build();
        let (hscratch, gscratch) = self.scratch_mem.build();
        let mut host_mgr = SandboxMemoryManager {
            shared_mem: hshm,
            scratch_mem: hscratch,
            layout: self.layout,
            load_addr: self.load_addr.clone(),
            entrypoint_offset: self.entrypoint_offset,
            mapped_rgns: self.mapped_rgns,
            stack_cookie: self.stack_cookie,
            abort_buffer: self.abort_buffer,
        };
        let guest_mgr = SandboxMemoryManager {
            shared_mem: gshm,
            scratch_mem: gscratch,
            layout: self.layout,
            load_addr: self.load_addr.clone(),
            entrypoint_offset: self.entrypoint_offset,
            mapped_rgns: self.mapped_rgns,
            stack_cookie: self.stack_cookie,
            abort_buffer: Vec::new(), // Guest doesn't need abort buffer
        };
        host_mgr.update_scratch_bookkeeping()?;
        Ok((host_mgr, guest_mgr))
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
    #[cfg(feature = "init-paging")]
    pub(crate) fn check_stack_guard(&self) -> Result<bool> {
        let expected = self.stack_cookie;
        let offset = self.layout.get_top_of_user_stack_offset();
        let actual: [u8; STACK_COOKIE_LEN] = self.shared_mem.read(offset)?;
        let cmp_res = expected.iter().cmp(actual.iter());
        Ok(cmp_res == Ordering::Equal)
    }

    #[cfg(not(feature = "init-paging"))]
    pub(crate) fn check_stack_guard(&self) -> Result<bool> {
        Ok(true)
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

    /// This function restores a memory snapshot from a given snapshot.
    pub(crate) fn restore_snapshot(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<Option<GuestSharedMemory>> {
        if self.shared_mem.mem_size() != snapshot.mem_size() {
            return Err(new_error!(
                "Snapshot size does not match current memory size: {} != {}",
                self.shared_mem.raw_mem_size(),
                snapshot.mem_size()
            ));
        }
        self.shared_mem.restore_from_snapshot(snapshot)?;
        let new_scratch_size = snapshot.layout().get_scratch_size();
        let gscratch = if new_scratch_size == self.scratch_mem.mem_size() {
            self.scratch_mem.zero()?;
            None
        } else {
            let new_scratch_mem = ExclusiveSharedMemory::new(new_scratch_size)?;
            let (hscratch, gscratch) = new_scratch_mem.build();
            // Even though this destroys the reference to the host
            // side of the old scratch mapping, the VM should still
            // own the reference to the guest side of the old scratch
            // mapping, so it won't actually be deallocated until it
            // has been unmapped from the VM.
            self.scratch_mem = hscratch;

            Some(gscratch)
        };
        self.update_scratch_bookkeeping()?;
        Ok(gscratch)
    }

    fn update_scratch_bookkeeping(&mut self) -> Result<()> {
        let scratch_size = self.scratch_mem.mem_size();

        let size_offset =
            scratch_size - hyperlight_common::layout::SCRATCH_TOP_SIZE_OFFSET as usize;
        self.scratch_mem
            .write::<u64>(size_offset, scratch_size as u64)?;

        let alloc_offset =
            scratch_size - hyperlight_common::layout::SCRATCH_TOP_ALLOCATOR_OFFSET as usize;
        self.scratch_mem.write::<u64>(
            alloc_offset,
            hyperlight_common::layout::scratch_base_gpa(scratch_size),
        )?;

        Ok(())
    }
}

#[cfg(test)]
#[cfg(all(feature = "init-paging", target_arch = "x86_64"))]
mod tests {
    use hyperlight_common::vmem::PAGE_TABLE_SIZE;
    use hyperlight_common::vmem::arch::{PAGE_NX, PAGE_PRESENT, PAGE_RW, PTE_ADDR_MASK};
    use hyperlight_testing::sandbox_sizes::{LARGE_HEAP_SIZE, MEDIUM_HEAP_SIZE, SMALL_HEAP_SIZE};
    use hyperlight_testing::simple_guest_as_string;

    use crate::GuestBinary;
    use crate::mem::memory_region::MemoryRegionFlags;
    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox::snapshot::Snapshot;

    /// Convert MemoryRegionFlags to expected PTE flags.
    fn expected_pte_flags(flags: MemoryRegionFlags) -> u64 {
        let mut pte = PAGE_PRESENT;

        // Writable if WRITE or STACK_GUARD (stack guard needs to be writable
        // so faults go to hypervisor, not guest kernel)
        if flags.contains(MemoryRegionFlags::WRITE)
            || flags.contains(MemoryRegionFlags::STACK_GUARD)
        {
            pte |= PAGE_RW;
        }

        // NX unless EXECUTE is set
        if !flags.contains(MemoryRegionFlags::EXECUTE) {
            pte |= PAGE_NX;
        }

        pte
    }

    /// Walk page tables to get PTE for a virtual address.
    /// Returns None if address is not mapped.
    fn get_pte(memory: &[u8], pt_offset: usize, pt_base_gpa: usize, vaddr: u64) -> Option<u64> {
        let pml4_idx = ((vaddr >> 39) & 0x1ff) as usize;
        let pdpt_idx = ((vaddr >> 30) & 0x1ff) as usize;
        let pd_idx = ((vaddr >> 21) & 0x1ff) as usize;
        let pt_idx = ((vaddr >> 12) & 0x1ff) as usize;

        let read_entry = |table_gpa: usize, index: usize| -> Option<u64> {
            let entry_gpa = table_gpa + index * 8;
            let offset = entry_gpa - pt_base_gpa + pt_offset;
            if offset + 8 > memory.len() {
                return None;
            }
            let entry = u64::from_ne_bytes(memory[offset..offset + 8].try_into().ok()?);
            if entry & PAGE_PRESENT != 0 {
                Some(entry)
            } else {
                None
            }
        };

        let pml4e = read_entry(pt_base_gpa, pml4_idx)?;
        let pdpt_gpa = (pml4e & PTE_ADDR_MASK) as usize;

        let pdpte = read_entry(pdpt_gpa, pdpt_idx)?;
        let pd_gpa = (pdpte & PTE_ADDR_MASK) as usize;

        let pde = read_entry(pd_gpa, pd_idx)?;
        let pt_gpa = (pde & PTE_ADDR_MASK) as usize;

        read_entry(pt_gpa, pt_idx)
    }

    /// Verify page tables for a given configuration.
    /// Creates a Snapshot and verifies every page in every region has correct PTEs.
    fn verify_page_tables(name: &str, config: SandboxConfiguration) {
        let path = simple_guest_as_string().expect("failed to get simple guest path");
        let snapshot = Snapshot::from_env(GuestBinary::FilePath(path), config)
            .unwrap_or_else(|e| panic!("{}: failed to create snapshot: {}", name, e));

        let memory = snapshot.memory();
        let layout = snapshot.layout();
        let pt_offset = layout.get_pt_offset();
        let pt_base_gpa = super::super::layout::SandboxMemoryLayout::BASE_ADDRESS + pt_offset;
        let regions = snapshot.regions();

        // Mask for the flags we care about (PRESENT, RW, NX)
        const FLAG_MASK: u64 = PAGE_PRESENT | PAGE_RW | PAGE_NX;

        // Verify NULL page (0x0) is NOT mapped
        assert!(
            get_pte(memory, pt_offset, pt_base_gpa, 0).is_none(),
            "{}: NULL page (0x0) should NOT be mapped",
            name
        );

        // Verify every page in every region
        for region in regions {
            let expected = expected_pte_flags(region.flags);
            let mut addr = region.guest_region.start as u64;

            while addr < region.guest_region.end as u64 {
                let pte = get_pte(memory, pt_offset, pt_base_gpa, addr).unwrap_or_else(|| {
                    panic!(
                        "{}: {:?} region: address 0x{:x} is not mapped",
                        name, region.region_type, addr
                    )
                });

                // Verify identity mapping (phys == virt for low memory)
                let phys = pte & PTE_ADDR_MASK;
                assert_eq!(
                    phys, addr,
                    "{}: {:?} region: address 0x{:x} should identity map, got phys 0x{:x}",
                    name, region.region_type, addr, phys
                );

                // Verify flags
                let actual = pte & FLAG_MASK;
                assert_eq!(
                    actual, expected,
                    "{}: {:?} region: address 0x{:x} has flags 0x{:x}, expected 0x{:x} (region flags: {:?})",
                    name, region.region_type, addr, actual, expected, region.flags
                );

                addr += PAGE_TABLE_SIZE as u64;
            }
        }
    }

    #[test]
    fn test_page_tables_for_various_configurations() {
        let test_cases: [(&str, SandboxConfiguration); 4] = [
            ("default", { SandboxConfiguration::default() }),
            ("small (8MB heap)", {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(SMALL_HEAP_SIZE);
                cfg
            }),
            ("medium (64MB heap)", {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(MEDIUM_HEAP_SIZE);
                cfg
            }),
            ("large (256MB heap)", {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(LARGE_HEAP_SIZE);
                cfg
            }),
        ];

        for (name, config) in test_cases {
            verify_page_tables(name, config);
        }
    }
}
