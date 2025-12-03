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

use hyperlight_common::flatbuffer_wrappers::function_call::{
    FunctionCall, validate_guest_function_call_buffer,
};
use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
use hyperlight_common::flatbuffer_wrappers::guest_error::GuestError;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
#[cfg(feature = "init-paging")]
use hyperlight_common::vm::{
    self, BasicMapping, Mapping, MappingKind, PAGE_TABLE_ENTRIES_PER_TABLE, PAGE_TABLE_SIZE,
    PageTableEntry, PhysAddr,
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
use crate::sandbox::snapshot::NextAction;

cfg_if::cfg_if! {
    if #[cfg(feature = "init-paging")] {
        // The amount of memory that can be mapped per page table
        pub(super) const AMOUNT_OF_MEMORY_PER_PT: usize = 0x200_000;
    }
}

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
    /// Pointer to the next place to jump to in the guest in order to
    /// do something in it (either initialise or dispatch)
    pub(crate) entrypoint: RawPtr,
    /// Whether the sandbox still needs to be initialised or is ready
    /// to take a call
    pub(crate) next_action: NextAction,
    /// How many memory regions were mapped after sandbox creation
    pub(crate) mapped_rgns: u64,
    /// Buffer for accumulating guest abort messages
    pub(crate) abort_buffer: Vec<u8>,
}

#[cfg(feature = "init-paging")]
pub(crate) struct GuestPageTableBuffer {
    buffer: std::cell::RefCell<Vec<[PageTableEntry; PAGE_TABLE_ENTRIES_PER_TABLE]>>,
    phys_base: usize,
}
#[cfg(feature = "init-paging")]
impl vm::TableOps for GuestPageTableBuffer {
    type TableAddr = (usize, usize);
    unsafe fn alloc_table(&self) -> (usize, usize) {
        let mut b = self.buffer.borrow_mut();
        let page_addr = b.len();
        b.push([0; PAGE_TABLE_ENTRIES_PER_TABLE]);
        (self.phys_base / PAGE_TABLE_SIZE + page_addr, 0)
    }
    fn entry_addr(addr: (usize, usize), offset: u64) -> (usize, usize) {
        (addr.0, offset as usize >> 3)
    }
    unsafe fn read_entry(&self, addr: (usize, usize)) -> PageTableEntry {
        let b = self.buffer.borrow();
        b[addr.0 - (self.phys_base / PAGE_TABLE_SIZE)][addr.1]
    }
    unsafe fn write_entry(&self, addr: (usize, usize), x: PageTableEntry) -> Option<(usize, usize)> {
        let mut b = self.buffer.borrow_mut();
        b[addr.0 - (self.phys_base / PAGE_TABLE_SIZE)][addr.1] = x;
        None
    }
    fn to_phys(addr: (usize, usize)) -> PhysAddr {
        (addr.0 as u64 * PAGE_TABLE_SIZE as u64) + addr.1 as u64
    }
    fn from_phys(addr: PhysAddr) -> (usize, usize) {
        (
            addr as usize / PAGE_TABLE_SIZE,
            addr as usize % PAGE_TABLE_SIZE,
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
            buffer: std::cell::RefCell::new(vec![[0; PAGE_TABLE_ENTRIES_PER_TABLE]]),
            phys_base
        }
    }
    pub(crate) fn phys_base(&self) -> usize {
        self.phys_base
    }
    pub(crate) fn size(&self) -> usize {
        self.buffer.borrow().len() * PAGE_TABLE_SIZE
    }
    pub(crate) fn into_bytes(self) -> Box<[u8]> {
        let bx = self.buffer.into_inner().into_boxed_slice();
        let len = bx.len();
        unsafe {
            Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                Box::into_raw(bx) as *mut u8,
                len * PAGE_TABLE_SIZE,
            ))
        }
    }
}

impl<S> SandboxMemoryManager<S>
where
    S: SharedMemory,
{    /// Create a new `SandboxMemoryManager` with the given parameters
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        layout: SandboxMemoryLayout,
        shared_mem: S,
        scratch_mem: S,
        load_addr: RawPtr,
        entrypoint: RawPtr,
        next_action: NextAction,
    ) -> Self {
        Self {
            layout,
            shared_mem,
            scratch_mem,
            load_addr,
            entrypoint,
            next_action,
            mapped_rgns: 0,
            abort_buffer: Vec::new(),
        }
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

    /// Get `SharedMemory` in `self` as a mutable reference
    #[cfg(any(gdb, test))]
    pub(crate) fn get_scratch_mem_mut(&mut self) -> &mut S {
        &mut self.scratch_mem
    }

    /// Create a snapshot with the given mapped regions
    ///
    /// Presently, this assumes that it is always called on a manager
    /// corresponding to an initialised sandbox
    pub(crate) fn snapshot(
        &mut self,
        sandbox_id: u64,
        mapped_regions: Vec<MemoryRegion>,
        root_pt: u64,
    ) -> Result<Snapshot> {
        Snapshot::new(
            &mut self.shared_mem,
            &mut self.scratch_mem,
            sandbox_id,
            self.layout.clone(),
            crate::mem::exe::LoadInfo::dummy(),
            mapped_regions,
            root_pt,
            self.entrypoint.clone().into(),
        )
    }

    /// Record that the entrypoint into the snapshot memory has changed
    pub(crate) fn set_entrypoint(&mut self, entrypoint: RawPtr) {
        self.entrypoint = entrypoint;
    }

}

impl SandboxMemoryManager<ExclusiveSharedMemory> {
    pub(crate) fn from_snapshot(s: &Snapshot) -> Result<Self> {
        let layout = s.layout().clone();
        let mut shared_mem = ExclusiveSharedMemory::new(s.mem_size())?;
        shared_mem.copy_from_slice(s.memory(), 0)?;
        let scratch_mem = ExclusiveSharedMemory::new(s.layout().get_scratch_size())?;
        let load_addr: RawPtr = RawPtr::try_from(layout.get_guest_code_address())?;
        Ok(Self::new(
            layout,
            shared_mem,
            scratch_mem,
            load_addr,
            RawPtr::from(s.entrypoint()),
            s.next_action(),
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
    pub fn build(
        self,
    ) -> (
        SandboxMemoryManager<HostSharedMemory>,
        SandboxMemoryManager<GuestSharedMemory>,
    ) {
        let (hshm, gshm) = self.shared_mem.build();
        let (hscratch, gscratch) = self.scratch_mem.build();
        let mut host_mgr = SandboxMemoryManager {
            shared_mem: hshm,
            scratch_mem: hscratch,
            layout: self.layout,
            load_addr: self.load_addr.clone(),
            entrypoint: self.entrypoint.clone(),
            next_action: self.next_action.clone(),
            mapped_rgns: self.mapped_rgns,
            abort_buffer: self.abort_buffer,
        };
        let guest_mgr = SandboxMemoryManager {
            shared_mem: gshm,
            scratch_mem: gscratch,
            layout: self.layout,
            load_addr: self.load_addr.clone(),
            entrypoint: self.entrypoint.clone(),
            next_action: self.next_action.clone(),
            mapped_rgns: self.mapped_rgns,
            abort_buffer: Vec::new(), // Guest doesn't need abort buffer
        };
        host_mgr.update_scratch_bookkeeping((SandboxMemoryLayout::BASE_ADDRESS + self.layout.get_pt_offset()) as u64);
        (host_mgr, guest_mgr)
    }
}

impl SandboxMemoryManager<HostSharedMemory> {
    /// Reads a host function call from memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_host_function_call(&mut self) -> Result<FunctionCall> {
        self.scratch_mem.try_pop_buffer_into::<FunctionCall>(
            self.layout.get_output_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    /// Writes a function call result to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_response_from_host_method_call(&mut self, res: &ReturnValue) -> Result<()> {
        let function_call_ret_val_buffer = Vec::<u8>::try_from(res).map_err(|_| {
            new_error!(
                "write_response_from_host_method_call: failed to convert ReturnValue to Vec<u8>"
            )
        })?;
        self.scratch_mem.push_buffer(
            self.layout.get_input_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_input_data_size(),
            function_call_ret_val_buffer.as_slice(),
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

        self.scratch_mem.push_buffer(
            self.layout.get_input_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_input_data_size(),
            buffer,
        )?;
        Ok(())
    }

    /// Reads a function call result from memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_function_call_result(&mut self) -> Result<ReturnValue> {
        self.scratch_mem.try_pop_buffer_into::<ReturnValue>(
            self.layout.get_output_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    /// Read guest log data from the `SharedMemory` contained within `self`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_guest_log_data(&mut self) -> Result<GuestLogData> {
        self.scratch_mem.try_pop_buffer_into::<GuestLogData>(
            self.layout.get_output_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    /// Get the guest error data
    pub(crate) fn get_guest_error(&mut self) -> Result<GuestError> {
        self.scratch_mem.try_pop_buffer_into::<GuestError>(
            self.layout.get_output_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    pub(crate) fn clear_io_buffers(&mut self) {
        // Clear the output data buffer
        loop {
            let Ok(_) = self.scratch_mem.try_pop_buffer_into::<Vec<u8>>(
                self.layout.get_output_data_buffer_scratch_host_offset(),
                self.layout.sandbox_memory_config.get_output_data_size(),
            ) else {
                break;
            };
        }
        // Clear the input data buffer
        loop {
            let Ok(_) = self.scratch_mem.try_pop_buffer_into::<Vec<u8>>(
                self.layout.get_input_data_buffer_scratch_host_offset(),
                self.layout.sandbox_memory_config.get_input_data_size(),
            ) else {
                break;
            };
        }
    }

    /// This function restores a memory snapshot from a given snapshot.
    pub(crate) fn restore_snapshot(&mut self, snapshot: &Snapshot) -> Result<(Option<GuestSharedMemory>, Option<GuestSharedMemory>)> {
        let gsnapshot = if self.shared_mem.mem_size() == snapshot.mem_size() {
            None
        } else {
            let new_snapshot_mem = ExclusiveSharedMemory::new(snapshot.mem_size())?;
            let (hsnapshot, gsnapshot) = new_snapshot_mem.build();
            self.shared_mem = hsnapshot;
            Some(gsnapshot)
        };
        self.shared_mem.restore_from_snapshot(snapshot)?;
        let new_scratch_size = snapshot.layout().get_scratch_size();
        let gscratch = if new_scratch_size == self.scratch_mem.mem_size() {
            self.scratch_mem.zero()?;
            None
        } else {
            // todo: make sure the old scratch memory lives long
            // enough that we don't have a period where the region is
            // unmapped in process but still mapped into the vm.
            let new_scratch_mem = ExclusiveSharedMemory::new(new_scratch_size)?;
            let (hscratch, gscratch) = new_scratch_mem.build();
            self.scratch_mem = hscratch;
            Some(gscratch)
        };
        self.update_scratch_bookkeeping(snapshot.root_pt_gpa());
        self.entrypoint = RawPtr::from(snapshot.entrypoint());
        Ok((gsnapshot, gscratch))
    }

    fn update_scratch_bookkeeping(&mut self, snapshot_pt_base_gpa: u64) {
        let scratch_size = self.scratch_mem.mem_size();
        let size_offset = scratch_size - hyperlight_common::layout::SCRATCH_TOP_SIZE_OFFSET as usize;
        // The only way that write can fail is if the offset is
        // outside of the memory, which would be sufficiently much of
        // an invariant violation that panicking is probably
        // sensible...
        self.scratch_mem.write::<u64>(size_offset, scratch_size as u64).unwrap();
        let alloc_offset = scratch_size - hyperlight_common::layout::SCRATCH_TOP_ALLOCATOR_OFFSET as usize;
        self.scratch_mem.write::<u64>(
            alloc_offset,
            self.layout.get_first_free_scratch_gpa()
        ).unwrap();
        let snapshot_pt_base_gpa_offset = scratch_size - hyperlight_common::layout::SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET as usize;
        self.scratch_mem.write::<u64>(snapshot_pt_base_gpa_offset, snapshot_pt_base_gpa).unwrap();

        // Initialise the guest input and output data buffers in
        // scratch memory. TODO: remove the need for this.
        self.scratch_mem.write::<u64>(
            self.layout.get_input_data_buffer_scratch_host_offset(),
            SandboxMemoryLayout::STACK_POINTER_SIZE_BYTES
        ).unwrap();
        self.scratch_mem.write::<u64>(
            self.layout.get_output_data_buffer_scratch_host_offset(),
            SandboxMemoryLayout::STACK_POINTER_SIZE_BYTES
        ).unwrap();
    }
}
