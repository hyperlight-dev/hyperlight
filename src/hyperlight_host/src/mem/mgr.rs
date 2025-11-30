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
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
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

cfg_if::cfg_if! {
    if #[cfg(feature = "init-paging")] {
        // The amount of memory that can be mapped per page table
        pub(super) const AMOUNT_OF_MEMORY_PER_PT: usize = 0x200_000;
    }
}

/// Read/write permissions flag for the 64-bit PDE
/// The page size for the 64-bit PDE
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
    unsafe fn write_entry(&self, addr: (usize, usize), x: PageTableEntry) {
        let mut b = self.buffer.borrow_mut();
        b[addr.0 - (self.phys_base / PAGE_TABLE_SIZE)][addr.1] = x;
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
{
    /// Create a new `SandboxMemoryManager` with the given parameters
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        layout: SandboxMemoryLayout,
        shared_mem: S,
        load_addr: RawPtr,
        entrypoint_offset: Option<Offset>,
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

    /// Create a snapshot with the given mapped regions
    pub(crate) fn snapshot(
        &mut self,
        sandbox_id: u64,
        mapped_regions: Vec<MemoryRegion>,
    ) -> Result<Snapshot> {
        Snapshot::new(
            &mut self.shared_mem,
            sandbox_id,
            self.layout.clone(),
            crate::mem::exe::LoadInfo::dummy(),
            mapped_regions,
        )
    }

    /// This function restores a memory snapshot from a given snapshot.
    pub(crate) fn restore_snapshot(&mut self, snapshot: &Snapshot) -> Result<()> {
        if self.shared_mem.mem_size() != snapshot.mem_size() {
            return Err(new_error!(
                "Snapshot size does not match current memory size: {} != {}",
                self.shared_mem.raw_mem_size(),
                snapshot.mem_size()
            ));
        }
        self.shared_mem.restore_from_snapshot(snapshot)?;
        Ok(())
    }
}

impl SandboxMemoryManager<ExclusiveSharedMemory> {
    pub(crate) fn from_snapshot(s: &Snapshot) -> Result<Self> {
        let layout = s.layout().clone();
        let mut shared_mem = ExclusiveSharedMemory::new(s.mem_size())?;
        shared_mem.copy_from_slice(s.memory(), 0)?;
        let load_addr: RawPtr = RawPtr::try_from(layout.get_guest_code_address())?;
        let stack_cookie = rand::random::<[u8; STACK_COOKIE_LEN]>();
        let entrypoint_gva = s.preinitialise();
        let entrypoint_offset = entrypoint_gva.map(|x| (x - u64::from(&load_addr)).into());
        Ok(Self::new(
            layout,
            shared_mem,
            load_addr,
            entrypoint_offset,
            stack_cookie,
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

    /// Writes a function call result to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_response_from_host_method_call(&mut self, res: &ReturnValue) -> Result<()> {
        let function_call_ret_val_buffer = Vec::<u8>::try_from(res).map_err(|_| {
            new_error!(
                "write_response_from_host_method_call: failed to convert ReturnValue to Vec<u8>"
            )
        })?;
        self.shared_mem.push_buffer(
            self.layout.input_data_buffer_offset,
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

        self.shared_mem.push_buffer(
            self.layout.input_data_buffer_offset,
            self.layout.sandbox_memory_config.get_input_data_size(),
            buffer,
        )
    }

    /// Reads a function call result from memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_function_call_result(&mut self) -> Result<ReturnValue> {
        self.shared_mem.try_pop_buffer_into::<ReturnValue>(
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

    /// Get the guest error data
    pub(crate) fn get_guest_error(&mut self) -> Result<GuestError> {
        self.shared_mem.try_pop_buffer_into::<GuestError>(
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
