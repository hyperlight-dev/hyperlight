// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::{
    FunctionCall, validate_guest_function_call_buffer,
};
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use hyperlight_common::vmem::{self, PAGE_TABLE_SIZE};
#[cfg(crashdump)]
use hyperlight_common::vmem::{BasicMapping, MappingKind};
use tracing::{Span, instrument};

use super::layout::SandboxMemoryLayout;
use super::shared_mem::{
    ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, HostSharedMemoryReadGuard,
    SharedMemory,
};
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::mem::memory_region::MemoryRegion;
#[cfg(crashdump)]
use crate::mem::memory_region::{CrashDumpRegion, MemoryRegionFlags, MemoryRegionType};
use crate::sandbox::snapshot::{NextAction, Snapshot, SnapshotMemoryBacking};
use crate::{Result, new_error};

#[cfg(crashdump)]
fn mapping_kind_to_flags(kind: &MappingKind) -> (MemoryRegionFlags, MemoryRegionType) {
    match kind {
        MappingKind::Basic(BasicMapping {
            readable,
            writable,
            executable,
        }) => {
            let mut flags = MemoryRegionFlags::empty();
            if *readable {
                flags |= MemoryRegionFlags::READ;
            }
            if *writable {
                flags |= MemoryRegionFlags::WRITE;
            }
            if *executable {
                flags |= MemoryRegionFlags::EXECUTE;
            }
            (flags, MemoryRegionType::Snapshot)
        }
        MappingKind::Cow(cow) => {
            let mut flags = MemoryRegionFlags::empty();
            if cow.readable {
                flags |= MemoryRegionFlags::READ;
            }
            if cow.executable {
                flags |= MemoryRegionFlags::EXECUTE;
            }
            (flags, MemoryRegionType::Scratch)
        }
        MappingKind::Unmapped => (MemoryRegionFlags::empty(), MemoryRegionType::Snapshot),
    }
}

/// Try to extend the last region in `regions` if the new page is contiguous
/// in both guest and host address space and has the same flags.
///
/// Returns `true` if the region was coalesced, `false` if a new region is needed.
#[cfg(crashdump)]
fn try_coalesce_region(
    regions: &mut [CrashDumpRegion],
    virt_base: usize,
    virt_end: usize,
    host_base: usize,
    flags: MemoryRegionFlags,
) -> bool {
    if let Some(last) = regions.last_mut()
        && last.guest_region.end == virt_base
        && last.host_region.end == host_base
        && last.flags == flags
    {
        last.guest_region.end = virt_end;
        last.host_region.end = host_base + (virt_end - virt_base);
        return true;
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GuestBacking {
    Snapshot { layer_index: usize, offset: usize },
    Scratch { offset: usize },
    Dynamic { region_index: usize, offset: usize },
}

enum ScratchMemoryView<'a> {
    #[cfg(any(test, crashdump, gdb, feature = "trace_guest"))]
    Shared(&'a HostSharedMemory),
    Locked(HostSharedMemoryReadGuard<'a>),
}

impl ScratchMemoryView<'_> {
    fn copy_to_slice(&self, destination: &mut [u8], offset: usize) -> Result<()> {
        match self {
            #[cfg(any(test, crashdump, gdb, feature = "trace_guest"))]
            Self::Shared(memory) => memory.copy_to_slice(destination, offset),
            Self::Locked(memory) => memory.copy_to_slice(destination, offset),
        }
        .map_err(Into::into)
    }

    #[cfg(crashdump)]
    fn base_addr(&self) -> usize {
        match self {
            Self::Shared(memory) => memory.base_addr(),
            Self::Locked(memory) => memory.base_addr(),
        }
    }

    #[cfg(crashdump)]
    fn mem_size(&self) -> usize {
        match self {
            Self::Shared(memory) => memory.mem_size(),
            Self::Locked(memory) => memory.mem_size(),
        }
    }
}

pub(crate) struct GuestPhysicalMemoryView<'a> {
    snapshot: &'a SnapshotMemoryBacking<HostSharedMemory>,
    scratch: ScratchMemoryView<'a>,
    dynamic: &'a [MemoryRegion],
    layout: SandboxMemoryLayout,
}

impl<'a> GuestPhysicalMemoryView<'a> {
    #[cfg(any(test, crashdump, gdb, feature = "trace_guest"))]
    pub(crate) fn new(
        snapshot: &'a SnapshotMemoryBacking<HostSharedMemory>,
        scratch: &'a HostSharedMemory,
        dynamic: &'a [MemoryRegion],
        layout: SandboxMemoryLayout,
    ) -> Self {
        Self {
            snapshot,
            scratch: ScratchMemoryView::Shared(scratch),
            dynamic,
            layout,
        }
    }

    pub(crate) fn for_snapshot_capture(
        snapshot: &'a SnapshotMemoryBacking<HostSharedMemory>,
        scratch: &'a HostSharedMemory,
        dynamic: &'a [MemoryRegion],
        layout: SandboxMemoryLayout,
    ) -> Result<Self> {
        Ok(Self {
            snapshot,
            scratch: ScratchMemoryView::Locked(scratch.read_guard()?),
            dynamic,
            layout,
        })
    }

    pub(crate) fn resolve(&self, gpa: u64, len: usize) -> Option<GuestBacking> {
        let end = gpa.checked_add(u64::try_from(len).ok()?)?;
        let scratch_start =
            hyperlight_common::layout::scratch_base_gpa(self.layout.get_scratch_size());
        let scratch_end = scratch_start.checked_add(self.layout.get_scratch_size() as u64)?;
        if scratch_start <= gpa && end <= scratch_end {
            return Some(GuestBacking::Scratch {
                offset: usize::try_from(gpa - scratch_start).ok()?,
            });
        }
        if let Some((layer_index, offset)) = self.snapshot.resolve(gpa, len) {
            return Some(GuestBacking::Snapshot {
                layer_index,
                offset,
            });
        }
        self.dynamic
            .iter()
            .enumerate()
            .find_map(|(region_index, region)| {
                let start = u64::try_from(region.guest_region.start).ok()?;
                let region_end = u64::try_from(region.guest_region.end).ok()?;
                if start <= gpa && end <= region_end {
                    Some(GuestBacking::Dynamic {
                        region_index,
                        offset: usize::try_from(gpa - start).ok()?,
                    })
                } else {
                    None
                }
            })
    }

    pub(crate) fn read(&self, gpa: u64, destination: &mut [u8]) -> Result<GuestBacking> {
        let backing = self
            .resolve(gpa, destination.len())
            .ok_or_else(|| new_error!("GPA range is not backed: {gpa:#x}"))?;
        self.read_backing(backing, destination)?;
        Ok(backing)
    }

    pub(crate) fn read_backing(&self, backing: GuestBacking, destination: &mut [u8]) -> Result<()> {
        match backing {
            GuestBacking::Snapshot {
                layer_index,
                offset,
            } => self
                .snapshot
                .copy_layer_to_slice(layer_index, destination, offset)?,
            GuestBacking::Scratch { offset } => {
                self.scratch.copy_to_slice(destination, offset)?;
            }
            GuestBacking::Dynamic {
                region_index,
                offset,
            } => {
                let region = &self.dynamic[region_index];
                #[allow(clippy::useless_conversion)]
                let host_start: usize = region.host_region.start.into();
                #[allow(clippy::useless_conversion)]
                let host_end: usize = region.host_region.end.into();
                let source_end = offset
                    .checked_add(destination.len())
                    .ok_or_else(|| new_error!("dynamic memory read range overflows"))?;
                if source_end > host_end - host_start {
                    return Err(new_error!("dynamic memory read range is out of bounds"));
                }
                // SAFETY: MemoryRegion requires its host backing to remain alive while mapped.
                // resolve() verified that this read lies within the corresponding guest range.
                let source = unsafe {
                    std::slice::from_raw_parts(
                        (host_start + offset) as *const u8,
                        destination.len(),
                    )
                };
                destination.copy_from_slice(source);
            }
        }
        Ok(())
    }

    #[cfg(crashdump)]
    fn host_range(&self, gpa: u64, len: usize) -> Result<std::ops::Range<usize>> {
        let backing = self
            .resolve(gpa, len)
            .ok_or_else(|| new_error!("GPA range is not backed: {gpa:#x}"))?;
        let (base, offset, backing_len) = match backing {
            GuestBacking::Snapshot {
                layer_index,
                offset,
            } => {
                let (base, len) = self.snapshot.host_range(layer_index)?;
                (base, offset, len)
            }
            GuestBacking::Scratch { offset } => {
                (self.scratch.base_addr(), offset, self.scratch.mem_size())
            }
            GuestBacking::Dynamic {
                region_index,
                offset,
            } => {
                let region = &self.dynamic[region_index];
                #[allow(clippy::useless_conversion)]
                let start: usize = region.host_region.start.into();
                #[allow(clippy::useless_conversion)]
                let end: usize = region.host_region.end.into();
                (start, offset, end - start)
            }
        };
        let end_offset = offset
            .checked_add(len)
            .filter(|end| *end <= backing_len)
            .ok_or_else(|| new_error!("resolved GPA range is out of bounds"))?;
        let start = base
            .checked_add(offset)
            .ok_or_else(|| new_error!("resolved host address overflows"))?;
        let end = base
            .checked_add(end_offset)
            .ok_or_else(|| new_error!("resolved host address overflows"))?;
        Ok(start..end)
    }
}

#[cfg(feature = "mem_profile")]
pub(crate) struct GuestVirtualMemoryReader<'a> {
    memory: GuestPhysicalMemoryView<'a>,
    root_pt: u64,
    cached_page: Option<(u64, u64)>,
}

#[cfg(feature = "mem_profile")]
impl<'a> GuestVirtualMemoryReader<'a> {
    fn new(
        snapshot: &'a SnapshotMemoryBacking<HostSharedMemory>,
        scratch: &'a HostSharedMemory,
        layout: SandboxMemoryLayout,
        root_pt: u64,
    ) -> Self {
        Self {
            memory: GuestPhysicalMemoryView::new(snapshot, scratch, &[], layout),
            root_pt,
            cached_page: None,
        }
    }

    fn translate_page(&mut self, page_gva: u64) -> Result<u64> {
        if let Some((cached_gva, cached_gpa)) = self.cached_page
            && cached_gva == page_gva
        {
            return Ok(cached_gpa);
        }

        use crate::sandbox::snapshot::PageTableReader;

        let pt_buf = PageTableReader::new(&self.memory, self.root_pt);
        // SAFETY: The vCPU is stopped for this outb, so its page tables cannot
        // change during the walk.
        let mapping = unsafe {
            hyperlight_common::vmem::virt_to_phys(
                &pt_buf,
                page_gva,
                hyperlight_common::vmem::PAGE_SIZE as u64,
            )
        }
        .next()
        .ok_or_else(|| new_error!("GVA page is not mapped: {page_gva:#x}"))?;
        let mapping_offset = page_gva
            .checked_sub(mapping.virt_base)
            .ok_or_else(|| new_error!("page-table mapping starts after requested GVA"))?;
        if mapping
            .len
            .checked_sub(mapping_offset)
            .is_none_or(|len| len < hyperlight_common::vmem::PAGE_SIZE as u64)
        {
            return Err(new_error!(
                "page-table mapping does not cover requested GVA page"
            ));
        }
        let page_gpa = mapping
            .phys_base
            .checked_add(mapping_offset)
            .ok_or_else(|| new_error!("guest physical address overflows"))?;
        self.cached_page = Some((page_gva, page_gpa));
        Ok(page_gpa)
    }

    pub(crate) fn read(&mut self, gva: u64, destination: &mut [u8]) -> Result<()> {
        let mut copied = 0usize;
        while copied < destination.len() {
            let current_gva = gva
                .checked_add(u64::try_from(copied)?)
                .ok_or_else(|| new_error!("guest virtual address overflows"))?;
            let page_gva = current_gva / hyperlight_common::vmem::PAGE_SIZE as u64
                * hyperlight_common::vmem::PAGE_SIZE as u64;
            let page_offset = usize::try_from(current_gva - page_gva)?;
            let chunk_len =
                (destination.len() - copied).min(hyperlight_common::vmem::PAGE_SIZE - page_offset);
            let gpa = self
                .translate_page(page_gva)?
                .checked_add(u64::try_from(page_offset)?)
                .ok_or_else(|| new_error!("guest physical address overflows"))?;
            self.memory
                .read(gpa, &mut destination[copied..copied + chunk_len])?;
            copied += chunk_len;
        }
        Ok(())
    }
}

/// A struct that is responsible for laying out and managing the memory
/// for a given `Sandbox`.
pub(crate) struct SandboxMemoryManager<S: SharedMemory> {
    /// Shared memory for the Sandbox
    pub(crate) shared_mem: SnapshotMemoryBacking<S>,
    /// Scratch memory for the Sandbox
    pub(crate) scratch_mem: S,
    /// The memory layout of the underlying shared memory
    pub(crate) layout: SandboxMemoryLayout,
    /// The next action to perform when this sandbox resumes:
    /// `Initialise` before the guest has run, `Call` afterwards.
    pub(crate) next_action: NextAction,
    /// Guest virtual address of the guest binary's ELF entry point,
    /// preserved across the `Initialise` -> `Call` transition so it
    /// can fill `AT_ENTRY` in guest core dumps. 0 if unknown.
    pub(crate) original_entrypoint: u64,
    /// Buffer for accumulating guest abort messages
    pub(crate) abort_buffer: Vec<u8>,
    /// Generation counter: how many snapshots have been taken from
    /// this sandbox's execution path from init to here. Incremented
    /// on each `snapshot` call; on `restore_snapshot` we inherit the
    /// restored snapshot's own generation number so the guest-visible
    /// counter tracks which snapshot the sandbox is a clone of.
    pub(crate) snapshot_count: u64,
}

/// Buffer for building guest page tables during snapshot creation.
/// `TableAddr` is an absolute GPA (u64) so the same address space is
/// used regardless of entry size.
pub(crate) struct GuestPageTableBuffer {
    buffer: std::cell::RefCell<Vec<u8>>,
    phys_base: usize,
    /// Absolute GPA of the currently-active root table. For
    /// multi-root guests, `set_root` switches which root subsequent
    /// `vmem::map` / `vmem::space_aware_map` calls target — typically
    /// to an address previously returned by `alloc_table`.
    root: std::cell::Cell<u64>,
}

impl vmem::TableReadOps for GuestPageTableBuffer {
    type TableAddr = u64;

    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr.saturating_add(offset)
    }

    unsafe fn read_entry(&self, addr: u64) -> vmem::PageTableEntry {
        let buffer = self.buffer.borrow();
        let Ok(addr) = usize::try_from(addr) else {
            return 0;
        };
        let Some(byte_offset) = addr.checked_sub(self.phys_base) else {
            return 0;
        };
        let pte_size = core::mem::size_of::<vmem::PageTableEntry>();
        let Some(end) = byte_offset.checked_add(pte_size) else {
            return 0;
        };
        let Some(bytes) = buffer.get(byte_offset..end) else {
            return 0;
        };
        let mut buf = [0u8; 8];
        buf[..pte_size].copy_from_slice(bytes);
        vmem::PageTableEntry::from_le_bytes(buf[..pte_size].try_into().unwrap_or_default())
    }

    fn to_phys(addr: u64) -> vmem::PhysAddr {
        addr as vmem::PhysAddr
    }

    fn from_phys(addr: vmem::PhysAddr) -> u64 {
        #[allow(clippy::unnecessary_cast)]
        {
            addr as u64
        }
    }

    fn root_table(&self) -> u64 {
        self.root.get()
    }
}

impl vmem::TableOps for GuestPageTableBuffer {
    type TableMovability = vmem::MayNotMoveTable;

    unsafe fn alloc_table(&self) -> u64 {
        let mut b = self.buffer.borrow_mut();
        let offset = b.len();
        b.resize(offset + PAGE_TABLE_SIZE, 0);
        (self.phys_base + offset) as u64
    }

    unsafe fn write_entry(&self, addr: u64, entry: vmem::PageTableEntry) -> Option<vmem::Void> {
        let mut b = self.buffer.borrow_mut();
        let byte_offset = addr as usize - self.phys_base;
        let pte_size = core::mem::size_of::<vmem::PageTableEntry>();
        if let Some(slice) = b.get_mut(byte_offset..byte_offset + pte_size) {
            slice.copy_from_slice(&entry.to_le_bytes()[..pte_size]);
        }
        None
    }

    unsafe fn update_root(&self, impossible: vmem::Void) {
        match impossible {}
    }
}

impl core::convert::AsRef<GuestPageTableBuffer> for GuestPageTableBuffer {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl GuestPageTableBuffer {
    /// Create a new buffer with an initial zeroed root table at
    /// `phys_base`. The returned buffer's current root is `phys_base`;
    /// additional roots can be obtained by calling `alloc_table`.
    pub(crate) fn new(phys_base: usize) -> Self {
        Self::with_capacity(phys_base, PAGE_TABLE_SIZE)
    }

    pub(crate) fn with_capacity(phys_base: usize, capacity: usize) -> Self {
        let mut buffer = Vec::with_capacity(capacity.max(PAGE_TABLE_SIZE));
        buffer.resize(PAGE_TABLE_SIZE, 0);
        GuestPageTableBuffer {
            buffer: std::cell::RefCell::new(buffer),
            phys_base,
            root: std::cell::Cell::new(phys_base as u64),
        }
    }

    /// Switch the active root. `addr` must have been obtained either
    /// as the initial root GPA (`phys_base`) or via `alloc_table`.
    pub(crate) fn set_root(&self, addr: u64) {
        self.root.set(addr);
    }

    /// GPA of the initial root allocated by `new`.
    pub(crate) fn initial_root(&self) -> u64 {
        self.phys_base as u64
    }

    #[cfg(test)]
    #[allow(dead_code)]
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
    pub(crate) fn first_free_scratch_gpa(&self) -> u64 {
        self.layout.get_pt_base_gpa() + self.shared_mem.page_table_len() as u64
    }

    /// Create a new `SandboxMemoryManager` with the given parameters
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        layout: SandboxMemoryLayout,
        shared_mem: SnapshotMemoryBacking<S>,
        scratch_mem: S,
        next_action: NextAction,
    ) -> Self {
        Self {
            layout,
            shared_mem,
            scratch_mem,
            next_action,
            original_entrypoint: 0,
            abort_buffer: Vec::new(),
            snapshot_count: 0,
        }
    }

    /// Get mutable access to the abort buffer
    pub(crate) fn get_abort_buffer_mut(&mut self) -> &mut Vec<u8> {
        &mut self.abort_buffer
    }
}

impl SandboxMemoryManager<ExclusiveSharedMemory> {
    pub(crate) fn from_snapshot(s: &Snapshot) -> Result<Self> {
        let layout = *s.layout();
        let shared_mem = SnapshotMemoryBacking::from_snapshot(s.snapshot_memory().clone())?;
        let scratch_mem = ExclusiveSharedMemory::new(s.layout().get_scratch_size())?;
        let next_action = s.next_action();
        let mut mgr = Self::new(layout, shared_mem, scratch_mem, next_action);
        mgr.original_entrypoint = s.original_entrypoint();
        // Inherit the snapshot's generation number for the same
        // reason `restore_snapshot` does: the guest-visible counter
        // reflects "which snapshot is the sandbox currently a clone
        // of", not "how many snapshots this partition has taken".
        mgr.snapshot_count = s.snapshot_generation();
        Ok(mgr)
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
            next_action: self.next_action,
            original_entrypoint: self.original_entrypoint,
            abort_buffer: self.abort_buffer,
            snapshot_count: self.snapshot_count,
        };
        let guest_mgr = SandboxMemoryManager {
            shared_mem: gshm,
            scratch_mem: gscratch,
            layout: self.layout,
            next_action: self.next_action,
            original_entrypoint: self.original_entrypoint,
            abort_buffer: Vec::new(), // Guest doesn't need abort buffer
            snapshot_count: self.snapshot_count,
        };
        host_mgr.update_scratch_bookkeeping()?;
        Ok((host_mgr, guest_mgr))
    }
}

impl SandboxMemoryManager<HostSharedMemory> {
    #[cfg(feature = "mem_profile")]
    pub(crate) fn guest_virtual_memory_reader(&self, root_pt: u64) -> GuestVirtualMemoryReader<'_> {
        GuestVirtualMemoryReader::new(&self.shared_mem, &self.scratch_mem, self.layout, root_pt)
    }

    /// Create a snapshot with the given mapped regions.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn snapshot(
        &mut self,
        mapped_regions: Vec<MemoryRegion>,
        root_pt_gpas: &[u64],
        rsp_gva: u64,
        sregs: CommonSpecialRegisters,
        #[cfg(target_arch = "x86_64")] msrs: Vec<crate::hypervisor::regs::MsrEntry>,
        next_action: NextAction,
        host_functions: HostFunctionDetails,
    ) -> Result<Snapshot> {
        let snapshot_count = self
            .snapshot_count
            .checked_add(1)
            .ok_or_else(|| new_error!("snapshot generation overflows"))?;
        let snapshot = Snapshot::new(
            &self.shared_mem,
            &self.scratch_mem,
            self.layout,
            crate::mem::exe::LoadInfo::dummy(),
            mapped_regions,
            root_pt_gpas,
            rsp_gva,
            sregs,
            #[cfg(target_arch = "x86_64")]
            msrs,
            next_action,
            self.original_entrypoint,
            snapshot_count,
            host_functions,
        )?;
        self.snapshot_count = snapshot_count;
        Ok(snapshot)
    }

    /// Reads a host function call from memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_host_function_call(&mut self) -> Result<FunctionCall> {
        self.scratch_mem
            .try_pop_buffer_into::<FunctionCall>(
                self.layout.get_output_data_buffer_scratch_host_offset(),
                self.layout.output_data_size(),
            )
            .map_err(From::from)
    }

    /// Writes a host function call result to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_response_from_host_function_call(
        &mut self,
        res: &FunctionCallResult,
    ) -> Result<()> {
        let mut builder = FlatBufferBuilder::new();
        let data = res.encode(&mut builder);

        self.scratch_mem
            .push_buffer(
                self.layout.get_input_data_buffer_scratch_host_offset(),
                self.layout.input_data_size(),
                data,
            )
            .map_err(From::from)
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
            self.layout.input_data_size(),
            buffer,
        )?;
        Ok(())
    }

    /// Reads a function call result from memory.
    /// A function call result can be either an error or a successful return value.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_function_call_result(&mut self) -> Result<FunctionCallResult> {
        self.scratch_mem
            .try_pop_buffer_into::<FunctionCallResult>(
                self.layout.get_output_data_buffer_scratch_host_offset(),
                self.layout.output_data_size(),
            )
            .map_err(From::from)
    }

    /// Read guest log data from the `SharedMemory` contained within `self`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_guest_log_data(&mut self) -> Result<GuestLogData> {
        self.scratch_mem
            .try_pop_buffer_into::<GuestLogData>(
                self.layout.get_output_data_buffer_scratch_host_offset(),
                self.layout.output_data_size(),
            )
            .map_err(From::from)
    }

    pub(crate) fn clear_io_buffers(&mut self) {
        // Clear the output data buffer
        loop {
            let Ok(_) = self.scratch_mem.try_pop_buffer_into::<Vec<u8>>(
                self.layout.get_output_data_buffer_scratch_host_offset(),
                self.layout.output_data_size(),
            ) else {
                break;
            };
        }
        // Clear the input data buffer
        loop {
            let Ok(_) = self.scratch_mem.try_pop_buffer_into::<Vec<u8>>(
                self.layout.get_input_data_buffer_scratch_host_offset(),
                self.layout.input_data_size(),
            ) else {
                break;
            };
        }
    }

    fn replace_snapshot_memory(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<SnapshotMemoryBacking<GuestSharedMemory>> {
        let new_snapshot_mem =
            SnapshotMemoryBacking::from_snapshot(snapshot.snapshot_memory().clone())?;
        let (hsnapshot, gsnapshot) = new_snapshot_mem.build();
        self.shared_mem = hsnapshot;
        Ok(gsnapshot)
    }

    fn apply_snapshot_metadata(&mut self, snapshot: &Snapshot) {
        self.layout = *snapshot.layout();
        self.snapshot_count = snapshot.snapshot_generation();
        self.original_entrypoint = snapshot.original_entrypoint();
    }

    /// Installs memory produced by a capture without restoring runtime state.
    pub(crate) fn install_captured_snapshot(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<SnapshotMemoryBacking<GuestSharedMemory>> {
        let gsnapshot = self.replace_snapshot_memory(snapshot)?;
        self.apply_snapshot_metadata(snapshot);
        self.update_snapshot_scratch_bookkeeping()?;
        Ok(gsnapshot)
    }

    /// This function restores a memory snapshot from a given snapshot.
    pub(crate) fn restore_snapshot(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<(
        SnapshotMemoryBacking<GuestSharedMemory>,
        Option<GuestSharedMemory>,
    )> {
        let gsnapshot = self.replace_snapshot_memory(snapshot)?;
        let new_scratch_size = snapshot.layout().get_scratch_size();
        let gscratch = if new_scratch_size == self.scratch_mem.mem_size() {
            // zero_or_replace picks the fastest zeroing strategy for
            // the current platform (see SharedMemory::zero_or_replace).
            self.scratch_mem.zero_or_replace()?
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
        self.apply_snapshot_metadata(snapshot);

        self.update_scratch_bookkeeping()?;
        Ok((gsnapshot, gscratch))
    }

    #[inline]
    fn update_scratch_bookkeeping_item(&mut self, offset: u64, value: u64) -> Result<()> {
        let scratch_size = self.scratch_mem.mem_size();
        let base_offset = scratch_size - offset as usize;
        self.scratch_mem
            .write::<u64>(base_offset, value)
            .map_err(From::from)
    }

    pub(crate) fn request_libc_rng_reseed(&mut self, seed: u32) -> Result<()> {
        // Zero means no request. The upper half marks a pending request, and
        // the lower half contains the complete u32 seed.
        self.update_scratch_bookkeeping_item(
            hyperlight_common::layout::SCRATCH_TOP_LIBC_RNG_SEED_OFFSET,
            (1_u64 << 32) | u64::from(seed),
        )
    }

    fn update_scratch_bookkeeping(&mut self) -> Result<()> {
        use hyperlight_common::layout::*;
        let scratch_size = self.scratch_mem.mem_size();
        self.update_scratch_bookkeeping_item(SCRATCH_TOP_SIZE_OFFSET, scratch_size as u64)?;
        self.update_snapshot_scratch_bookkeeping()?;

        // Initialise the guest input and output data buffers in
        // scratch memory. TODO: remove the need for this.
        self.scratch_mem.write::<u64>(
            self.layout.get_input_data_buffer_scratch_host_offset(),
            SandboxMemoryLayout::STACK_POINTER_SIZE_BYTES,
        )?;
        self.scratch_mem.write::<u64>(
            self.layout.get_output_data_buffer_scratch_host_offset(),
            SandboxMemoryLayout::STACK_POINTER_SIZE_BYTES,
        )?;

        Ok(())
    }

    fn update_snapshot_scratch_bookkeeping(&mut self) -> Result<()> {
        use hyperlight_common::layout::*;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_ALLOCATOR_OFFSET,
            self.first_free_scratch_gpa(),
        )?;
        // Record the GPA of the snapshot's copy of the page tables.
        // The copy lives at the tail of the snapshot blob; we copy it
        // into scratch below so the guest walker can run against
        // mutable, TLB-fresh tables. The guest reads this GPA during
        // CoW fault-in to follow the original PTs on the first write
        // — until the HV can execute directly out of the
        // snapshot-resident PTs, at which point the whole split goes
        // away.
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET,
            self.layout.get_pt_base_gpa(),
        )?;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET,
            self.snapshot_count,
        )?;

        self.copy_snapshot_page_tables()?;

        Ok(())
    }

    fn copy_snapshot_page_tables(&mut self) -> Result<()> {
        // Copy page tables from `shared_mem` into scratch. PT bytes
        // are appended to the snapshot blob at build time and live
        // just past the end of the guest-visible KVM slot (see
        // `Snapshot::new`). Keeping them outside the KVM slot avoids
        // overlapping with `map_file_cow` regions installed
        // immediately after the snapshot in the guest PA space.
        let page_table_len = self.shared_mem.page_table_len();
        let snapshot_pt_base = self.layout.get_pt_base_gpa();
        let scratch_offset = self.layout.get_pt_base_scratch_offset();
        let scratch_end = scratch_offset
            .checked_add(page_table_len)
            .ok_or_else(|| new_error!("snapshot page-table scratch range overflows"))?;
        let shared_mem = &self.shared_mem;
        self.scratch_mem.with_exclusivity(|scratch| {
            let destination = scratch
                .as_mut_slice()
                .get_mut(scratch_offset..scratch_end)
                .ok_or_else(|| new_error!("snapshot page-table scratch range is out of bounds"))?;
            shared_mem.read_page_tables(snapshot_pt_base, snapshot_pt_base, destination)
        })??;

        Ok(())
    }

    /// Build the list of guest memory regions for a crash dump.
    ///
    /// By default, walks the guest page tables to discover
    /// GVA→GPA mappings and translates them to host-backed regions.
    #[cfg(crashdump)]
    pub(crate) fn get_guest_memory_regions(
        &mut self,
        root_pt: u64,
        mmap_regions: &[MemoryRegion],
    ) -> Result<Vec<CrashDumpRegion>> {
        use crate::sandbox::snapshot::PageTableReader;

        let len = hyperlight_common::layout::SCRATCH_TOP_GVA;
        let memory = GuestPhysicalMemoryView::new(
            &self.shared_mem,
            &self.scratch_mem,
            mmap_regions,
            self.layout,
        );
        let pt_buf = PageTableReader::new(&memory, root_pt);
        let mut regions: Vec<CrashDumpRegion> = Vec::new();
        let mut saw_mapping = false;
        // SAFETY: Crash handling runs with the vCPU stopped, so its page tables
        // cannot change during the walk.
        for mapping in unsafe { hyperlight_common::vmem::virt_to_phys(&pt_buf, 0, len as u64) } {
            saw_mapping = true;
            let (flags, region_type) = mapping_kind_to_flags(&mapping.kind);
            let mut mapped = 0usize;
            let mapping_len = usize::try_from(mapping.len)?;
            while mapped < mapping_len {
                let chunk_len = (mapping_len - mapped).min(hyperlight_common::vmem::PAGE_SIZE);
                let gpa = mapping
                    .phys_base
                    .checked_add(u64::try_from(mapped)?)
                    .ok_or_else(|| new_error!("crash-dump GPA overflows"))?;
                let Some(host_region) = memory.host_range(gpa, chunk_len).ok() else {
                    mapped += chunk_len;
                    continue;
                };
                let virt_base = usize::try_from(mapping.virt_base)?
                    .checked_add(mapped)
                    .ok_or_else(|| new_error!("crash-dump GVA overflows"))?;
                let virt_end = virt_base
                    .checked_add(chunk_len)
                    .ok_or_else(|| new_error!("crash-dump GVA range overflows"))?;

                if !try_coalesce_region(&mut regions, virt_base, virt_end, host_region.start, flags)
                {
                    regions.push(CrashDumpRegion {
                        guest_region: virt_base..virt_end,
                        host_region,
                        flags,
                        region_type,
                    });
                }
                mapped += chunk_len;
            }
        }
        if !saw_mapping {
            return Err(new_error!("No page table mappings found (len {len})",));
        }

        Ok(regions)
    }

    /// Read guest memory at a Guest Virtual Address (GVA) by walking the
    /// page tables to translate GVA → GPA, then reading from the correct
    /// backing memory (shared_mem or scratch_mem).
    ///
    /// This is necessary because with Copy-on-Write (CoW) the guest's
    /// virtual pages are backed by physical pages in the scratch
    /// region rather than being identity-mapped.
    ///
    /// # Arguments
    /// * `gva` - The Guest Virtual Address to read from
    /// * `len` - The number of bytes to read
    /// * `root_pt` - The root page table physical address (CR3)
    #[cfg(feature = "trace_guest")]
    pub(crate) fn read_guest_memory_by_gva(
        &self,
        gva: u64,
        len: usize,
        root_pt: u64,
    ) -> Result<Vec<u8>> {
        let mut result = vec![0; len];
        self.read_guest_memory_by_gva_into(gva, &mut result, root_pt)?;
        Ok(result)
    }

    #[cfg(feature = "trace_guest")]
    pub(crate) fn read_guest_memory_by_gva_into(
        &self,
        gva: u64,
        destination: &mut [u8],
        root_pt: u64,
    ) -> Result<()> {
        use crate::sandbox::snapshot::PageTableReader;

        if destination.is_empty() {
            return Ok(());
        }

        let memory =
            GuestPhysicalMemoryView::new(&self.shared_mem, &self.scratch_mem, &[], self.layout);
        let pt_buf = PageTableReader::new(&memory, root_pt);
        let mut copied = 0usize;
        let mut current_gva = gva;
        let mut saw_mapping = false;

        // SAFETY: The vCPU is stopped for this trace exit, so its page tables
        // cannot change during the walk.
        for mapping in
            unsafe { hyperlight_common::vmem::virt_to_phys(&pt_buf, gva, destination.len() as u64) }
        {
            saw_mapping = true;
            if mapping.virt_base > current_gva {
                return Err(new_error!(
                    "Page table walker returned mapping with virt_base {:#x} > current read position {:#x}",
                    mapping.virt_base,
                    current_gva,
                ));
            }

            let page_offset = usize::try_from(current_gva - mapping.virt_base)?;
            let mapping_len = usize::try_from(mapping.len)?;
            let available = mapping_len
                .checked_sub(page_offset)
                .ok_or_else(|| new_error!("page-table mapping offset is out of bounds"))?;
            let bytes_to_copy = (destination.len() - copied).min(available);

            let gpa = mapping
                .phys_base
                .checked_add(u64::try_from(page_offset)?)
                .ok_or_else(|| new_error!("guest physical address overflows"))?;
            memory.read(gpa, &mut destination[copied..copied + bytes_to_copy])?;
            copied += bytes_to_copy;
            current_gva = current_gva
                .checked_add(u64::try_from(bytes_to_copy)?)
                .ok_or_else(|| new_error!("guest virtual address overflows"))?;
            if copied == destination.len() {
                break;
            }
        }

        if !saw_mapping {
            return Err(new_error!(
                "No page table mappings found for GVA {:#x} (len {})",
                gva,
                destination.len(),
            ));
        }
        if copied != destination.len() {
            return Err(new_error!(
                "Could not read full GVA range: got {} of {} bytes",
                copied,
                destination.len()
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use std::sync::Arc;

    use hyperlight_common::vmem::PAGE_SIZE;
    #[cfg(feature = "mem_profile")]
    use hyperlight_common::vmem::{self, BasicMapping, Mapping, MappingKind};
    use hyperlight_testing::sandbox_sizes::{LARGE_HEAP_SIZE, MEDIUM_HEAP_SIZE, SMALL_HEAP_SIZE};
    use hyperlight_testing::simple_guest_as_pathbuf;

    use super::{GuestBacking, GuestPhysicalMemoryView, SnapshotMemoryBacking};
    #[cfg(feature = "mem_profile")]
    use super::{GuestPageTableBuffer, SandboxMemoryManager};
    use crate::GuestBinary;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::memory_region::MemoryRegionType;
    use crate::mem::shared_mem::ExclusiveSharedMemory;
    #[cfg(feature = "mem_profile")]
    use crate::mem::shared_mem::ReadonlySharedMemory;
    use crate::sandbox::SandboxConfiguration;
    #[cfg(feature = "mem_profile")]
    use crate::sandbox::snapshot::NextAction;
    use crate::sandbox::snapshot::{Snapshot, SnapshotBlob, SnapshotLayer, SnapshotMemory};

    /// Build a Snapshot for the given configuration and verify the
    /// NULL page is not mapped in its page tables.
    fn verify_page_tables(name: &str, config: SandboxConfiguration) {
        let path = simple_guest_as_pathbuf();
        let snapshot = Snapshot::from_env(GuestBinary::FilePath(path), config)
            .unwrap_or_else(|e| panic!("{}: failed to create snapshot: {}", name, e));

        // Verify NULL page (0x0) is NOT mapped
        assert!(
            unsafe { hyperlight_common::vmem::virt_to_phys(&snapshot, 0, 1) }
                .next()
                .is_none(),
            "{}: NULL page (0x0) should NOT be mapped",
            name
        );
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
                cfg.set_scratch_size(0x100000);
                cfg
            }),
        ];

        for (name, config) in test_cases {
            verify_page_tables(name, config);
        }
    }

    #[test]
    fn snapshot_memory_backing_reads_live_ranges() {
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let scratch = base + (4 * PAGE_SIZE) as u64;
        let layer = |gpa_start: u64, value: u8, with_page_tables: bool| {
            let data_len = PAGE_SIZE;
            let storage_len = data_len + usize::from(with_page_tables) * PAGE_SIZE;
            let mut storage = ExclusiveSharedMemory::new(storage_len).unwrap();
            storage.copy_from_slice(&vec![value; PAGE_SIZE], 0).unwrap();
            let storage = storage.freeze().unwrap();
            let blob = Arc::new(
                SnapshotBlob::new(
                    storage,
                    Some(gpa_start),
                    data_len,
                    with_page_tables.then_some(data_len..storage_len),
                    scratch,
                )
                .unwrap(),
            );
            SnapshotLayer::new(blob, std::iter::once(0..PAGE_SIZE).collect()).unwrap()
        };
        let first = layer(base, 0x11, false);
        let second = layer(base + PAGE_SIZE as u64, 0x22, true);
        let memory = Arc::new(SnapshotMemory::new(Box::new([first, second]), 1).unwrap());
        let (snapshot, _) = SnapshotMemoryBacking::from_snapshot(memory)
            .unwrap()
            .build();
        let mut bytes = [0; 2];

        snapshot
            .read_snapshot_gpa(base + PAGE_SIZE as u64 - 1, &mut bytes)
            .unwrap();

        assert_eq!(bytes, [0x11, 0x22]);

        let data_len = 3 * PAGE_SIZE;
        let storage_len = data_len + PAGE_SIZE;
        let storage = ExclusiveSharedMemory::new(storage_len)
            .unwrap()
            .freeze()
            .unwrap();
        let blob = Arc::new(
            SnapshotBlob::new(
                storage,
                Some(base),
                data_len,
                Some(data_len..storage_len),
                scratch,
            )
            .unwrap(),
        );
        let layer =
            SnapshotLayer::new(blob, Box::new([0..PAGE_SIZE, 2 * PAGE_SIZE..3 * PAGE_SIZE]))
                .unwrap();
        let memory = Arc::new(SnapshotMemory::new(Box::new([layer]), 0).unwrap());
        let (snapshot, _) = SnapshotMemoryBacking::from_snapshot(memory)
            .unwrap()
            .build();

        assert!(
            snapshot
                .read_snapshot_gpa(base + PAGE_SIZE as u64 - 1, &mut bytes)
                .is_err()
        );
    }

    #[cfg(feature = "mem_profile")]
    #[test]
    fn mem_profile_reader_reads_across_snapshot_layers() {
        let cfg = SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, PAGE_SIZE, 0, None).unwrap();
        let host_page_size = page_size::get();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let second_gpa = base + host_page_size as u64;
        let scratch_base = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size());
        let pt_base = layout.get_pt_base_gpa();
        let pt_buf = GuestPageTableBuffer::new(pt_base as usize);
        let kind = MappingKind::Basic(BasicMapping {
            readable: true,
            writable: false,
            executable: false,
        });
        unsafe {
            vmem::map(
                &pt_buf,
                Mapping {
                    phys_base: base,
                    virt_base: base,
                    len: PAGE_SIZE as u64,
                    kind,
                },
            );
            vmem::map(
                &pt_buf,
                Mapping {
                    phys_base: second_gpa,
                    virt_base: base + PAGE_SIZE as u64,
                    len: PAGE_SIZE as u64,
                    kind,
                },
            );
        }
        let page_tables = pt_buf.into_bytes();
        layout.ensure_page_tables_fit(page_tables.len()).unwrap();

        let first_storage = ReadonlySharedMemory::from_bytes(&vec![0x11; host_page_size]).unwrap();
        let first_blob = Arc::new(
            SnapshotBlob::new(
                first_storage,
                Some(base),
                host_page_size,
                None,
                scratch_base,
            )
            .unwrap(),
        );
        let first =
            SnapshotLayer::new(first_blob, std::iter::once(0..host_page_size).collect()).unwrap();

        let logical_len = host_page_size + page_tables.len();
        let mut second_bytes = vec![0u8; logical_len.next_multiple_of(host_page_size)];
        second_bytes[..host_page_size].fill(0x22);
        second_bytes[host_page_size..logical_len].copy_from_slice(&page_tables);
        let second_storage = ReadonlySharedMemory::from_bytes(&second_bytes).unwrap();
        let second_blob = Arc::new(
            SnapshotBlob::new(
                second_storage,
                Some(second_gpa),
                host_page_size,
                Some(host_page_size..logical_len),
                scratch_base,
            )
            .unwrap(),
        );
        let second =
            SnapshotLayer::new(second_blob, std::iter::once(0..host_page_size).collect()).unwrap();
        let memory = Arc::new(SnapshotMemory::new(Box::new([first, second]), 1).unwrap());
        let manager = SandboxMemoryManager::new(
            layout,
            SnapshotMemoryBacking::from_snapshot(memory).unwrap(),
            ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap(),
            NextAction::None,
        );
        let (manager, _) = manager.build().unwrap();
        let mut reader = manager.guest_virtual_memory_reader(pt_base);
        let mut bytes = [0u8; 2];

        reader
            .read(base + PAGE_SIZE as u64 - 1, &mut bytes)
            .unwrap();

        assert_eq!(bytes, [0x11, 0x22]);
    }

    #[test]
    fn guest_physical_memory_view_resolves_scratch_and_dynamic_edges() {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_scratch_size(0x20000);
        let layout = SandboxMemoryLayout::new(cfg, PAGE_SIZE, 0, None).unwrap();
        let scratch_start = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size());
        let page_tables = ExclusiveSharedMemory::new(PAGE_SIZE)
            .unwrap()
            .freeze()
            .unwrap();
        let snapshot = Arc::new(
            SnapshotMemory::from_flat(
                page_tables,
                SandboxMemoryLayout::BASE_ADDRESS as u64,
                0,
                0..PAGE_SIZE,
                scratch_start,
            )
            .unwrap(),
        );
        let (snapshot, _) = SnapshotMemoryBacking::from_snapshot(snapshot)
            .unwrap()
            .build();

        let mut scratch = ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap();
        scratch.copy_from_slice(&[0x11], 0).unwrap();
        scratch
            .copy_from_slice(&[0x22], layout.get_scratch_size() - 1)
            .unwrap();
        let (scratch, _) = scratch.build();

        let dynamic_gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let mut dynamic = ExclusiveSharedMemory::new(PAGE_SIZE).unwrap();
        dynamic.copy_from_slice(&[0x33], 0).unwrap();
        dynamic.copy_from_slice(&[0x44], PAGE_SIZE - 1).unwrap();
        let (dynamic, dynamic_guest) = dynamic.build();
        let dynamic_region = dynamic_guest.mapping_at(dynamic_gpa, MemoryRegionType::Scratch);
        let dynamic_regions = [dynamic_region];
        let view = GuestPhysicalMemoryView::new(&snapshot, &scratch, &dynamic_regions, layout);
        let mut byte = [0u8; 1];

        assert_eq!(
            view.read(scratch_start, &mut byte).unwrap(),
            GuestBacking::Scratch { offset: 0 }
        );
        assert_eq!(byte, [0x11]);
        assert_eq!(
            view.read(
                scratch_start + layout.get_scratch_size() as u64 - 1,
                &mut byte,
            )
            .unwrap(),
            GuestBacking::Scratch {
                offset: layout.get_scratch_size() - 1,
            }
        );
        assert_eq!(byte, [0x22]);
        assert_eq!(
            view.read(dynamic_gpa, &mut byte).unwrap(),
            GuestBacking::Dynamic {
                region_index: 0,
                offset: 0,
            }
        );
        assert_eq!(byte, [0x33]);
        assert_eq!(
            view.read(dynamic_gpa + PAGE_SIZE as u64 - 1, &mut byte)
                .unwrap(),
            GuestBacking::Dynamic {
                region_index: 0,
                offset: PAGE_SIZE - 1,
            }
        );
        assert_eq!(byte, [0x44]);
        assert!(
            view.resolve(dynamic_gpa + PAGE_SIZE as u64 - 1, 2)
                .is_none()
        );
        assert!(
            view.resolve(scratch_start + layout.get_scratch_size() as u64 - 1, 2,)
                .is_none()
        );

        drop(dynamic);
        drop(dynamic_guest);
    }
}
