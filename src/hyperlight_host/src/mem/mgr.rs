// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use hyperlight_common::log_level::GuestLogFilter;
use hyperlight_common::stream::{DEFAULT_WINDOW, Mux, Side};
use hyperlight_common::transport::{Buf, EncodedMessage, MailboxValue, MsgKind, PendingMessage};
use hyperlight_common::virtq::ReplyChain;
use hyperlight_common::vmem::{self, PAGE_TABLE_SIZE};
#[cfg(crashdump)]
use hyperlight_common::vmem::{BasicMapping, MappingKind};
use tracing::{Span, instrument};

use super::layout::SandboxMemoryLayout;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory};
use super::virtq::{self, G2hConsumer, H2gConsumer, VirtqSnapshot};
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::mem::memory_region::MemoryRegion;
#[cfg(crashdump)]
use crate::mem::memory_region::{CrashDumpRegion, MemoryRegionFlags, MemoryRegionType};
use crate::sandbox::snapshot::{NextAction, Snapshot, SnapshotMemoryBacking};
use crate::{HyperlightError, Result, new_error};

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
        MappingKind::ZeroInit(bm) => {
            let mut flags = MemoryRegionFlags::empty();
            if bm.readable {
                flags |= MemoryRegionFlags::READ;
            }
            if bm.writable {
                flags |= MemoryRegionFlags::WRITE;
            }
            if bm.executable {
                flags |= MemoryRegionFlags::EXECUTE;
            }
            (flags, MemoryRegionType::Snapshot)
        }
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
pub(crate) enum BackingSource {
    /// Snapshot layer index.
    Snapshot(usize),
    Scratch,
    /// Dynamic region index.
    Dynamic(usize),
}

/// A guest physical range resolved to its backing memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GuestBacking {
    pub(crate) source: BackingSource,
    pub(crate) offset: usize,
}

/// Guest physical memory with scratch locked for exclusive access.
pub(crate) struct GuestPhysicalMemoryView<'a> {
    snapshot: &'a SnapshotMemoryBacking<HostSharedMemory>,
    scratch: &'a [u8],
    dynamic: &'a [MemoryRegion],
    layout: SandboxMemoryLayout,
}

impl<'a> GuestPhysicalMemoryView<'a> {
    /// Runs `f` with a view of `snapshot`, `scratch` and `dynamic`. Scratch
    /// stays locked until `f` returns.
    pub(crate) fn with_memory<T>(
        snapshot: &SnapshotMemoryBacking<HostSharedMemory>,
        scratch: &HostSharedMemory,
        dynamic: &[MemoryRegion],
        layout: SandboxMemoryLayout,
        f: impl FnOnce(&GuestPhysicalMemoryView<'_>) -> Result<T>,
    ) -> Result<T> {
        scratch.with_exclusive_contents(|scratch| {
            f(&GuestPhysicalMemoryView {
                snapshot,
                scratch,
                dynamic,
                layout,
            })
        })?
    }

    pub(crate) fn snapshot(&self) -> &'a SnapshotMemoryBacking<HostSharedMemory> {
        self.snapshot
    }

    pub(crate) fn resolve(&self, gpa: u64, len: usize) -> Option<GuestBacking> {
        let end = gpa.checked_add(u64::try_from(len).ok()?)?;
        let scratch_start =
            hyperlight_common::layout::scratch_base_gpa(self.layout.get_scratch_size());
        let scratch_end = scratch_start.checked_add(self.layout.get_scratch_size() as u64)?;
        if scratch_start <= gpa && end <= scratch_end {
            return Some(GuestBacking {
                source: BackingSource::Scratch,
                offset: usize::try_from(gpa - scratch_start).ok()?,
            });
        }
        if let Some((layer_index, offset)) = self.snapshot.resolve(gpa, len) {
            return Some(GuestBacking {
                source: BackingSource::Snapshot(layer_index),
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
                    Some(GuestBacking {
                        source: BackingSource::Dynamic(region_index),
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
        let offset = backing.offset;
        match backing.source {
            BackingSource::Snapshot(layer_index) => {
                self.snapshot
                    .copy_layer_to_slice(layer_index, destination, offset)?
            }
            BackingSource::Scratch => {
                let source = offset
                    .checked_add(destination.len())
                    .and_then(|end| self.scratch.get(offset..end))
                    .ok_or_else(|| new_error!("scratch read range is out of bounds"))?;
                destination.copy_from_slice(source);
            }
            BackingSource::Dynamic(region_index) => {
                let region = &self.dynamic[region_index];
                #[allow(clippy::useless_conversion)]
                let host_start: usize = region.host_region.start.into();
                #[allow(clippy::useless_conversion)]
                let host_end: usize = region.host_region.end.into();
                let source_end = offset
                    .checked_add(destination.len())
                    .ok_or_else(|| new_error!("dynamic memory read range overflows"))?;
                let host_len = host_end
                    .checked_sub(host_start)
                    .ok_or_else(|| new_error!("dynamic memory host range is invalid"))?;
                if source_end > host_len {
                    return Err(new_error!("dynamic memory read range is out of bounds"));
                }
                let source_start = host_start
                    .checked_add(offset)
                    .ok_or_else(|| new_error!("dynamic memory host address overflows"))?;
                // SAFETY: Dynamic regions come from `Sandbox::map_region`, whose
                // contract keeps them valid and unmodified for the sandbox's
                // lifetime. The checks above bound this read.
                unsafe {
                    std::ptr::copy(
                        source_start as *const u8,
                        destination.as_mut_ptr(),
                        destination.len(),
                    )
                };
            }
        }
        Ok(())
    }

    #[cfg(crashdump)]
    fn host_range(&self, gpa: u64, len: usize) -> Result<std::ops::Range<usize>> {
        let backing = self
            .resolve(gpa, len)
            .ok_or_else(|| new_error!("GPA range is not backed: {gpa:#x}"))?;
        let offset = backing.offset;
        let (base, backing_len) = match backing.source {
            BackingSource::Snapshot(layer_index) => self.snapshot.host_range(layer_index)?,
            BackingSource::Scratch => (self.scratch.as_ptr() as usize, self.scratch.len()),
            BackingSource::Dynamic(region_index) => {
                let region = &self.dynamic[region_index];
                #[allow(clippy::useless_conversion)]
                let start: usize = region.host_region.start.into();
                #[allow(clippy::useless_conversion)]
                let end: usize = region.host_region.end.into();
                (start, end - start)
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
#[cfg(any(feature = "mem_profile", feature = "trace_guest", test))]
pub(crate) struct GuestVirtualMemoryReader<'a> {
    memory: &'a GuestPhysicalMemoryView<'a>,
    root_pt: u64,
    cached_page: Option<(u64, u64)>,
}

#[cfg(any(feature = "mem_profile", feature = "trace_guest", test))]
impl<'a> GuestVirtualMemoryReader<'a> {
    fn new(memory: &'a GuestPhysicalMemoryView<'a>, root_pt: u64) -> Self {
        Self {
            memory,
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

        let pt_buf = PageTableReader::new(self.memory, self.root_pt);
        // SAFETY: The vCPU is stopped for this outb, so its page tables cannot
        // change during the walk.
        let mapping = unsafe {
            hyperlight_common::vmem::virt_to_phys(
                &pt_buf,
                page_gva,
                hyperlight_common::vmem::PAGE_SIZE as u64,
            )
        }
        .next();
        // A suppressed read leaves a not-present entry behind, so ask before
        // blaming the guest for an unmapped page.
        pt_buf.finish()?;
        let mapping = mapping.ok_or_else(|| new_error!("GVA page is not mapped: {page_gva:#x}"))?;
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

    pub(crate) fn read_exact(&mut self, gva: u64, destination: &mut [u8]) -> Result<()> {
        gva.checked_add(u64::try_from(destination.len())?)
            .ok_or_else(|| new_error!("guest virtual address overflows"))?;
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

/// Scratch-top slots the host writes and the guest applies and clears on its
/// next entry.
const GUEST_REQUEST_OFFSETS: [u64; 2] = [
    hyperlight_common::layout::SCRATCH_TOP_LIBC_RNG_SEED_OFFSET,
    hyperlight_common::layout::SCRATCH_TOP_GUEST_LOG_LEVEL_OFFSET,
];

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
    /// G2H consumer bound to the current scratch mapping.
    pub(crate) g2h_consumer: Option<G2hConsumer>,
    /// H2G consumer bound to the current scratch mapping.
    pub(crate) h2g_consumer: Option<H2gConsumer>,
    /// The stream session's Mux. Function calls and results move readers through it.
    pub(crate) mux: Mux,
    /// Reusable control storage for outgoing messages.
    pub(crate) encode_buffer: Vec<u8>,
    /// Correlation ID sequence survives consumer replacement and manager cloning.
    next_guest_cid: u32,
}

impl<S: Clone + SharedMemory> Clone for SandboxMemoryManager<S> {
    fn clone(&self) -> Self {
        Self {
            shared_mem: self.shared_mem.clone(),
            scratch_mem: self.scratch_mem.clone(),
            layout: self.layout,
            next_action: self.next_action,
            original_entrypoint: self.original_entrypoint,
            abort_buffer: self.abort_buffer.clone(),
            snapshot_count: self.snapshot_count,
            g2h_consumer: None,
            h2g_consumer: None,
            mux: Mux::new(Side::Host, DEFAULT_WINDOW),
            encode_buffer: Vec::new(),
            next_guest_cid: self.next_guest_cid,
        }
    }
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
        addr + offset
    }

    unsafe fn read_entry(&self, addr: u64) -> vmem::PageTableEntry {
        let buffer = self.buffer.borrow();
        let byte_offset = addr as usize - self.phys_base;
        let pte_size = core::mem::size_of::<vmem::PageTableEntry>();
        let Some(bytes) = buffer.get(byte_offset..byte_offset + pte_size) else {
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
        GuestPageTableBuffer {
            buffer: std::cell::RefCell::new(vec![0u8; PAGE_TABLE_SIZE]),
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
    /// First GPA available to the guest scratch allocator.
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
            g2h_consumer: None,
            h2g_consumer: None,
            mux: Mux::new(Side::Host, DEFAULT_WINDOW),
            encode_buffer: Vec::new(),
            next_guest_cid: 1,
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
            g2h_consumer: None,
            h2g_consumer: None,
            mux: self.mux,
            encode_buffer: self.encode_buffer,
            next_guest_cid: self.next_guest_cid,
        };
        let guest_mgr = SandboxMemoryManager {
            shared_mem: gshm,
            scratch_mem: gscratch,
            layout: self.layout,
            next_action: self.next_action,
            original_entrypoint: self.original_entrypoint,
            abort_buffer: Vec::new(), // Guest doesn't need abort buffer
            snapshot_count: self.snapshot_count,
            g2h_consumer: None,
            h2g_consumer: None,
            mux: Mux::new(Side::Host, DEFAULT_WINDOW),
            encode_buffer: Vec::new(),
            next_guest_cid: self.next_guest_cid,
        };
        host_mgr.update_scratch_bookkeeping()?;

        if matches!(host_mgr.next_action, NextAction::Initialise(_)) {
            let status = MailboxValue::InitPending.as_bytes();
            let mbx = host_mgr.layout.mbx_scratch_offset();

            host_mgr.scratch_mem.copy_from_slice(status, mbx)?;
            host_mgr.create_virtq_consumers()?;
        }

        Ok((host_mgr, guest_mgr))
    }
}

/// Borrow `consumer`, or fail without poisoning when it is not attached.
fn attached<C>(consumer: &mut Option<C>) -> Result<&mut C> {
    consumer
        .as_mut()
        .ok_or_else(|| new_error!("virtqueue consumer is not attached"))
}

impl SandboxMemoryManager<HostSharedMemory> {
    /// Runs `f` with a view of guest physical memory, including `dynamic`.
    pub(crate) fn with_guest_memory<T>(
        &self,
        dynamic: &[MemoryRegion],
        f: impl FnOnce(&GuestPhysicalMemoryView<'_>) -> Result<T>,
    ) -> Result<T> {
        GuestPhysicalMemoryView::with_memory(
            &self.shared_mem,
            &self.scratch_mem,
            dynamic,
            self.layout,
            f,
        )
    }

    #[cfg(any(feature = "mem_profile", feature = "trace_guest", test))]
    pub(crate) fn with_guest_virtual_memory_reader<T>(
        &self,
        root_pt: u64,
        f: impl FnOnce(&mut GuestVirtualMemoryReader<'_>) -> Result<T>,
    ) -> Result<T> {
        self.with_guest_memory(&[], |memory| {
            f(&mut GuestVirtualMemoryReader::new(memory, root_pt))
        })
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
        scratch_size: usize,
    ) -> Result<Snapshot> {
        let target = self.layout.with_scratch_size(scratch_size)?;
        let virtq = match (&self.g2h_consumer, &self.h2g_consumer) {
            (Some(_), Some(_)) => Some(VirtqSnapshot::bootstrap(&target)?),
            (None, None) => None,
            _ => return Err(new_error!("virtqueue consumer ownership is incomplete")),
        };

        let layout = self.layout;
        let original_entrypoint = self.original_entrypoint;
        let snapshot_generation = self.snapshot_count + 1;
        let snapshot = self.with_guest_memory(&mapped_regions, |memory| {
            Snapshot::new(
                memory,
                layout,
                crate::mem::exe::LoadInfo::dummy(),
                root_pt_gpas,
                rsp_gva,
                sregs,
                #[cfg(target_arch = "x86_64")]
                msrs,
                next_action,
                original_entrypoint,
                snapshot_generation,
                host_functions,
                virtq,
                scratch_size,
            )
        })?;
        self.snapshot_count = snapshot.snapshot_generation();
        Ok(snapshot)
    }

    /// Create host consumers before the guest initializes the transport.
    ///
    /// The consumers begin at cursor zero and observe descriptors published
    /// during the first guest entry.
    fn create_virtq_consumers(&mut self) -> Result<()> {
        if self.g2h_consumer.is_some() || self.h2g_consumer.is_some() {
            return Err(new_error!("virtqueue consumers already exist"));
        }

        let (g2h, h2g) = virtq::create_consumers(&self.layout, &self.scratch_mem)?;
        self.g2h_consumer = Some(g2h);
        self.h2g_consumer = Some(h2g);
        Ok(())
    }

    /// Restore admitted ring images into this scratch mapping.
    pub(crate) fn restore_virtq(&mut self, snapshot: &VirtqSnapshot) -> Result<()> {
        if self.g2h_consumer.is_some() || self.h2g_consumer.is_some() {
            return Err(new_error!("virtqueue consumers are already attached"));
        }

        let (g2h, h2g) = snapshot.restore(&self.layout, &self.scratch_mem)?;
        self.g2h_consumer = Some(g2h);
        self.h2g_consumer = Some(h2g);
        Ok(())
    }

    /// Write a guest function call into the H2G virtqueue, then flush pending stream records.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_guest_function_call(&mut self, call: FunctionCall) -> Result<u32> {
        let cid = self.next_guest_cid;
        let bufsz = self.layout.get_h2g_buffer_size();
        let consumer = attached(&mut self.h2g_consumer)?;

        let pending = PendingMessage::new_call(call, cid, &mut self.mux)?;
        let encoded = pending.encode(&mut self.encode_buffer)?;

        let res = Self::write_h2g_message(consumer, bufsz, &encoded);
        if let Err(err) = res {
            if err.is_poison_error() {
                pending.fail();
            }

            return Err(err);
        }

        pending.settle(Ok(()))?;

        self.next_guest_cid = cid.wrapping_add(1);
        if self.next_guest_cid == 0 {
            self.next_guest_cid = 1;
        }

        self.flush_h2g_streams()?;
        Ok(cid)
    }

    /// Publish pending stream records into the posted H2G buffers, one buffer per message.
    pub(crate) fn flush_h2g_streams(&mut self) -> Result<()> {
        let bufsz = self.layout.get_h2g_buffer_size();
        let consumer = attached(&mut self.h2g_consumer)?;

        while let Some(pending) = PendingMessage::next_stream(&mut self.mux, bufsz) {
            let encoded = pending.encode(&mut self.encode_buffer).map_err(|err| {
                HyperlightError::TransportError(format!(
                    "Failed to encode H2G stream message: {err}"
                ))
            })?;

            let res = Self::try_write_h2g_message(consumer, bufsz, 0, &encoded);
            drop(encoded);

            match res {
                // Commit outgoing stream changes.
                Ok(true) => pending.settle(Ok(()))?,
                // Dropping the message leaves its records pending.
                Ok(false) => break,
                Err(err) => {
                    pending.fail();
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    /// Write `message` into posted H2G buffers of `buffer_size` bytes.
    ///
    /// Too few posted buffers is an admission error, which does not poison.
    fn write_h2g_message(
        consumer: &mut H2gConsumer,
        buffer_size: usize,
        message: &EncodedMessage<'_>,
    ) -> Result<()> {
        // Keep a buffer for a control call that releases retained external bytes.
        let reserve = usize::from(message.external_len() != 0);

        if !Self::try_write_h2g_message(consumer, buffer_size, reserve, message)? {
            let buf_cnt = message.total_len().div_ceil(buffer_size);
            return Err(new_error!(
                "H2G capacity cannot provide {buf_cnt} buffers with {reserve} spare"
            ));
        }

        Ok(())
    }

    /// Write `message` into posted H2G buffers of `buffer_size` bytes, keeping `reserve` more
    /// posted.
    ///
    /// Returns `false` and writes nothing when too few buffers are posted.
    fn try_write_h2g_message(
        consumer: &mut H2gConsumer,
        buffer_size: usize,
        reserve: usize,
        message: &EncodedMessage<'_>,
    ) -> Result<bool> {
        let buffer_count = message.total_len().div_ceil(buffer_size);

        // H2G receive buffers are writable-only, so any readable payload is malformed.
        let maybe_buffers = consumer
            .poll_batch(buffer_count, reserve, 0)
            .map_err(|err| HyperlightError::TransportError(format!("H2G poll failed: {err}")))?;

        let Some(buffers) = maybe_buffers else {
            return Ok(false);
        };

        // The message is a contiguous sequence of bytes, but the buffers are a chain of possibly
        // non contiguous slices. Write the message into the buffers in order, advancing the message
        // cursor as we go.
        let mut message = message.as_buf();

        for (recv, reply) in buffers {
            let ReplyChain::Writable(mut buffer) = reply else {
                return Err(HyperlightError::TransportError(
                    "H2G receive buffer is not writable".into(),
                ));
            };

            if buffer.desc_count() != 1 || buffer.capacity() != buffer_size {
                return Err(HyperlightError::TransportError(
                    "H2G receive buffer has an invalid shape".into(),
                ));
            }

            while message.has_remaining() && buffer.remaining() != 0 {
                let written = buffer.write(message.chunk()).map_err(|err| {
                    HyperlightError::TransportError(format!("H2G write failed: {err}"))
                })?;

                message.advance(written);
            }

            consumer.complete(recv, buffer).map_err(|err| {
                HyperlightError::TransportError(format!("H2G completion failed: {err}"))
            })?;
        }

        debug_assert!(!message.has_remaining());
        Ok(true)
    }

    /// Read a guest function result and the messages that follow it from the G2H virtqueue.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_h2g_result_from_g2h(&mut self, cid: u32) -> Result<FunctionCallResult> {
        let max_recv_len = self.layout.get_g2h_queue_dims().pool_len();
        let consumer = attached(&mut self.g2h_consumer)?;
        let mut result = None;

        loop {
            let maybe_next = consumer.poll(max_recv_len).map_err(|err| {
                HyperlightError::TransportError(format!("G2H poll failed: {err}"))
            })?;

            let Some((recv, reply)) = maybe_next else {
                break;
            };

            let mut message = virtq::RecvMessage::new(recv).map_err(|err| {
                HyperlightError::TransportError(format!("Failed to read G2H message header: {err}"))
            })?;

            if message.kind() != MsgKind::Response {
                virtq::recv_one_way(consumer, &mut self.mux, message, reply)
                    .map_err(|err| HyperlightError::TransportError(format!("{err:#}")))?;

                continue;
            }

            if result.is_some() {
                return Err(HyperlightError::TransportError(
                    "G2H has more than one guest function result".into(),
                ));
            }

            if !matches!(&reply, ReplyChain::Ack(_)) {
                return Err(HyperlightError::TransportError(
                    "G2H result entry has writable buffers".into(),
                ));
            }

            if message.cid() != cid {
                return Err(HyperlightError::TransportError(
                    "G2H guest function result correlation ID mismatch".into(),
                ));
            }

            let decoded = message.decode_result(&mut self.mux);

            consumer
                .complete(message.into_chain(), reply)
                .map_err(|err| {
                    HyperlightError::TransportError(format!(
                        "Failed to complete G2H guest function result: {err}"
                    ))
                })?;

            result = Some(decoded.map_err(|err| {
                HyperlightError::TransportError(format!(
                    "Failed to decode G2H guest function result: {err}"
                ))
            })?);
        }

        result.ok_or_else(|| {
            HyperlightError::TransportError("G2H has no guest function result after halt".into())
        })
    }

    /// Apply the one-way messages a progress turn left in the G2H virtqueue.
    ///
    /// A guest function result is a transport error.
    #[cfg(feature = "streams")]
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_progress_from_g2h(&mut self) -> Result<()> {
        let max_recv_len = self.layout.get_g2h_queue_dims().pool_len();
        let consumer = attached(&mut self.g2h_consumer)?;

        loop {
            let maybe_next = consumer.poll(max_recv_len).map_err(|err| {
                HyperlightError::TransportError(format!("G2H poll failed: {err}"))
            })?;

            let Some((recv, reply)) = maybe_next else {
                return Ok(());
            };

            let message = virtq::RecvMessage::new(recv).map_err(|err| {
                HyperlightError::TransportError(format!("Failed to read G2H message header: {err}"))
            })?;

            virtq::recv_one_way(consumer, &mut self.mux, message, reply)
                .map_err(|err| HyperlightError::TransportError(format!("{err:#}")))?;
        }
    }

    /// Require successful guest initialization at the startup halt.
    pub(crate) fn require_initialization_complete(&self) -> Result<()> {
        let status = self
            .scratch_mem
            .read::<u64>(self.layout.mbx_scratch_offset())
            .map_err(|error| HyperlightError::TransportError(error.to_string()))?;

        match MailboxValue::try_from(status) {
            Ok(MailboxValue::InitComplete) => Ok(()),
            Ok(MailboxValue::InitPending) => Err(HyperlightError::TransportError(
                "Guest did not complete initialization".into(),
            )),
            Err(_) => Err(HyperlightError::TransportError(format!(
                "Guest published invalid initialization status {status:#x}"
            ))),
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
        // Inherit the snapshot's own generation number — the
        // guest-visible counter reflects "which snapshot is the
        // sandbox currently a clone of", not "how many restores have
        // happened into this (possibly-reused) partition".
        self.snapshot_count = snapshot.snapshot_generation();
        // Carry the guest ELF entry point across restore so crashdumps
        // report the restored image's entry.
        self.original_entrypoint = snapshot.original_entrypoint();
    }

    /// Install captured memory and fresh transport ownership.
    ///
    /// A capture with another scratch size moves the scratch base and page
    /// tables. It gets new scratch, which the caller maps.
    pub(crate) fn install_captured_snapshot(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<(
        SnapshotMemoryBacking<GuestSharedMemory>,
        Option<GuestSharedMemory>,
    )> {
        if snapshot.layout().get_scratch_size() != self.scratch_mem.mem_size() {
            let requests = self.guest_requests()?;
            let memory = self.restore_snapshot(snapshot)?;
            self.set_guest_requests(requests)?;
            return Ok(memory);
        }

        let virtq = snapshot
            .virtq()
            .ok_or_else(|| new_error!("running snapshot has no canonical transport state"))?;

        let used_scratch_end = self.used_scratch_end_gpa()?;
        let gsnapshot = self.replace_snapshot_memory(snapshot)?;

        self.g2h_consumer = None;
        self.h2g_consumer = None;
        self.apply_snapshot_metadata(snapshot);
        self.update_snapshot_scratch_bookkeeping()?;
        self.zero_freed_scratch(used_scratch_end)?;
        self.restore_virtq(virtq)?;

        Ok((gsnapshot, None))
    }

    /// The end of the scratch the guest has allocated: its allocator's next
    /// free page. The guest controls that value, so it is held to the
    /// transport arena, where the guest's allocator stops.
    fn used_scratch_end_gpa(&self) -> Result<u64> {
        let offset = self.scratch_mem.mem_size()
            - hyperlight_common::layout::SCRATCH_TOP_ALLOCATOR_OFFSET as usize;
        let end = self.scratch_mem.read::<u64>(offset)?;
        Ok(end.min(self.layout.get_transport_arena().base_addr()))
    }

    /// Bytes of scratch the guest has allocated since the allocator was
    /// last reset, at build, restore or snapshot.
    pub(crate) fn scratch_allocated_bytes(&self) -> Result<u64> {
        Ok(self
            .used_scratch_end_gpa()?
            .saturating_sub(self.first_free_scratch_gpa()))
    }

    /// Zeroes the scratch pages freed by resetting the allocator, up to
    /// `end`, the allocator's end as `used_scratch_end_gpa` read it.
    fn zero_freed_scratch(&mut self, end: u64) -> Result<()> {
        let scratch_base = hyperlight_common::layout::scratch_base_gpa(self.scratch_mem.mem_size());
        let start = self.first_free_scratch_gpa();
        if end <= start {
            return Ok(());
        }
        let start = usize::try_from(start - scratch_base)?;
        let end = usize::try_from(end - scratch_base)?;
        self.scratch_mem
            .with_exclusivity(|scratch| scratch.as_mut_slice()[start..end].fill(0))?;
        Ok(())
    }

    /// Restore base memory after the caller checks snapshot compatibility.
    pub(crate) fn restore_snapshot(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<(
        SnapshotMemoryBacking<GuestSharedMemory>,
        Option<GuestSharedMemory>,
    )> {
        let virtq = snapshot.virtq();

        if virtq.is_none() && matches!(snapshot.next_action(), NextAction::Call(_)) {
            return Err(new_error!(
                "running snapshot has no canonical transport state"
            ));
        }

        self.g2h_consumer = None;
        self.h2g_consumer = None;
        self.mux = Mux::new(Side::Host, DEFAULT_WINDOW);

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
        if let Some(virtq) = virtq {
            self.restore_virtq(virtq)?;
        } else if matches!(snapshot.next_action(), NextAction::Initialise(_)) {
            self.scratch_mem.copy_from_slice(
                MailboxValue::InitPending.as_bytes(),
                self.layout.mbx_scratch_offset(),
            )?;
            self.create_virtq_consumers()?;
        }
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

    fn guest_requests(&self) -> Result<[u64; 2]> {
        let scratch_size = self.scratch_mem.mem_size();
        let mut values = [0; 2];
        for (value, offset) in values.iter_mut().zip(GUEST_REQUEST_OFFSETS) {
            *value = self
                .scratch_mem
                .read::<u64>(scratch_size - offset as usize)?;
        }
        Ok(values)
    }

    fn set_guest_requests(&mut self, values: [u64; 2]) -> Result<()> {
        for (value, offset) in values.into_iter().zip(GUEST_REQUEST_OFFSETS) {
            self.update_scratch_bookkeeping_item(offset, value)?;
        }
        Ok(())
    }

    pub(crate) fn request_libc_rng_reseed(&mut self, seed: u32) -> Result<()> {
        // Zero means no request. The upper half marks a pending request, and
        // the lower half contains the complete u32 seed.
        self.update_scratch_bookkeeping_item(
            hyperlight_common::layout::SCRATCH_TOP_LIBC_RNG_SEED_OFFSET,
            (1_u64 << 32) | u64::from(seed),
        )
    }

    pub(crate) fn request_guest_log_level_update(
        &mut self,
        log_level: tracing_core::LevelFilter,
    ) -> Result<()> {
        self.update_scratch_bookkeeping_item(
            hyperlight_common::layout::SCRATCH_TOP_GUEST_LOG_LEVEL_OFFSET,
            (hyperlight_common::log_level::GUEST_LOG_FILTER_UPDATE_PENDING)
                | u64::from(GuestLogFilter::from(log_level)),
        )
    }

    fn update_scratch_bookkeeping(&mut self) -> Result<()> {
        use hyperlight_common::layout::*;
        let scratch_size = self.scratch_mem.mem_size();
        self.update_scratch_bookkeeping_item(SCRATCH_TOP_SIZE_OFFSET, scratch_size as u64)?;
        self.update_snapshot_scratch_bookkeeping()?;

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
        // Record the G2H and H2G queue sizes, pool page counts, and buffer sizes.
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_G2H_QUEUE_SIZE_OFFSET,
            u64::try_from(self.layout.get_g2h_queue_size())?,
        )?;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_G2H_POOL_PAGES_OFFSET,
            u64::try_from(self.layout.get_g2h_pool_pages())?,
        )?;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_G2H_BUFFER_SIZE_OFFSET,
            u64::try_from(self.layout.get_g2h_buffer_size())?,
        )?;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_H2G_QUEUE_SIZE_OFFSET,
            u64::try_from(self.layout.get_h2g_queue_size())?,
        )?;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_H2G_POOL_PAGES_OFFSET,
            u64::try_from(self.layout.get_h2g_pool_pages())?,
        )?;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_H2G_BUFFER_SIZE_OFFSET,
            u64::try_from(self.layout.get_h2g_buffer_size())?,
        )?;

        let transport_arena = self.layout.get_transport_arena();
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET,
            transport_arena.base_addr(),
        )?;

        // Copy page tables from `shared_mem` into scratch. PT bytes
        // are appended to the snapshot blob at build time and live
        // just past the end of the guest-visible KVM slot (see
        // `Snapshot::new`). Keeping them outside the KVM slot avoids
        // overlapping with `map_file_cow` regions installed
        // immediately after the snapshot in the guest PA space.
        let page_tables = self.shared_mem.page_table_bytes();
        let offset = self.layout.get_pt_base_scratch_offset();
        self.scratch_mem
            .with_exclusivity(|scratch| scratch.copy_from_slice(page_tables, offset))??;

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
        self.with_guest_memory(mmap_regions, |memory| {
            let pt_buf = PageTableReader::new(memory, root_pt);
            let mut regions: Vec<CrashDumpRegion> = Vec::new();
            let mut saw_mapping = false;
            // SAFETY: Crash handling runs with the vCPU stopped, so its page tables
            // cannot change during the walk.
            for mapping in unsafe { hyperlight_common::vmem::virt_to_phys(&pt_buf, 0, len as u64) }
            {
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

                    if !try_coalesce_region(
                        &mut regions,
                        virt_base,
                        virt_end,
                        host_region.start,
                        flags,
                    ) {
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
        })
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
        self.with_guest_virtual_memory_reader(root_pt, |reader| {
            reader.read_exact(gva, &mut result)
        })?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::sync::Arc;
    #[cfg(feature = "streams")]
    use std::{
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCallType;
    use hyperlight_common::flatbuffer_wrappers::function_types::{
        ParameterValue, ReturnType, ReturnValue,
    };
    #[cfg(feature = "streams")]
    use hyperlight_common::stream::{self, StreamWriter};
    use hyperlight_common::transport::MsgHeader;
    use hyperlight_common::virtq::{BufferChainBuilder, DescFlags, MemOps, RingProducer};
    use hyperlight_common::vmem::{self, BasicMapping, Mapping, MappingKind, PAGE_SIZE};
    #[cfg(target_arch = "x86_64")]
    use hyperlight_testing::sandbox_sizes::{
        LARGE_SCRATCH_SIZE, MEDIUM_SCRATCH_SIZE, SMALL_SCRATCH_SIZE,
    };
    #[cfg(target_arch = "x86_64")]
    use hyperlight_testing::simple_guest_as_pathbuf;

    use super::*;
    #[cfg(target_arch = "x86_64")]
    use crate::GuestBinary;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::memory_region::MemoryRegionType;
    use crate::mem::shared_mem::{ExclusiveSharedMemory, ReadonlySharedMemory};
    use crate::mem::virtq::tests::{H2G_BUFFER_SIZE, SCRATCH_SIZE, TestCase, memory_layout};
    use crate::sandbox::SandboxConfiguration;
    #[cfg(target_arch = "x86_64")]
    use crate::sandbox::snapshot::Snapshot;
    use crate::sandbox::snapshot::memory::tests::flat_memory;
    use crate::sandbox::snapshot::{SnapshotBlob, SnapshotMemory};

    fn manager(case: &TestCase) -> SandboxMemoryManager<HostSharedMemory> {
        let host_page_size = page_size::get();
        let layout = memory_layout();
        let snapshot = Arc::new(flat_memory(
            &vec![0; host_page_size],
            &[0; PAGE_SIZE],
            SandboxMemoryLayout::BASE_ADDRESS as u64,
            hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size()),
        ));

        let mut mgr = SandboxMemoryManager::new(
            layout,
            SnapshotMemoryBacking::from_snapshot(snapshot)
                .unwrap()
                .build()
                .0,
            case.scratch.clone(),
            NextAction::None,
        );

        mgr.h2g_consumer = Some(case.h2g_consumer());
        mgr
    }

    fn h2g_call(bytes: usize) -> FunctionCall {
        let params = (bytes != 0).then(|| vec![ParameterValue::VecBytes(vec![0xa5; bytes])]);
        FunctionCall::new(
            "call".to_string(),
            params,
            FunctionCallType::Guest,
            ReturnType::Void,
        )
    }

    /// A call passing `params` and then a reader whose stream holds `data`, with its open writer.
    #[cfg(feature = "streams")]
    fn h2g_stream_call(
        mut params: Vec<ParameterValue>,
        data: &[u8],
    ) -> (FunctionCall, StreamWriter<u8>) {
        let (reader, mut writer) = stream::new::<u8>();
        let mut cx = Context::from_waker(Waker::noop());

        let written = pin!(writer.write(data)).poll(&mut cx);
        assert!(matches!(written, Poll::Ready(Ok(len)) if len == data.len()));

        params.push(ParameterValue::StreamReader(reader));
        let call = FunctionCall::new(
            "call".to_string(),
            Some(params),
            FunctionCallType::Guest,
            ReturnType::Void,
        );

        (call, writer)
    }

    #[test]
    fn rejects_invalid_h2g_descriptors() {
        for (len, expected) in [
            (H2G_BUFFER_SIZE as u32, "Payload data too large"),
            (0, "not writable"),
        ] {
            let case = TestCase::new();
            let mut mgr = manager(&case);
            let mut desc = case.h2g_desc(0);

            desc.flags &= !DescFlags::WRITE.bits();
            desc.len = len;
            case.set_h2g_desc(0, desc);

            let error = mgr.write_guest_function_call(h2g_call(0)).unwrap_err();

            assert!(error.to_string().contains(expected), "{error:#}");
            assert!(error.is_poison_error());
            assert!(matches!(error, HyperlightError::TransportError(_)));
        }
    }

    #[test]
    fn partial_h2g_write_is_fatal() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        let mut desc = case.h2g_desc(1);

        desc.addr = hyperlight_common::layout::scratch_base_gva(SCRATCH_SIZE) + SCRATCH_SIZE as u64;
        case.set_h2g_desc(1, desc);

        let error = mgr
            .write_guest_function_call(h2g_call(H2G_BUFFER_SIZE + 1024))
            .unwrap_err();

        assert!(error.to_string().contains("Memory write"), "{error:#}");
        assert!(error.is_poison_error());
        assert!(matches!(error, HyperlightError::TransportError(_)));
        assert_eq!(mgr.h2g_consumer.as_ref().unwrap().used_cursor().head(), 1);
    }

    #[test]
    fn insufficient_h2g_capacity_rolls_back() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        let cursor = mgr.h2g_consumer.as_ref().unwrap().avail_cursor();

        let error = mgr
            .write_guest_function_call(h2g_call(H2G_BUFFER_SIZE * 4))
            .unwrap_err();

        assert!(error.to_string().contains("H2G capacity"), "{error:#}");
        assert!(!error.is_poison_error());
        assert_eq!(mgr.h2g_consumer.as_ref().unwrap().avail_cursor(), cursor);
        assert_eq!(mgr.write_guest_function_call(h2g_call(0)).unwrap(), 1);
    }

    /// Admission fails before the transfer commits, so dropping the call closes its reader.
    #[cfg(feature = "streams")]
    #[test]
    fn insufficient_h2g_capacity_closes_readers() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        let cursor = mgr.h2g_consumer.as_ref().unwrap().avail_cursor();
        let params = vec![ParameterValue::VecBytes(vec![0xa5; H2G_BUFFER_SIZE * 4])];
        let (call, mut writer) = h2g_stream_call(params, b"hello");

        let error = mgr.write_guest_function_call(call).unwrap_err();

        assert!(error.to_string().contains("H2G capacity"), "{error:#}");
        assert!(!error.is_poison_error());
        assert_eq!(mgr.h2g_consumer.as_ref().unwrap().avail_cursor(), cursor);
        assert!(!mgr.mux.has_live_streams());

        let mut cx = Context::from_waker(Waker::noop());
        let written = pin!(writer.write(b"!")).poll(&mut cx);

        assert_eq!(written, Poll::Ready(Err(stream::StreamError::ReaderClosed)));
        assert_eq!(mgr.write_guest_function_call(h2g_call(0)).unwrap(), 1);
    }

    #[test]
    fn missing_g2h_result_is_fatal() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        mgr.g2h_consumer = Some(case.g2h_consumer());

        let Err(error) = mgr.read_h2g_result_from_g2h(1) else {
            panic!("expected missing G2H result");
        };

        assert!(
            error
                .to_string()
                .contains("G2H has no guest function result")
        );
        assert!(error.is_poison_error());
        assert!(matches!(error, HyperlightError::TransportError(_)));
    }

    /// The drain continues past the result, so a malformed Stream message after it is fatal.
    #[test]
    fn malformed_g2h_stream_message_is_fatal() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        mgr.g2h_consumer = Some(case.g2h_consumer());

        let mut guest = Mux::new(Side::Guest, DEFAULT_WINDOW);
        let mut buffer = Vec::new();
        let result = FunctionCallResult::new(Ok(ReturnValue::Int(7)));
        let pending = PendingMessage::new_result(result, 1, &mut guest).unwrap();
        let response: Vec<u8> = pending
            .encode(&mut buffer)
            .unwrap()
            .chunks()
            .flatten()
            .copied()
            .collect();

        // An unknown record tag.
        let mut records = MsgHeader::new(MsgKind::Stream, 0, 1, 1).as_bytes().to_vec();
        records.push(5);

        let mut producer = RingProducer::new(case.g2h_layout, case.mem.clone());
        let mut addr = case.g2h_pool_base;

        for message in [&response, &records] {
            case.mem.write(addr, message).unwrap();

            let chain = BufferChainBuilder::new()
                .readable(addr, message.len() as u32)
                .build()
                .unwrap();

            producer.submit_available(&chain).unwrap();
            addr += message.len() as u64;
        }

        let Err(error) = mgr.read_h2g_result_from_g2h(1) else {
            panic!("expected a malformed G2H stream message");
        };

        assert!(
            error.to_string().contains("Invalid G2H stream message"),
            "{error:#}"
        );
        assert!(error.is_poison_error());
        assert!(matches!(error, HyperlightError::TransportError(_)));
    }

    #[test]
    fn writes_dense_h2g_request_and_reserves_control_buffer() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        let external_len = H2G_BUFFER_SIZE * 2;
        let buffers: Vec<_> = (0..4).map(|index| case.h2g_desc(index).addr).collect();

        let cid = mgr
            .write_guest_function_call(h2g_call(external_len))
            .unwrap();

        let used = mgr.h2g_consumer.as_ref().unwrap().avail_cursor().head();
        let wire: Vec<u8> = (0..used)
            .flat_map(|index| case.h2g_buffer(index, buffers[index as usize]))
            .collect();

        let header = MsgHeader::from_bytes(&wire[..MsgHeader::SIZE]).unwrap();
        assert_eq!(header.kind, MsgKind::Request);
        assert_eq!(header.cid, cid);
        assert_eq!(header.payload_len as usize, wire.len() - MsgHeader::SIZE);

        let external = &wire[MsgHeader::SIZE + header.control_len as usize..];
        assert_eq!(external, vec![0xa5; external_len]);

        let cursor = mgr.h2g_consumer.as_ref().unwrap().avail_cursor();
        let error = mgr.write_guest_function_call(h2g_call(1)).unwrap_err();

        assert!(error.to_string().contains("H2G capacity"), "{error:#}");
        assert_eq!(mgr.h2g_consumer.as_ref().unwrap().avail_cursor(), cursor);
        assert_eq!(mgr.write_guest_function_call(h2g_call(0)).unwrap(), 2);
    }

    /// Stream messages follow the Request and can take the buffer it keeps spare.
    #[cfg(feature = "streams")]
    #[test]
    fn flushes_h2g_stream_message_after_request() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        let buffers: Vec<_> = (0..4).map(|index| case.h2g_desc(index).addr).collect();
        let params = vec![ParameterValue::VecBytes(vec![0xa5; H2G_BUFFER_SIZE * 2])];
        let (call, _writer) = h2g_stream_call(params, b"hello");

        let cid = mgr.write_guest_function_call(call).unwrap();
        assert_eq!(mgr.h2g_consumer.as_ref().unwrap().avail_cursor().head(), 4);

        let wire = case.h2g_buffer(0, buffers[0]);
        let header = MsgHeader::from_bytes(&wire[..MsgHeader::SIZE]).unwrap();
        assert_eq!(header.kind, MsgKind::Request);
        assert_eq!(header.cid, cid);

        let wire = case.h2g_buffer(3, buffers[3]);
        let header = MsgHeader::from_bytes(&wire[..MsgHeader::SIZE]).unwrap();
        assert_eq!(header.kind, MsgKind::Stream);
        assert_eq!(header.cid, 0);

        let data = &wire[MsgHeader::SIZE + header.control_len as usize..];
        assert_eq!(data, b"hello");
    }

    /// The Request is already published, so a failed stream write poisons and fails the Mux.
    #[cfg(feature = "streams")]
    #[test]
    fn failed_h2g_stream_flush_is_fatal() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        let mut desc = case.h2g_desc(1);

        desc.flags &= !DescFlags::WRITE.bits();
        desc.len = 0;
        case.set_h2g_desc(1, desc);

        let (call, _writer) = h2g_stream_call(Vec::new(), b"hello");
        let error = mgr.write_guest_function_call(call).unwrap_err();

        assert!(error.to_string().contains("not writable"), "{error:#}");
        assert!(error.is_poison_error());
        assert!(matches!(error, HyperlightError::TransportError(_)));
        assert!(PendingMessage::next_stream(&mut mgr.mux, H2G_BUFFER_SIZE).is_none());
    }

    #[test]
    fn incomplete_initialization_is_fatal() {
        let case = TestCase::new();
        let mgr = manager(&case);

        let error = mgr.require_initialization_complete().unwrap_err();

        assert_matches!(error, HyperlightError::TransportError(_));
        assert!(error.is_poison_error());
    }

    #[test]
    fn initialization_status_preserves_consumer_cursors() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        mgr.g2h_consumer = Some(case.g2h_consumer());
        mgr.write_guest_function_call(h2g_call(0)).unwrap();

        let mut producer = RingProducer::new(case.g2h_layout, case.mem.clone());
        producer.submit_one(case.g2h_pool_base, 64, true).unwrap();

        let consumer = mgr.g2h_consumer.as_mut().unwrap();
        let (recv, reply) = consumer.poll(0).unwrap().unwrap();
        consumer.complete(recv, reply).unwrap();
        let g2h_avail = consumer.avail_cursor();
        let g2h_used = consumer.used_cursor();
        assert_ne!(g2h_avail.head(), 0);

        let consumer = mgr.h2g_consumer.as_ref().unwrap();
        let h2g_avail = consumer.avail_cursor();
        let h2g_used = consumer.used_cursor();
        assert_ne!(h2g_avail.head(), 0);

        let mbx = mgr.layout.mbx_scratch_offset();
        mgr.scratch_mem
            .copy_from_slice(MailboxValue::InitComplete.as_bytes(), mbx)
            .unwrap();

        mgr.require_initialization_complete().unwrap();

        let consumer = mgr.g2h_consumer.as_ref().unwrap();
        assert_eq!(consumer.avail_cursor(), g2h_avail);
        assert_eq!(consumer.used_cursor(), g2h_used);

        let consumer = mgr.h2g_consumer.as_ref().unwrap();
        assert_eq!(consumer.avail_cursor(), h2g_avail);
        assert_eq!(consumer.used_cursor(), h2g_used);
        assert_eq!(mgr.write_guest_function_call(h2g_call(0)).unwrap(), 2);

        assert_matches!(producer.poll_used(), Ok(_));
    }

    #[test]
    fn invalid_initialization_status_is_fatal() {
        for status in [2, 3, 0xa000, u64::MAX - 1, u64::MAX] {
            let queue = TestCase::new();
            let mut mgr = manager(&queue);
            mgr.g2h_consumer = Some(queue.g2h_consumer());
            let mbx = mgr.layout.mbx_scratch_offset();
            mgr.scratch_mem.write::<u64>(mbx, status).unwrap();
            let error = mgr.require_initialization_complete().unwrap_err();

            assert_matches!(error, HyperlightError::TransportError(_));
            assert!(error.is_poison_error(), "{error}");
        }
    }

    #[test]
    fn guest_cid_wraps_without_zero() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        mgr.next_guest_cid = u32::MAX;

        assert_eq!(
            mgr.write_guest_function_call(h2g_call(0)).unwrap(),
            u32::MAX
        );
        assert_eq!(mgr.write_guest_function_call(h2g_call(0)).unwrap(), 1);
    }

    #[test]
    fn cloning_preserves_guest_cids_without_consumers() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        mgr.g2h_consumer = Some(case.g2h_consumer());
        mgr.write_guest_function_call(h2g_call(0)).unwrap();

        let cloned = mgr.clone();

        assert!(cloned.g2h_consumer.is_none());
        assert!(cloned.h2g_consumer.is_none());
        assert_eq!(cloned.next_guest_cid, 2);
        assert!(mgr.g2h_consumer.is_some());
        assert!(mgr.h2g_consumer.is_some());
    }

    #[test]
    fn restoring_transport_preserves_guest_cids() {
        let case = TestCase::new();
        let mut mgr = manager(&case);
        mgr.g2h_consumer = Some(case.g2h_consumer());
        let captured = VirtqSnapshot::bootstrap(&mgr.layout).unwrap();
        assert_eq!(mgr.write_guest_function_call(h2g_call(0)).unwrap(), 1);

        mgr.g2h_consumer = None;
        mgr.h2g_consumer = None;
        mgr.restore_virtq(&captured).unwrap();

        assert_eq!(mgr.write_guest_function_call(h2g_call(0)).unwrap(), 2);
    }

    /// Build a snapshot for the given configuration and verify the
    /// NULL page is not mapped in its page tables.
    #[cfg(target_arch = "x86_64")]
    fn verify_page_tables(name: &str, config: SandboxConfiguration) {
        let path = simple_guest_as_pathbuf();
        let snapshot = Snapshot::from_binary(GuestBinary::FilePath(path), config)
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
    #[cfg(target_arch = "x86_64")]
    fn test_page_tables_for_various_configurations() {
        let test_cases: [(&str, SandboxConfiguration); 4] = [
            ("default", { SandboxConfiguration::default() }),
            ("small (8MiB scratch)", {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_scratch_size(SMALL_SCRATCH_SIZE);
                cfg
            }),
            ("medium (64MiB scratch)", {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_scratch_size(MEDIUM_SCRATCH_SIZE);
                cfg
            }),
            ("large (256MiB scratch)", {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_scratch_size(LARGE_SCRATCH_SIZE);
                cfg
            }),
        ];

        for (name, config) in test_cases {
            verify_page_tables(name, config);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn build_creates_virtq_consumers_before_initialization() {
        let path = simple_guest_as_pathbuf();
        let bin = GuestBinary::FilePath(path);
        let config = SandboxConfiguration::default();

        let snapshot = Snapshot::from_binary(bin, config).unwrap();

        let mgr = SandboxMemoryManager::from_snapshot(&snapshot).unwrap();
        let (mgr, _) = mgr.build().unwrap();

        assert!(mgr.g2h_consumer.is_some());
        assert!(mgr.h2g_consumer.is_some());
    }

    #[test]
    fn snapshot_memory_backing_reads_across_layers() {
        let host_page_size = page_size::get();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let scratch = base + (4 * host_page_size) as u64;
        let layer = |gpa_start: u64, value: u8| {
            let data_len = host_page_size;
            let mut storage = ExclusiveSharedMemory::new(data_len).unwrap();
            storage
                .copy_from_slice(&vec![value; host_page_size], 0)
                .unwrap();
            let storage = storage.freeze(data_len).unwrap();
            Arc::new(SnapshotBlob::new(storage, gpa_start, 0, scratch).unwrap())
        };
        let first = layer(base, 0x11);
        let second = layer(base + host_page_size as u64, 0x22);
        let memory = Arc::new(
            SnapshotMemory::new(
                Box::new([first, second]),
                crate::sandbox::snapshot::memory::tests::stub_page_tables(),
            )
            .unwrap(),
        );
        let (snapshot, _) = SnapshotMemoryBacking::from_snapshot(memory)
            .unwrap()
            .build();
        let mut bytes = [0; 2];

        snapshot
            .read_snapshot_gpa(base + host_page_size as u64 - 1, &mut bytes)
            .unwrap();

        assert_eq!(bytes, [0x11, 0x22]);
        assert!(
            snapshot
                .read_snapshot_gpa(base + 2 * host_page_size as u64 - 1, &mut bytes)
                .is_err()
        );
    }

    fn virtual_reader_manager() -> (SandboxMemoryManager<HostSharedMemory>, u64, u64) {
        let cfg = SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, PAGE_SIZE).unwrap();
        let host_page_size = page_size::get();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let second_gpa = base + host_page_size as u64;
        let scratch_base = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size());
        let scratch_gpa = scratch_base + layout.get_scratch_size() as u64 - 0x10000;
        let pt_base = layout.get_pt_base_gpa();
        let pt_buf = GuestPageTableBuffer::new(pt_base as usize);
        let kind = MappingKind::Basic(BasicMapping {
            readable: true,
            writable: false,
            executable: false,
        });
        // SAFETY: The local page-table buffer has no concurrent writers.
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
            vmem::map(
                &pt_buf,
                Mapping {
                    phys_base: scratch_gpa,
                    virt_base: base + 2 * PAGE_SIZE as u64,
                    len: PAGE_SIZE as u64,
                    kind,
                },
            );
        }
        let page_tables = pt_buf.into_bytes();
        layout.ensure_page_tables_fit(page_tables.len()).unwrap();

        let first_storage =
            ReadonlySharedMemory::from_bytes(&vec![0x11; host_page_size], host_page_size).unwrap();
        let first = Arc::new(SnapshotBlob::new(first_storage, base, 0, scratch_base).unwrap());

        let second_storage =
            ReadonlySharedMemory::from_bytes(&vec![0x22; host_page_size], host_page_size).unwrap();
        let second =
            Arc::new(SnapshotBlob::new(second_storage, second_gpa, 0, scratch_base).unwrap());
        let memory = Arc::new(
            SnapshotMemory::new(
                Box::new([first, second]),
                crate::sandbox::snapshot::memory::tests::page_tables_from_bytes(&page_tables),
            )
            .unwrap(),
        );
        let manager = SandboxMemoryManager::new(
            layout,
            SnapshotMemoryBacking::from_snapshot(memory).unwrap(),
            ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap(),
            NextAction::None,
        );
        let (manager, _) = manager.build().unwrap();
        manager
            .scratch_mem
            .copy_from_slice(
                &vec![0x33; PAGE_SIZE],
                (scratch_gpa - scratch_base) as usize,
            )
            .unwrap();
        (manager, pt_base, base)
    }

    #[test]
    fn virtual_reader_reads_across_snapshot_layers() {
        let (manager, pt_base, base) = virtual_reader_manager();
        let mut bytes = [0u8; 2];

        manager
            .with_guest_virtual_memory_reader(pt_base, |reader| {
                reader.read_exact(base + PAGE_SIZE as u64 - 1, &mut bytes)
            })
            .unwrap();

        assert_eq!(bytes, [0x11, 0x22]);
    }

    #[test]
    fn virtual_reader_reads_snapshot_and_cow_scratch_across_pages() {
        let (manager, root, base) = virtual_reader_manager();
        let mut bytes = [0; 2];
        manager
            .with_guest_virtual_memory_reader(root, |reader| {
                reader.read_exact(base + 2 * PAGE_SIZE as u64 - 1, &mut bytes)
            })
            .unwrap();
        assert_eq!(bytes, [0x22, 0x33]);
    }

    #[test]
    fn virtual_reader_rejects_unmapped_and_overflowing_ranges() {
        let (manager, root, base) = virtual_reader_manager();
        manager
            .with_guest_virtual_memory_reader(root, |reader| {
                assert!(
                    reader
                        .read_exact(base + 3 * PAGE_SIZE as u64, &mut [0])
                        .is_err()
                );
                assert!(reader.read_exact(u64::MAX, &mut [0; 2]).is_err());
                assert!(reader.read_exact(u64::MAX, &mut []).is_ok());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn virtual_reader_reports_invalid_page_tables() {
        let (manager, _, base) = virtual_reader_manager();
        let error = manager
            .with_guest_virtual_memory_reader(u64::MAX, |reader| reader.read_exact(base, &mut [0]))
            .unwrap_err();
        assert!(error.to_string().contains("unbacked"));
    }

    #[test]
    fn guest_physical_memory_view_resolves_scratch_and_dynamic_edges() {
        let host_page_size = page_size::get();
        let layout = SandboxMemoryLayout::new(SandboxConfiguration::default(), PAGE_SIZE).unwrap();
        let scratch_start = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size());
        let snapshot = Arc::new(flat_memory(
            &[0u8; PAGE_SIZE],
            &[0; PAGE_SIZE],
            SandboxMemoryLayout::BASE_ADDRESS as u64,
            scratch_start,
        ));
        let (snapshot, _) = SnapshotMemoryBacking::from_snapshot(snapshot)
            .unwrap()
            .build();

        let mut scratch = ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap();
        scratch.copy_from_slice(&[0x11], 0).unwrap();
        scratch
            .copy_from_slice(&[0x22], layout.get_scratch_size() - 1)
            .unwrap();
        let (scratch, _) = scratch.build();

        let dynamic_gpa = SandboxMemoryLayout::BASE_ADDRESS as u64 + host_page_size as u64;
        let mut dynamic = ExclusiveSharedMemory::new(host_page_size).unwrap();
        dynamic.copy_from_slice(&[0x33], 0).unwrap();
        dynamic
            .copy_from_slice(&[0x44], host_page_size - 1)
            .unwrap();
        let (dynamic, dynamic_guest) = dynamic.build();
        let dynamic_region = dynamic_guest.mapping_at(dynamic_gpa, MemoryRegionType::Scratch);
        let dynamic_regions = [dynamic_region];
        GuestPhysicalMemoryView::with_memory(
            &snapshot,
            &scratch,
            &dynamic_regions,
            layout,
            |view| {
                let mut byte = [0u8; 1];

                assert_eq!(
                    view.read(scratch_start, &mut byte).unwrap(),
                    GuestBacking {
                        source: BackingSource::Scratch,
                        offset: 0,
                    }
                );
                assert_eq!(byte, [0x11]);
                assert_eq!(
                    view.read(
                        scratch_start + layout.get_scratch_size() as u64 - 1,
                        &mut byte,
                    )
                    .unwrap(),
                    GuestBacking {
                        source: BackingSource::Scratch,
                        offset: layout.get_scratch_size() - 1,
                    }
                );
                assert_eq!(byte, [0x22]);
                assert_eq!(
                    view.read(dynamic_gpa, &mut byte).unwrap(),
                    GuestBacking {
                        source: BackingSource::Dynamic(0),
                        offset: 0,
                    }
                );
                assert_eq!(byte, [0x33]);
                assert_eq!(
                    view.read(dynamic_gpa + host_page_size as u64 - 1, &mut byte)
                        .unwrap(),
                    GuestBacking {
                        source: BackingSource::Dynamic(0),
                        offset: host_page_size - 1,
                    }
                );
                assert_eq!(byte, [0x44]);
                assert!(
                    view.resolve(dynamic_gpa + host_page_size as u64 - 1, 2)
                        .is_none()
                );
                assert!(
                    view.resolve(scratch_start + layout.get_scratch_size() as u64 - 1, 2,)
                        .is_none()
                );
                Ok(())
            },
        )
        .unwrap();

        drop(dynamic);
        drop(dynamic_guest);
    }
}
