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
#[cfg(feature = "nanvix-unstable")]
use std::mem::offset_of;
use std::num::NonZeroU16;

use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::mem::PAGE_SIZE_USIZE;
use hyperlight_common::virtq::msg::{MsgKind, VirtqMsgHeader};
use hyperlight_common::virtq::{self, Layout as VirtqLayout};
use hyperlight_common::vmem::{self, PAGE_TABLE_SIZE};
#[cfg(all(feature = "crashdump", not(feature = "i686-guest")))]
use hyperlight_common::vmem::{BasicMapping, MappingKind};
use tracing::{Span, instrument};

use super::layout::SandboxMemoryLayout;
use super::shared_mem::{
    ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, ReadonlySharedMemory, SharedMemory,
};
use super::virtq_mem::HostMemOps;
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::mem::memory_region::MemoryRegion;
#[cfg(crashdump)]
use crate::mem::memory_region::{CrashDumpRegion, MemoryRegionFlags, MemoryRegionType};
use crate::sandbox::snapshot::{NextAction, Snapshot};
use crate::{Result, new_error};

/// Type alias for the host-side G2H virtqueue consumer.
pub(crate) type G2hConsumer = virtq::VirtqConsumer<HostMemOps, HostNotifier>;
/// Type alias for the host-side H2G virtqueue consumer.
pub(crate) type H2gConsumer = virtq::VirtqConsumer<HostMemOps, HostNotifier>;

/// No-op notifier for host-side consumer.
/// The host resumes the VM to notify the guest, not via the ring.
#[derive(Clone, Copy)]
pub(crate) struct HostNotifier;

impl virtq::Notifier for HostNotifier {
    fn notify(&self, _stats: virtq::QueueStats) {}
}

#[cfg(all(feature = "crashdump", not(feature = "i686-guest")))]
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
#[cfg(all(feature = "crashdump", not(feature = "i686-guest")))]
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

// It would be nice to have a simple type alias
// `SnapshotSharedMemory<S: SharedMemory>` that abstracts over the
// fact that the snapshot shared memory is `ReadonlySharedMemory`
// normally, but there is (temporary) support for writable
// `GuestSharedMemory` with `#[cfg(feature =
// "i686-guest")]`. Unfortunately, rustc gets annoyed about an
// unused type parameter, unless one goes to a little bit of effort to
// trick it...
mod unused_hack {
    #[cfg(not(unshared_snapshot_mem))]
    use crate::mem::shared_mem::ReadonlySharedMemory;
    use crate::mem::shared_mem::SharedMemory;
    pub trait SnapshotSharedMemoryT {
        type T<S: SharedMemory>;
    }
    pub struct SnapshotSharedMemory_;
    impl SnapshotSharedMemoryT for SnapshotSharedMemory_ {
        #[cfg(not(unshared_snapshot_mem))]
        type T<S: SharedMemory> = ReadonlySharedMemory;
        #[cfg(unshared_snapshot_mem)]
        type T<S: SharedMemory> = S;
    }
    pub type SnapshotSharedMemory<S> = <SnapshotSharedMemory_ as SnapshotSharedMemoryT>::T<S>;
}
impl ReadonlySharedMemory {
    pub(crate) fn to_mgr_snapshot_mem(
        &self,
    ) -> Result<SnapshotSharedMemory<ExclusiveSharedMemory>> {
        #[cfg(not(unshared_snapshot_mem))]
        let ret = self.clone();
        #[cfg(unshared_snapshot_mem)]
        let ret = self.copy_to_writable()?;
        Ok(ret)
    }
}
pub(crate) use unused_hack::SnapshotSharedMemory;
/// A struct that is responsible for laying out and managing the memory
/// for a given `Sandbox`.
pub(crate) struct SandboxMemoryManager<S: SharedMemory> {
    /// Shared memory for the Sandbox
    pub(crate) shared_mem: SnapshotSharedMemory<S>,
    /// Scratch memory for the Sandbox
    pub(crate) scratch_mem: S,
    /// The memory layout of the underlying shared memory
    pub(crate) layout: SandboxMemoryLayout,
    /// Offset for the execution entrypoint from `load_addr`
    pub(crate) entrypoint: NextAction,
    /// How many memory regions were mapped after sandbox creation
    pub(crate) mapped_rgns: u64,
    /// Buffer for accumulating guest abort messages
    pub(crate) abort_buffer: Vec<u8>,
    /// Generation counter: how many snapshots have been taken from
    /// this sandbox's execution path from init to here. Incremented
    /// on each `snapshot` call; on `restore_snapshot` we inherit the
    /// restored snapshot's own generation number so the guest-visible
    /// counter tracks which snapshot the sandbox is a clone of.
    pub(crate) snapshot_count: u64,
    /// G2H virtqueue consumer, created after sandbox init.
    pub(crate) g2h_consumer: Option<G2hConsumer>,
    /// H2G virtqueue consumer, created after sandbox init.
    pub(crate) h2g_consumer: Option<H2gConsumer>,
    /// Saved H2G pool GVA for prefilling after snapshot restore.
    pub(crate) h2g_pool_gva: Option<u64>,
}

impl<S: Clone + SharedMemory> Clone for SandboxMemoryManager<S> {
    fn clone(&self) -> Self {
        Self {
            shared_mem: self.shared_mem.clone(),
            scratch_mem: self.scratch_mem.clone(),
            layout: self.layout,
            entrypoint: self.entrypoint,
            mapped_rgns: self.mapped_rgns,
            abort_buffer: self.abort_buffer.clone(),
            snapshot_count: self.snapshot_count,
            g2h_consumer: None,
            h2g_consumer: None,
            h2g_pool_gva: self.h2g_pool_gva,
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
    /// Create a new `SandboxMemoryManager` with the given parameters
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        layout: SandboxMemoryLayout,
        shared_mem: SnapshotSharedMemory<S>,
        scratch_mem: S,
        entrypoint: NextAction,
    ) -> Self {
        Self {
            layout,
            shared_mem,
            scratch_mem,
            entrypoint,
            mapped_rgns: 0,
            abort_buffer: Vec::new(),
            snapshot_count: 0,
            g2h_consumer: None,
            h2g_consumer: None,
            h2g_pool_gva: None,
        }
    }

    /// Get mutable access to the abort buffer
    pub(crate) fn get_abort_buffer_mut(&mut self) -> &mut Vec<u8> {
        &mut self.abort_buffer
    }

    /// Create a snapshot with the given mapped regions
    pub(crate) fn snapshot(
        &mut self,
        sandbox_id: u64,
        mapped_regions: Vec<MemoryRegion>,
        root_pt_gpas: &[u64],
        rsp_gva: u64,
        sregs: CommonSpecialRegisters,
        entrypoint: NextAction,
    ) -> Result<Snapshot> {
        self.snapshot_count += 1;
        Snapshot::new(
            &mut self.shared_mem,
            &mut self.scratch_mem,
            sandbox_id,
            self.layout,
            crate::mem::exe::LoadInfo::dummy(),
            mapped_regions,
            root_pt_gpas,
            rsp_gva,
            sregs,
            entrypoint,
            self.snapshot_count,
        )
    }
}

impl SandboxMemoryManager<ExclusiveSharedMemory> {
    pub(crate) fn from_snapshot(s: &Snapshot) -> Result<Self> {
        let layout = *s.layout();
        let shared_mem = s.memory().to_mgr_snapshot_mem()?;
        let scratch_mem = ExclusiveSharedMemory::new(s.layout().get_scratch_size())?;
        let entrypoint = s.entrypoint();
        Ok(Self::new(layout, shared_mem, scratch_mem, entrypoint))
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
            entrypoint: self.entrypoint,
            mapped_rgns: self.mapped_rgns,
            abort_buffer: self.abort_buffer,
            snapshot_count: self.snapshot_count,
            g2h_consumer: None,
            h2g_consumer: None,
            h2g_pool_gva: None,
        };
        let guest_mgr = SandboxMemoryManager {
            shared_mem: gshm,
            scratch_mem: gscratch,
            layout: self.layout,
            entrypoint: self.entrypoint,
            mapped_rgns: self.mapped_rgns,
            abort_buffer: Vec::new(), // Guest doesn't need abort buffer
            snapshot_count: self.snapshot_count,
            g2h_consumer: None,
            h2g_consumer: None,
            h2g_pool_gva: None,
        };
        host_mgr.update_scratch_bookkeeping()?;
        host_mgr.init_g2h_consumer()?;
        host_mgr.init_h2g_consumer()?;
        Ok((host_mgr, guest_mgr))
    }
}

impl SandboxMemoryManager<HostSharedMemory> {
    /// Write a [`FileMappingInfo`] entry into the PEB's preallocated array.
    ///
    /// Reads the current entry count from the PEB, validates that the
    /// array isn't full ([`MAX_FILE_MAPPINGS`]), writes the entry at the
    /// next available slot, and increments the count.
    ///
    /// This is the **only** place that writes to the PEB file mappings
    /// array — both `MultiUseSandbox::map_file_cow` and the evolve loop
    /// call through here so the logic is not duplicated.
    ///
    /// # Errors
    ///
    /// Returns an error if [`MAX_FILE_MAPPINGS`] has been reached.
    ///
    /// [`FileMappingInfo`]: hyperlight_common::mem::FileMappingInfo
    /// [`MAX_FILE_MAPPINGS`]: hyperlight_common::mem::MAX_FILE_MAPPINGS
    #[cfg(feature = "nanvix-unstable")]
    pub(crate) fn write_file_mapping_entry(
        &mut self,
        guest_addr: u64,
        size: u64,
        label: &[u8; hyperlight_common::mem::FILE_MAPPING_LABEL_MAX_LEN + 1],
    ) -> Result<()> {
        use hyperlight_common::mem::{FileMappingInfo, MAX_FILE_MAPPINGS};

        // Read the current entry count from the PEB. This is the source
        // of truth — it survives snapshot/restore because the PEB is
        // part of shared memory that gets snapshotted.
        let current_count =
            self.shared_mem
                .read::<u64>(self.layout.get_file_mappings_size_offset())? as usize;

        if current_count >= MAX_FILE_MAPPINGS {
            return Err(crate::new_error!(
                "file mapping limit reached ({} of {})",
                current_count,
                MAX_FILE_MAPPINGS,
            ));
        }

        // Write the entry into the next available slot.
        let entry_offset = self.layout.get_file_mappings_array_offset()
            + current_count * std::mem::size_of::<FileMappingInfo>();
        let guest_addr_offset = offset_of!(FileMappingInfo, guest_addr);
        let size_offset = offset_of!(FileMappingInfo, size);
        let label_offset = offset_of!(FileMappingInfo, label);
        self.shared_mem
            .write::<u64>(entry_offset + guest_addr_offset, guest_addr)?;
        self.shared_mem
            .write::<u64>(entry_offset + size_offset, size)?;
        self.shared_mem
            .copy_from_slice(label, entry_offset + label_offset)?;

        // Increment the entry count.
        let new_count = (current_count + 1) as u64;
        self.shared_mem
            .write::<u64>(self.layout.get_file_mappings_size_offset(), new_count)?;

        Ok(())
    }

    /// This function restores a memory snapshot from a given snapshot.
    pub(crate) fn restore_snapshot(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<(
        Option<SnapshotSharedMemory<GuestSharedMemory>>,
        Option<GuestSharedMemory>,
    )> {
        let gsnapshot = if *snapshot.memory() == self.shared_mem {
            // If the snapshot memory is already the correct memory,
            // which is readonly, don't bother with restoring it,
            // since its contents must be the same.  Note that in the
            // #[cfg(unshared_snapshot_mem)] case, this condition will
            // never be true, since even immediately after a restore,
            // self.shared_mem is a (writable) copy, not the original
            // shared_mem.
            None
        } else {
            let new_snapshot_mem = snapshot.memory().to_mgr_snapshot_mem()?;
            let (hsnapshot, gsnapshot) = new_snapshot_mem.build();
            self.shared_mem = hsnapshot;
            Some(gsnapshot)
        };
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
        self.layout = *snapshot.layout();
        // Inherit the snapshot's own generation number — the
        // guest-visible counter reflects "which snapshot is the
        // sandbox currently a clone of", not "how many restores have
        // happened into this (possibly-reused) partition".
        self.snapshot_count = snapshot.snapshot_generation();

        self.update_scratch_bookkeeping()?;
        self.init_g2h_consumer()?;
        self.init_h2g_consumer()?;
        self.restore_h2g_prefill()?;
        Ok((gsnapshot, gscratch))
    }

    #[inline]
    fn update_scratch_bookkeeping_item(&mut self, offset: u64, value: u64) -> Result<()> {
        let scratch_size = self.scratch_mem.mem_size();
        let base_offset = scratch_size - offset as usize;
        self.scratch_mem.write::<u64>(base_offset, value)
    }

    fn update_scratch_bookkeeping(&mut self) -> Result<()> {
        use hyperlight_common::layout::*;
        let scratch_size = self.scratch_mem.mem_size();
        self.update_scratch_bookkeeping_item(SCRATCH_TOP_SIZE_OFFSET, scratch_size as u64)?;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_ALLOCATOR_OFFSET,
            self.layout.get_first_free_scratch_gpa(),
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

        // Write virtqueue metadata to scratch-top so the guest can
        // discover ring locations without reading the PEB.
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_G2H_RING_GVA_OFFSET,
            self.layout.get_g2h_ring_gva(),
        )?;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_H2G_RING_GVA_OFFSET,
            self.layout.get_h2g_ring_gva(),
        )?;
        self.scratch_mem.write::<u16>(
            scratch_size - SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET as usize,
            self.layout.sandbox_memory_config.get_g2h_queue_depth() as u16,
        )?;
        self.scratch_mem.write::<u16>(
            scratch_size - SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET as usize,
            self.layout.sandbox_memory_config.get_h2g_queue_depth() as u16,
        )?;
        self.scratch_mem.write::<u16>(
            scratch_size - SCRATCH_TOP_G2H_POOL_PAGES_OFFSET as usize,
            self.layout.sandbox_memory_config.get_g2h_pool_pages() as u16,
        )?;
        self.scratch_mem.write::<u16>(
            scratch_size - SCRATCH_TOP_H2G_POOL_PAGES_OFFSET as usize,
            self.layout.sandbox_memory_config.get_h2g_pool_pages() as u16,
        )?;

        // Copy page tables from `shared_mem` into scratch. PT bytes
        // are appended to the snapshot blob at build time and live
        // just past the end of the guest-visible KVM slot (see
        // `Snapshot::new`). Keeping them outside the KVM slot avoids
        // overlapping with `map_file_cow` regions installed
        // immediately after the snapshot in the guest PA space.
        let snapshot_pt_end = self.shared_mem.mem_size();
        let snapshot_pt_size = self.layout.get_pt_size();
        let snapshot_pt_start = snapshot_pt_end - snapshot_pt_size;
        self.scratch_mem.with_exclusivity(|scratch| {
            #[cfg(not(unshared_snapshot_mem))]
            let bytes = &self.shared_mem.as_slice()[snapshot_pt_start..snapshot_pt_end];
            #[cfg(unshared_snapshot_mem)]
            let bytes = {
                let mut bytes = vec![0u8; snapshot_pt_size];
                self.shared_mem
                    .copy_to_slice(&mut bytes, snapshot_pt_start)?;
                bytes
            };
            #[allow(clippy::needless_borrow)]
            scratch.copy_from_slice(&bytes, self.layout.get_pt_base_scratch_offset())
        })??;

        Ok(())
    }

    /// Build the list of guest memory regions for a crash dump.
    ///
    /// By default, walks the guest page tables to discover
    /// GVA→GPA mappings and translates them to host-backed regions.
    #[cfg(all(feature = "crashdump", not(feature = "i686-guest")))]
    pub(crate) fn get_guest_memory_regions(
        &mut self,
        root_pt: u64,
        mmap_regions: &[MemoryRegion],
    ) -> Result<Vec<CrashDumpRegion>> {
        use crate::sandbox::snapshot::SharedMemoryPageTableBuffer;

        let len = hyperlight_common::layout::MAX_GVA;

        let regions = self.shared_mem.with_contents(|snapshot| {
            self.scratch_mem.with_contents(|scratch| {
                let pt_buf =
                    SharedMemoryPageTableBuffer::new(snapshot, scratch, self.layout, root_pt);

                let mappings: Vec<_> =
                    unsafe { hyperlight_common::vmem::virt_to_phys(&pt_buf, 0, len as u64) }
                        .collect();

                if mappings.is_empty() {
                    return Err(new_error!("No page table mappings found (len {len})",));
                }

                let mut regions: Vec<CrashDumpRegion> = Vec::new();
                for mapping in &mappings {
                    let virt_base = mapping.virt_base as usize;
                    let virt_end = (mapping.virt_base + mapping.len) as usize;

                    if let Some(resolved) = self.layout.resolve_gpa(mapping.phys_base, mmap_regions)
                    {
                        let (flags, region_type) = mapping_kind_to_flags(&mapping.kind);
                        let resolved = resolved.with_memories(snapshot, scratch);
                        let contents = resolved.as_ref();
                        let host_base = contents.as_ptr() as usize;
                        let host_len = (mapping.len as usize).min(contents.len());

                        if try_coalesce_region(&mut regions, virt_base, virt_end, host_base, flags)
                        {
                            continue;
                        }

                        regions.push(CrashDumpRegion {
                            guest_region: virt_base..virt_end,
                            host_region: host_base..host_base + host_len,
                            flags,
                            region_type,
                        });
                    }
                }

                Ok(regions)
            })
        })???;

        Ok(regions)
    }

    /// Build the list of guest memory regions for a crash dump (non-paging).
    ///
    /// Without paging, GVA == GPA (identity mapped), so we return the
    /// snapshot and scratch regions directly at their known addresses
    /// alongside any dynamic mmap regions.
    #[cfg(all(feature = "crashdump", feature = "i686-guest"))]
    pub(crate) fn get_guest_memory_regions(
        &mut self,
        _root_pt: u64,
        mmap_regions: &[MemoryRegion],
    ) -> Result<Vec<CrashDumpRegion>> {
        use crate::mem::memory_region::HostGuestMemoryRegion;

        let snapshot_base = SandboxMemoryLayout::BASE_ADDRESS;
        let snapshot_size = self.shared_mem.mem_size();
        let snapshot_host = self.shared_mem.base_addr();

        let scratch_size = self.scratch_mem.mem_size();
        let scratch_gva = hyperlight_common::layout::scratch_base_gva(scratch_size) as usize;
        let scratch_host = self.scratch_mem.base_addr();

        let mut regions = vec![
            CrashDumpRegion {
                guest_region: snapshot_base..snapshot_base + snapshot_size,
                host_region: snapshot_host..snapshot_host + snapshot_size,
                flags: MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE,
                region_type: MemoryRegionType::Snapshot,
            },
            CrashDumpRegion {
                guest_region: scratch_gva..scratch_gva + scratch_size,
                host_region: scratch_host..scratch_host + scratch_size,
                flags: MemoryRegionFlags::READ
                    | MemoryRegionFlags::WRITE
                    | MemoryRegionFlags::EXECUTE,
                region_type: MemoryRegionType::Scratch,
            },
        ];
        for rgn in mmap_regions {
            regions.push(CrashDumpRegion {
                guest_region: rgn.guest_region.clone(),
                host_region: HostGuestMemoryRegion::to_addr(rgn.host_region.start)
                    ..HostGuestMemoryRegion::to_addr(rgn.host_region.end),
                flags: rgn.flags,
                region_type: rgn.region_type,
            });
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
        &mut self,
        gva: u64,
        len: usize,
        root_pt: u64,
    ) -> Result<Vec<u8>> {
        use hyperlight_common::vmem::PAGE_SIZE;

        use crate::sandbox::snapshot::{SharedMemoryPageTableBuffer, access_gpa};

        self.shared_mem.with_contents(|snap| {
            self.scratch_mem.with_contents(|scratch| {
                let pt_buf = SharedMemoryPageTableBuffer::new(snap, scratch, self.layout, root_pt);

                // Walk page tables to get all mappings that cover the GVA range
                let mappings: Vec<_> = unsafe {
                    hyperlight_common::vmem::virt_to_phys(&pt_buf, gva, len as u64)
                }
                .collect();

                if mappings.is_empty() {
                    return Err(new_error!(
                        "No page table mappings found for GVA {:#x} (len {})",
                        gva,
                        len,
                    ));
                }

                // Resulting vector of bytes to return
                let mut result = Vec::with_capacity(len);
                let mut current_gva = gva;

                for mapping in &mappings {
                    // The page table walker should only return valid mappings
                    // that cover our current read position.
                    if mapping.virt_base > current_gva {
                        return Err(new_error!(
                            "Page table walker returned mapping with virt_base {:#x} > current read position {:#x}",
                            mapping.virt_base,
                            current_gva,
                        ));
                    }

                    // Calculate the offset within this page where to start copying
                    let page_offset = (current_gva - mapping.virt_base) as usize;

                    let bytes_remaining = len - result.len();
                    let available_in_page = PAGE_SIZE - page_offset;
                    let bytes_to_copy = bytes_remaining.min(available_in_page);

                    // Translate the GPA to host memory
                    let gpa = mapping.phys_base + page_offset as u64;
                    let (mem, offset) = access_gpa(snap, scratch, self.layout, gpa)
                        .ok_or_else(|| {
                            new_error!(
                                "Failed to resolve GPA {:#x} to host memory (GVA {:#x})",
                                gpa,
                                gva
                            )
                        })?;

                    let slice = mem
                        .get(offset..offset + bytes_to_copy)
                        .ok_or_else(|| {
                            new_error!(
                                "GPA {:#x} resolved to out-of-bounds host offset {} (need {} bytes)",
                                gpa,
                                offset,
                                bytes_to_copy
                            )
                        })?;

                    result.extend_from_slice(slice);
                    current_gva += bytes_to_copy as u64;
                }

                if result.len() != len {
                    tracing::error!(
                        "Page table walker returned mappings that don't cover the full requested length: got {}, expected {}",
                        result.len(),
                        len,
                    );
                    return Err(new_error!(
                        "Could not read full GVA range: got {} of {} bytes {:?}",
                        result.len(),
                        len,
                        mappings
                    ));
                }

                Ok(result)
            })
        })??
    }

    /// Compute the G2H virtqueue Layout from scratch region addresses.
    pub(crate) fn g2h_virtq_layout(&self) -> Result<virtq::Layout> {
        let base = self.layout.get_g2h_ring_gva();
        let depth = self.layout.sandbox_memory_config.get_g2h_queue_depth() as u16;

        let nz = NonZeroU16::new(depth).ok_or_else(|| new_error!("G2H queue depth is zero"))?;

        unsafe { VirtqLayout::from_base(base, nz) }
            .map_err(|e| new_error!("Invalid G2H virtq layout: {:?}", e))
    }

    /// Compute the H2G virtqueue Layout from scratch region addresses.
    pub(crate) fn h2g_virtq_layout(&self) -> Result<virtq::Layout> {
        let base = self.layout.get_h2g_ring_gva();
        let depth = self.layout.sandbox_memory_config.get_h2g_queue_depth() as u16;

        let nz = NonZeroU16::new(depth).ok_or_else(|| new_error!("H2G queue depth is zero"))?;

        unsafe { VirtqLayout::from_base(base, nz) }
            .map_err(|e| new_error!("Invalid H2G virtq layout: {:?}", e))
    }

    /// Create a [`HostMemOps`] instance backed by this manager's
    /// scratch shared memory.
    pub(crate) fn host_mem_ops(&self) -> HostMemOps {
        let scratch_base_gva =
            hyperlight_common::layout::scratch_base_gva(self.scratch_mem.mem_size());
        HostMemOps::new(&self.scratch_mem, scratch_base_gva)
    }

    /// Initialize the G2H virtqueue consumer.
    /// Must be called after scratch bookkeeping is written.
    pub(crate) fn init_g2h_consumer(&mut self) -> Result<()> {
        match &mut self.g2h_consumer {
            Some(consumer) => {
                consumer.reset();
            }
            None => {
                let layout = self.g2h_virtq_layout()?;
                let mem_ops = self.host_mem_ops();
                let consumer = virtq::VirtqConsumer::new(layout, mem_ops, HostNotifier);
                self.g2h_consumer = Some(consumer);
            }
        }
        Ok(())
    }

    /// Initialize the H2G virtqueue consumer.
    ///
    /// Must be called after scratch bookkeeping is written. Avail suppression is set to Disable
    /// so guest prefill/refill operations do not trigger VM exits.
    pub(crate) fn init_h2g_consumer(&mut self) -> Result<()> {
        match &mut self.h2g_consumer {
            Some(consumer) => {
                consumer.reset();
                consumer
                    .set_avail_suppression(virtq::SuppressionKind::Disable)
                    .map_err(|e| new_error!("H2G avail suppression: {:?}", e))?;
            }
            None => {
                let layout = self.h2g_virtq_layout()?;
                let mem_ops = self.host_mem_ops();
                let mut consumer = virtq::VirtqConsumer::new(layout, mem_ops, HostNotifier);
                consumer
                    .set_avail_suppression(virtq::SuppressionKind::Disable)
                    .map_err(|e| new_error!("H2G avail suppression: {:?}", e))?;
                self.h2g_consumer = Some(consumer);
            }
        }
        Ok(())
    }

    /// Prefill the H2G ring with writable descriptors after snapshot restore.
    ///
    /// Uses a temporary `RingProducer` to write descriptors into the H2G ring
    /// so the host consumer can poll them. The guest's `restore_from_ring`
    /// will later reconstruct its inflight state from these descriptors.
    pub(crate) fn restore_h2g_prefill(&mut self) -> Result<()> {
        let pool_gva = match self.h2g_pool_gva {
            Some(gva) => gva,
            None => return Ok(()),
        };

        let layout = self.h2g_virtq_layout()?;
        let mem_ops = self.host_mem_ops();
        let h2g_depth = self.layout.sandbox_memory_config.get_h2g_queue_depth();

        // Pool size from config
        let slot_size = PAGE_SIZE_USIZE;
        let pool_size = self.layout.sandbox_memory_config.get_h2g_pool_pages() * PAGE_SIZE_USIZE;
        let slot_count = pool_size / slot_size;

        let mut producer = virtq::RingProducer::new(layout, mem_ops);
        let prefill_count = core::cmp::min(slot_count, h2g_depth);

        // Write descriptors in reverse order to match the guest's LIFO
        // allocation pattern (RecyclePool::alloc pops from the end of
        // the free list, so the first prefill gets the highest address).
        for i in (0..prefill_count).rev() {
            let addr = pool_gva + (i * slot_size) as u64;
            producer
                .submit_one(addr, slot_size as u32, true)
                .map_err(|e| new_error!("H2G prefill submit: {:?}", e))?;
        }

        Ok(())
    }

    /// Write a guest function call into the H2G virtqueue.
    ///
    /// Polls the H2G consumer for a prefilled entry from the guest,
    /// writes `VirtqMsgHeader::Request` followed by `buffer` into the
    /// writable completion, and completes the entry.
    pub(crate) fn write_guest_function_call_virtq(&mut self, buffer: &[u8]) -> Result<()> {
        let consumer = self
            .h2g_consumer
            .as_mut()
            .ok_or_else(|| new_error!("H2G consumer not initialized"))?;

        let (entry, completion) = consumer
            .poll(8192)
            .map_err(|e| new_error!("H2G poll: {:?}", e))?
            .ok_or_else(|| new_error!("H2G: no prefilled entry available"))?;

        // Consume the entry data - this should be empty
        drop(entry);

        let header = VirtqMsgHeader::new(MsgKind::Request, 0, buffer.len() as u32);

        let virtq::SendCompletion::Writable(mut wc) = completion else {
            return Err(new_error!(
                "H2G: expected writable completion, got non-writable (ring corruption)"
            ));
        };

        wc.write_all(bytemuck::bytes_of(&header))
            .map_err(|e| new_error!("H2G write header: {:?}", e))?;
        wc.write_all(buffer)
            .map_err(|e| new_error!("H2G write payload: {:?}", e))?;

        consumer
            .complete(wc.into())
            .map_err(|e| new_error!("H2G complete: {:?}", e))?;

        Ok(())
    }

    /// Read the H2G result from G2H after the guest halts.
    ///
    /// The guest submitted the Response on G2H with
    pub(crate) fn read_h2g_result_from_g2h(&mut self) -> Result<FunctionCallResult> {
        let consumer = self
            .g2h_consumer
            .as_mut()
            .ok_or_else(|| new_error!("G2H consumer not initialized"))?;

        // Drain the G2H queue, processing Log entries inline, until we
        // find the Response that carries the H2G function call result.
        loop {
            let maybe_next = consumer
                .poll(8192)
                .map_err(|e| new_error!("G2H poll for H2G result: {:?}", e))?;

            let Some((entry, completion)) = maybe_next else {
                return Err(new_error!("G2H: no H2G result entry after halt"));
            };

            let entry_data = entry.data();
            if entry_data.len() < VirtqMsgHeader::SIZE {
                return Err(new_error!("G2H: result entry too short"));
            }

            let hdr: &VirtqMsgHeader = bytemuck::from_bytes(&entry_data[..VirtqMsgHeader::SIZE]);
            let payload = &entry_data[VirtqMsgHeader::SIZE..];

            match hdr.msg_kind() {
                Ok(MsgKind::Response) => {
                    let fcr = FunctionCallResult::try_from(payload)
                        .map_err(|e| new_error!("G2H: malformed FunctionCallResult: {}", e))?;
                    consumer
                        .complete(completion)
                        .map_err(|e| new_error!("G2H complete: {:?}", e))?;
                    return Ok(fcr);
                }
                Ok(MsgKind::Log) => {
                    crate::sandbox::outb::emit_guest_log(payload);
                    consumer
                        .complete(completion)
                        .map_err(|e| new_error!("G2H complete log: {:?}", e))?;
                }
                Ok(other) => {
                    return Err(new_error!("G2H: expected Response or Log, got {:?}", other));
                }
                Err(unknown) => {
                    return Err(new_error!("G2H: unknown message kind: 0x{:02x}", unknown));
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg(all(not(feature = "i686-guest"), target_arch = "x86_64"))]
mod tests {
    use hyperlight_common::vmem::{MappingKind, PAGE_TABLE_SIZE};
    use hyperlight_testing::sandbox_sizes::{LARGE_HEAP_SIZE, MEDIUM_HEAP_SIZE, SMALL_HEAP_SIZE};
    use hyperlight_testing::simple_guest_as_string;

    use crate::GuestBinary;
    use crate::mem::memory_region::MemoryRegionFlags;
    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox::snapshot::Snapshot;

    /// Verify page tables for a given configuration.
    /// Creates a Snapshot and verifies every page in every region has correct PTEs.
    fn verify_page_tables(name: &str, config: SandboxConfiguration) {
        let path = simple_guest_as_string().expect("failed to get simple guest path");
        let snapshot = Snapshot::from_env(GuestBinary::FilePath(path), config)
            .unwrap_or_else(|e| panic!("{}: failed to create snapshot: {}", name, e));

        let regions = snapshot.regions();

        // Verify NULL page (0x0) is NOT mapped
        assert!(
            unsafe { hyperlight_common::vmem::virt_to_phys(&snapshot, 0, 1) }
                .next()
                .is_none(),
            "{}: NULL page (0x0) should NOT be mapped",
            name
        );

        // Verify every page in every region
        for region in regions {
            let mut addr = region.guest_region.start as u64;

            while addr < region.guest_region.end as u64 {
                let mapping = unsafe { hyperlight_common::vmem::virt_to_phys(&snapshot, addr, 1) }
                    .next()
                    .unwrap_or_else(|| {
                        panic!(
                            "{}: {:?} region: address 0x{:x} is not mapped",
                            name, region.region_type, addr
                        )
                    });

                // Verify identity mapping (phys == virt for low memory)
                assert_eq!(
                    mapping.phys_base, addr,
                    "{}: {:?} region: address 0x{:x} should identity map, got phys 0x{:x}",
                    name, region.region_type, addr, mapping.phys_base
                );

                // Verify kind is Basic
                let MappingKind::Basic(bm) = mapping.kind else {
                    panic!(
                        "{}: {:?} region: address 0x{:x} should be kind basic, got {:?}",
                        name, region.region_type, addr, mapping.kind
                    );
                };

                // Verify writable
                let actual = bm.writable;
                let expected = region.flags.contains(MemoryRegionFlags::WRITE);
                assert_eq!(
                    actual, expected,
                    "{}: {:?} region: address 0x{:x} has writable {}, expected {} (region flags: {:?})",
                    name, region.region_type, addr, actual, expected, region.flags
                );

                // Verify executable
                let actual = bm.executable;
                let expected = region.flags.contains(MemoryRegionFlags::EXECUTE);
                assert_eq!(
                    actual, expected,
                    "{}: {:?} region: address 0x{:x} has executable {}, expected {} (region flags: {:?})",
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
                cfg.set_scratch_size(0x100000);
                cfg
            }),
        ];

        for (name, config) in test_cases {
            verify_page_tables(name, config);
        }
    }
}
