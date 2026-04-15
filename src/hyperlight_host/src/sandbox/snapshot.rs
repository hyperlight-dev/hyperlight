/*
Copyright 2025 The Hyperlight Authors.

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

use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(feature = "i686-guest"))]
use hyperlight_common::layout::scratch_base_gpa;
use hyperlight_common::layout::scratch_base_gva;
#[cfg(not(feature = "i686-guest"))]
use hyperlight_common::vmem::{self, BasicMapping, CowMapping};
use hyperlight_common::vmem::{Mapping, MappingKind, PAGE_SIZE};
use tracing::{Span, instrument};

use crate::HyperlightError::MemoryRegionSizeMismatch;
use crate::Result;
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::mem::exe::LoadInfo;
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::memory_region::MemoryRegion;
#[cfg(not(feature = "i686-guest"))]
use crate::mem::mgr::GuestPageTableBuffer;
use crate::mem::mgr::SnapshotSharedMemory;
use crate::mem::shared_mem::{ReadonlySharedMemory, SharedMemory};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::uninitialized::{GuestBinary, GuestEnvironment};

pub(super) static SANDBOX_CONFIGURATION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Presently, a snapshot can be of a preinitialised sandbox, which
/// still needs an initialise function called in order to determine
/// how to call into it, or of an already-properly-initialised sandbox
/// which can be immediately called into. This keeps track of the
/// difference.
///
/// TODO: this should not necessarily be around in the long term:
/// ideally we would just preinitialise earlier in the snapshot
/// creation process and never need this.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum NextAction {
    /// A sandbox in the preinitialise state still needs to be
    /// initialised by calling the initialise function
    Initialise(u64),
    /// A sandbox in the ready state can immediately be called into,
    /// using the dispatch function pointer.
    Call(u64),
    /// Only when compiling for tests: a sandbox that cannot actually
    /// be used
    #[cfg(test)]
    None,
}

/// A wrapper around a `SharedMemory` reference and a snapshot
/// of the memory therein
pub struct Snapshot {
    /// Unique ID of the sandbox configuration for sandboxes where
    /// this snapshot may be restored.
    sandbox_id: u64,
    /// Layout object for the sandbox. TODO: get rid of this and
    /// replace with something saner and set up from the guest (early
    /// on?).
    ///
    /// Not checked on restore, since any sandbox with the same
    /// configuration id will share the same layout
    layout: crate::mem::layout::SandboxMemoryLayout,
    /// Memory of the sandbox at the time this snapshot was taken
    memory: ReadonlySharedMemory,
    /// The memory regions that were mapped when this snapshot was
    /// taken (excluding initial sandbox regions)
    regions: Vec<MemoryRegion>,
    /// Separate PT storage for i686 snapshots where PTs are stored
    /// outside the main snapshot memory to avoid overlap with map_file_cow.
    #[cfg(feature = "i686-guest")]
    separate_pt_bytes: Vec<u8>,
    /// Extra debug information about the binary in this snapshot,
    /// from when the binary was first loaded into the snapshot.
    ///
    /// This information is provided on a best-effort basis, and there
    /// is a pretty good chance that it does not exist; generally speaking,
    /// things like persisting a snapshot and reloading it are likely
    /// to destroy this information.
    load_info: LoadInfo,
    /// The hash of the other portions of the snapshot. Morally, this
    /// is just a memoization cache for [`hash`], below, but it is not
    /// a [`std::sync::OnceLock`] because it may be persisted to disk
    /// without being recomputed on load.
    ///
    /// It is not a [`blake3::Hash`] because we do not presently
    /// require constant-time equality checking
    hash: [u8; 32],
    /// The address of the top of the guest stack
    stack_top_gva: u64,

    /// Special register state captured from the vCPU during snapshot.
    /// None for snapshots created directly from a binary (before
    /// guest runs).  Some for snapshots taken from a running sandbox.
    /// Note: CR3 in this struct is NOT used on restore, since page
    /// tables are relocated during snapshot.
    sregs: Option<CommonSpecialRegisters>,

    /// The next action that should be performed on this snapshot
    entrypoint: NextAction,
}
impl core::convert::AsRef<Snapshot> for Snapshot {
    fn as_ref(&self) -> &Self {
        self
    }
}
impl hyperlight_common::vmem::TableReadOps for Snapshot {
    type TableAddr = u64;
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }
    unsafe fn read_entry(&self, addr: u64) -> u64 {
        let addr = addr as usize;
        let Some(pte_bytes) = self.memory.as_slice().get(addr..addr + 8) else {
            // Attacker-controlled data pointed out-of-bounds. We'll
            // default to returning 0 in this case, which, for most
            // architectures (including x86-64 and arm64, the ones we
            // care about presently) will be a not-present entry.
            return 0;
        };
        // this is statically the correct size, so using unwrap() here
        // doesn't make this any more panic-y.
        #[allow(clippy::unwrap_used)]
        let n: [u8; 8] = pte_bytes.try_into().unwrap();
        u64::from_ne_bytes(n)
    }
    fn to_phys(addr: u64) -> u64 {
        addr
    }
    fn from_phys(addr: u64) -> u64 {
        addr
    }
    fn root_table(&self) -> u64 {
        self.root_pt_gpa()
    }
}

/// Compute a deterministic hash of a snapshot.
///
/// This does not include the load info from the snapshot, because
/// that is only used for debugging builds.
fn hash(memory: &[u8], regions: &[MemoryRegion]) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(memory);
    for rgn in regions {
        hasher.update(&usize::to_le_bytes(rgn.guest_region.start));
        let guest_len = rgn.guest_region.end - rgn.guest_region.start;
        #[allow(clippy::useless_conversion)]
        let host_start_addr: usize = rgn.host_region.start.into();
        #[allow(clippy::useless_conversion)]
        let host_end_addr: usize = rgn.host_region.end.into();
        hasher.update(&usize::to_le_bytes(host_start_addr));
        let host_len = host_end_addr - host_start_addr;
        if guest_len != host_len {
            return Err(MemoryRegionSizeMismatch(
                host_len,
                guest_len,
                format!("{:?}", rgn),
            ));
        }
        // Ignore [`MemoryRegion::region_type`], since it is extra
        // information for debugging rather than a core part of the
        // identity of the snapshot/workload.
        hasher.update(&usize::to_le_bytes(guest_len));
        hasher.update(&u32::to_le_bytes(rgn.flags.bits()));
    }
    // Ignore [`load_info`], since it is extra information for
    // debugging rather than a core part of the identity of the
    // snapshot/workload.
    Ok(hasher.finalize().into())
}

pub(crate) fn access_gpa<'a>(
    snap: &'a [u8],
    scratch: &'a [u8],
    layout: SandboxMemoryLayout,
    gpa: u64,
) -> Option<(&'a [u8], usize)> {
    let resolved = layout.resolve_gpa(gpa, &[])?.with_memories(snap, scratch);
    Some((resolved.base.as_ref(), resolved.offset))
}

pub(crate) struct SharedMemoryPageTableBuffer<'a> {
    snap: &'a [u8],
    scratch: &'a [u8],
    layout: SandboxMemoryLayout,
    root: u64,
    /// CoW resolution map: maps snapshot GPAs to their CoW'd scratch GPAs.
    /// Built by walking the kernel PD to find pages that were CoW'd during boot.
    #[cfg(feature = "i686-guest")]
    cow_map: Option<&'a std::collections::HashMap<u64, u64>>,
}

impl<'a> SharedMemoryPageTableBuffer<'a> {
    pub(crate) fn new(
        snap: &'a [u8],
        scratch: &'a [u8],
        layout: SandboxMemoryLayout,
        root: u64,
    ) -> Self {
        Self {
            snap,
            scratch,
            layout,
            root,
            #[cfg(feature = "i686-guest")]
            cow_map: None,
        }
    }

    #[cfg(feature = "i686-guest")]
    fn with_cow_map(mut self, cow_map: &'a std::collections::HashMap<u64, u64>) -> Self {
        self.cow_map = Some(cow_map);
        self
    }
}
impl<'a> hyperlight_common::vmem::TableReadOps for SharedMemoryPageTableBuffer<'a> {
    type TableAddr = u64;
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }
    unsafe fn read_entry(&self, addr: u64) -> u64 {
        // For i686: if the GPA was CoW'd, read from the scratch copy instead.
        #[cfg(feature = "i686-guest")]
        let addr = {
            let page_gpa = addr & 0xFFFFF000;
            if let Some(map) = self.cow_map {
                if let Some(&scratch_gpa) = map.get(&page_gpa) {
                    scratch_gpa + (addr & 0xFFF)
                } else {
                    addr
                }
            } else {
                addr
            }
        };
        let memoff = access_gpa(self.snap, self.scratch, self.layout, addr);
        // For i686 guests, page table entries are 4 bytes; for x86_64 they
        // are 8 bytes. Read the correct size based on the feature flag.
        #[cfg(feature = "i686-guest")]
        {
            let Some(pte_bytes) = memoff.and_then(|(mem, off)| mem.get(off..off + 4)) else {
                // Out-of-bounds: return 0, which is a not-present entry.
                return 0;
            };
            #[allow(clippy::unwrap_used)]
            let n: [u8; 4] = pte_bytes.try_into().unwrap();
            u32::from_ne_bytes(n) as u64
        }
        #[cfg(not(feature = "i686-guest"))]
        {
            let Some(pte_bytes) = memoff.and_then(|(mem, off)| mem.get(off..off + 8)) else {
                // Attacker-controlled data pointed out-of-bounds. We'll
                // default to returning 0 in this case, which, for most
                // architectures (including x86-64 and arm64, the ones we
                // care about presently) will be a not-present entry.
                return 0;
            };
            // this is statically the correct size, so using unwrap() here
            // doesn't make this any more panic-y.
            #[allow(clippy::unwrap_used)]
            let n: [u8; 8] = pte_bytes.try_into().unwrap();
            u64::from_ne_bytes(n)
        }
    }
    fn to_phys(addr: u64) -> u64 {
        addr
    }
    fn from_phys(addr: u64) -> u64 {
        addr
    }
    fn root_table(&self) -> u64 {
        self.root
    }
}
impl<'a> core::convert::AsRef<SharedMemoryPageTableBuffer<'a>> for SharedMemoryPageTableBuffer<'a> {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// Build a CoW resolution map by walking a kernel PD.
/// For each PTE that maps a VA in [0, MEMORY_SIZE) to a PA in scratch,
/// record: original_gpa -> scratch_gpa.
#[cfg(feature = "i686-guest")]
fn build_cow_map(
    snap: &[u8],
    scratch: &[u8],
    layout: SandboxMemoryLayout,
    kernel_root: u64,
) -> std::collections::HashMap<u64, u64> {
    use hyperlight_common::layout::scratch_base_gpa;
    let mut cow_map = std::collections::HashMap::new();
    let scratch_base = scratch_base_gpa(layout.get_scratch_size());
    let scratch_end = scratch_base + layout.get_scratch_size() as u64;
    let mem_size = layout.get_memory_size().unwrap_or(0) as u64;

    for pdi in 0..1024u64 {
        let pde_addr = kernel_root + pdi * 4;
        let pde = access_gpa(snap, scratch, layout, pde_addr)
            .and_then(|(mem, off)| mem.get(off..off + 4))
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0);
        if (pde & 1) == 0 {
            continue;
        }
        let pt_gpa = (pde & 0xFFFFF000) as u64;
        for pti in 0..1024u64 {
            let pte_addr = pt_gpa + pti * 4;
            let pte = access_gpa(snap, scratch, layout, pte_addr)
                .and_then(|(mem, off)| mem.get(off..off + 4))
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0);
            if (pte & 1) == 0 {
                continue;
            }
            let frame_gpa = (pte & 0xFFFFF000) as u64;
            let va = (pdi << 22) | (pti << 12);
            if va < mem_size && frame_gpa >= scratch_base && frame_gpa < scratch_end {
                cow_map.insert(va, frame_gpa);
            }
        }
    }
    cow_map
}

/// Helper for building i686 2-level page tables as a flat byte buffer.
///
/// The buffer stores one or more page directories (PDs) at the front,
/// followed by page tables (PTs) that are allocated on demand. All
/// entries use 4-byte i686 PTEs.
#[cfg(feature = "i686-guest")]
mod i686_pt {
    use hyperlight_common::vmem::i686_guest::{PAGE_ACCESSED, PAGE_AVL_COW, PAGE_PRESENT, PAGE_RW};

    const PTE_PRESENT: u32 = PAGE_PRESENT as u32;
    const PTE_RW: u32 = PAGE_RW as u32;
    const PTE_ACCESSED: u32 = PAGE_ACCESSED as u32;
    pub(super) const PTE_COW: u32 = PAGE_AVL_COW as u32;
    pub(super) const ADDR_MASK: u32 = 0xFFFFF000;
    pub(super) const RW_FLAGS: u32 = PTE_PRESENT | PTE_RW | PTE_ACCESSED;
    const PAGE_SIZE: usize = 4096;

    pub(super) struct Builder {
        pub bytes: Vec<u8>,
        pd_base_gpa: usize,
    }

    impl Builder {
        pub fn new(pd_base_gpa: usize) -> Self {
            Self {
                bytes: vec![0u8; PAGE_SIZE],
                pd_base_gpa,
            }
        }

        pub fn with_pds(pd_base_gpa: usize, num_pds: usize) -> Self {
            Self {
                bytes: vec![0u8; num_pds * PAGE_SIZE],
                pd_base_gpa,
            }
        }

        pub fn read_u32(&self, offset: usize) -> u32 {
            let b = &self.bytes[offset..offset + 4];
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }

        fn write_u32(&mut self, offset: usize, val: u32) {
            self.bytes[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        }

        /// Ensures a page table exists for PDE index `pdi` within the PD
        /// at byte offset `pd_offset`. Allocates a new PT page at the end
        /// of the buffer if absent. Returns the byte offset of the PT.
        pub fn ensure_pt(&mut self, pd_offset: usize, pdi: usize, pde_flags: u32) -> usize {
            let pde_off = pd_offset + pdi * 4;
            let pde = self.read_u32(pde_off);
            if (pde & PTE_PRESENT) != 0 {
                (pde & ADDR_MASK) as usize - self.pd_base_gpa
            } else {
                let pt_offset = self.bytes.len();
                self.bytes.resize(pt_offset + PAGE_SIZE, 0);
                let pt_gpa = (self.pd_base_gpa + pt_offset) as u32;
                self.write_u32(pde_off, pt_gpa | pde_flags);
                pt_offset
            }
        }

        /// Maps a single 4K page within the PD at `pd_offset`.
        pub fn map_page(&mut self, pd_offset: usize, va: u64, pa: u64, pte_flags: u32) {
            let pdi = ((va as u32 >> 22) & 0x3FF) as usize;
            let pti = ((va as u32 >> 12) & 0x3FF) as usize;
            let pt_offset = self.ensure_pt(pd_offset, pdi, RW_FLAGS);
            let pte_off = pt_offset + pti * 4;
            self.write_u32(pte_off, (pa as u32) | pte_flags);
        }

        /// Maps a contiguous range of pages with uniform flags.
        pub fn map_range(
            &mut self,
            pd_offset: usize,
            va_start: u64,
            pa_start: u64,
            len: u64,
            pte_flags: u32,
        ) {
            let mut va = va_start;
            let mut pa = pa_start;
            let end = va_start + len;
            while va < end {
                self.map_page(pd_offset, va, pa, pte_flags);
                va += PAGE_SIZE as u64;
                pa += PAGE_SIZE as u64;
            }
        }

        pub fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }
    }
}

/// Build initial i686 page tables for a freshly loaded guest binary.
/// Maps snapshot regions (with CoW flags for writable pages) and the scratch region.
#[cfg(feature = "i686-guest")]
fn build_initial_i686_page_tables(
    layout: &crate::mem::layout::SandboxMemoryLayout,
) -> crate::Result<Vec<u8>> {
    use i686_pt::{PTE_COW, RW_FLAGS};

    use crate::mem::memory_region::{GuestMemoryRegion, MemoryRegionFlags};

    let pd_base_gpa = layout.get_pt_base_gpa() as usize;
    let mut pt = i686_pt::Builder::new(pd_base_gpa);

    let ro_flags = hyperlight_common::vmem::i686_guest::PAGE_PRESENT as u32
        | hyperlight_common::vmem::i686_guest::PAGE_ACCESSED as u32;

    // 1. Map snapshot memory regions
    for rgn in layout.get_memory_regions_::<GuestMemoryRegion>(())?.iter() {
        let flags = if rgn.flags.contains(MemoryRegionFlags::WRITE) {
            ro_flags | PTE_COW
        } else {
            ro_flags
        };
        pt.map_range(
            0,
            rgn.guest_region.start as u64,
            rgn.guest_region.start as u64,
            rgn.guest_region.len() as u64,
            flags,
        );
    }

    // 2. Map scratch region (writable, not CoW)
    let scratch_size = layout.get_scratch_size();
    let scratch_gpa = hyperlight_common::layout::scratch_base_gpa(scratch_size);
    let scratch_gva = hyperlight_common::layout::scratch_base_gva(scratch_size);
    pt.map_range(0, scratch_gva, scratch_gpa, scratch_size as u64, RW_FLAGS);

    Ok(pt.into_bytes())
}

/// Compact an i686 snapshot: densely pack live pages and rebuild
/// per-process page tables with updated GPAs.
///
/// Returns `(snapshot_memory, pt_bytes)`.
#[cfg(feature = "i686-guest")]
fn compact_i686_snapshot(
    snap: &[u8],
    scratch: &[u8],
    layout: SandboxMemoryLayout,
    live_pages: Vec<(Mapping, &[u8])>,
    root_pt_gpas: &[u64],
    cow_map: &std::collections::HashMap<u64, u64>,
    phys_seen: &mut std::collections::HashMap<u64, usize>,
) -> crate::Result<(Vec<u8>, Vec<u8>)> {
    use hyperlight_common::vmem::i686_guest::{PAGE_PRESENT, PAGE_USER};
    use i686_pt::{ADDR_MASK, PTE_COW, RW_FLAGS};

    let page_size: usize = 4096;

    // Phase 1: pack live pages densely into a new snapshot buffer.
    let mut snapshot_memory: Vec<u8> = Vec::new();
    for (mapping, contents) in live_pages {
        if matches!(mapping.kind, MappingKind::Unmapped) {
            continue;
        }
        phys_seen.entry(mapping.phys_base).or_insert_with(|| {
            let new_offset = snapshot_memory.len();
            snapshot_memory.extend(contents);
            new_offset + SandboxMemoryLayout::BASE_ADDRESS
        });
    }

    // Phase 2: build per-process page tables with compacted GPAs.
    let pd_base_gpa = layout.get_pt_base_gpa() as usize;
    let n_roots = root_pt_gpas.len().max(1);
    let mut pt = i686_pt::Builder::with_pds(pd_base_gpa, n_roots);

    let scratch_size = layout.get_scratch_size();
    let scratch_gpa = hyperlight_common::layout::scratch_base_gpa(scratch_size);

    // Helper: read a u32 from guest memory, resolving CoW redirections.
    let read_u32 = |gpa: u64| -> u32 {
        let resolved = {
            let page = gpa & 0xFFFFF000;
            cow_map
                .get(&page)
                .map_or(gpa, |&scratch| scratch + (gpa & 0xFFF))
        };
        access_gpa(snap, scratch, layout, resolved)
            .and_then(|(mem, off)| mem.get(off..off + 4))
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0)
    };

    // Rebuild a single page table with remapped frame GPAs.
    let rebuild_pt = |pt: &mut i686_pt::Builder,
                      old_pt_gpa: u64,
                      extra_flags: u32,
                      phys_map: &std::collections::HashMap<u64, usize>|
     -> u32 {
        let new_pt_offset = pt.bytes.len();
        pt.bytes.resize(new_pt_offset + page_size, 0);
        let new_pt_gpa = (pd_base_gpa + new_pt_offset) as u32;
        for pti in 0..1024usize {
            let pte = read_u32(old_pt_gpa + pti as u64 * 4);
            if (pte & PAGE_PRESENT as u32) == 0 {
                continue;
            }
            let old_frame = (pte & ADDR_MASK) as u64;
            let Some(&new_gpa) = phys_map.get(&old_frame) else {
                continue;
            };
            let mut flags = (pte & 0xFFF) | extra_flags;
            // Mark writable or already-CoW pages as CoW (read-only + AVL bit).
            if (flags & RW_FLAGS & !PTE_COW) != 0 || (flags & PTE_COW) != 0 {
                flags = (flags & !(hyperlight_common::vmem::i686_guest::PAGE_RW as u32)) | PTE_COW;
            }
            let off = new_pt_offset + pti * 4;
            pt.bytes[off..off + 4].copy_from_slice(&((new_gpa as u32) | flags).to_le_bytes());
        }
        new_pt_gpa
    };

    // Resolve a VA through a PD to its physical frame.
    let resolve_through_pd = |pd_gpa: u64, va: u64| -> u64 {
        let pdi = (va >> 22) & 0x3FF;
        let pde = read_u32(pd_gpa + pdi * 4);
        if (pde & PAGE_PRESENT as u32) == 0 {
            return va;
        }
        let pti = (va >> 12) & 0x3FF;
        let pte = read_u32((pde & ADDR_MASK) as u64 + pti * 4);
        if (pte & PAGE_PRESENT as u32) == 0 {
            return va;
        }
        (pte & ADDR_MASK) as u64
    };

    // Build kernel page tables (lower 256 PD entries) from the first root.
    let first_root = root_pt_gpas.first().copied().ok_or_else(|| {
        crate::new_error!("compact_i686_snapshot called with no page directory roots")
    })?;
    let mut kernel_pdes = [0u32; 256];
    for (pdi, kernel_pde) in kernel_pdes.iter_mut().enumerate() {
        let pde = read_u32(first_root + pdi as u64 * 4);
        if (pde & PAGE_PRESENT as u32) == 0 {
            continue;
        }
        let new_pt_gpa = rebuild_pt(&mut pt, (pde & ADDR_MASK) as u64, 0, phys_seen);
        *kernel_pde = (pde & 0xFFF) | new_pt_gpa;
    }

    // Fill in per-process PDs: kernel half (shared) + user half (per-process).
    for (root_idx, &root) in root_pt_gpas.iter().enumerate() {
        let pd_offset = root_idx * page_size;
        // Copy kernel PDEs (lower 256 entries) into this PD.
        for (pdi, &kpde) in kernel_pdes.iter().enumerate() {
            if kpde != 0 {
                pt.bytes[pd_offset + pdi * 4..pd_offset + pdi * 4 + 4]
                    .copy_from_slice(&kpde.to_le_bytes());
            }
        }
        // Rebuild user PDEs (upper 256 entries).
        for pdi in 256..1024usize {
            let pde = read_u32(root + pdi as u64 * 4);
            if (pde & PAGE_PRESENT as u32) == 0 {
                continue;
            }
            let user = PAGE_USER as u32;
            let pt_gpa_raw = (pde & ADDR_MASK) as u64;
            let pt_gpa = resolve_through_pd(first_root, pt_gpa_raw);
            let new_pt_gpa = rebuild_pt(&mut pt, pt_gpa, user, phys_seen);
            let fixed_pde = (pde & 0xFFF) | new_pt_gpa | user;
            pt.bytes[pd_offset + pdi * 4..pd_offset + pdi * 4 + 4]
                .copy_from_slice(&fixed_pde.to_le_bytes());
        }
    }

    // Map scratch and snapshot identity regions into every PD.
    for ri in 0..n_roots {
        let pd_off = ri * page_size;
        pt.map_range(
            pd_off,
            scratch_gpa,
            scratch_gpa,
            scratch_size as u64,
            RW_FLAGS,
        );

        let snapshot_end = SandboxMemoryLayout::BASE_ADDRESS + snapshot_memory.len();
        let snapshot_pages = (snapshot_end - SandboxMemoryLayout::BASE_ADDRESS) / page_size;
        for pi in 0..snapshot_pages {
            let gpa = (SandboxMemoryLayout::BASE_ADDRESS + pi * page_size) as u64;
            let pdi = ((gpa >> 22) & 0x3FF) as usize;
            let pti = ((gpa >> 12) & 0x3FF) as usize;
            let pt_off = pt.ensure_pt(pd_off, pdi, RW_FLAGS);
            let pte_off = pt_off + pti * 4;
            if pt.read_u32(pte_off) & PAGE_PRESENT as u32 == 0 {
                pt.bytes[pte_off..pte_off + 4]
                    .copy_from_slice(&((gpa as u32) | RW_FLAGS).to_le_bytes());
            }
        }
    }

    Ok((snapshot_memory, pt.into_bytes()))
}

fn filtered_mappings<'a>(
    snap: &'a [u8],
    scratch: &'a [u8],
    regions: &[MemoryRegion],
    layout: SandboxMemoryLayout,
    root_pts: &[u64],
    #[cfg(feature = "i686-guest")] cow_map: &std::collections::HashMap<u64, u64>,
) -> Vec<(Mapping, &'a [u8])> {
    #[cfg(not(feature = "i686-guest"))]
    let mappings_iter: Vec<Mapping> = {
        let Some(&root_pt) = root_pts.first() else {
            return Vec::new();
        };
        let op = SharedMemoryPageTableBuffer::new(snap, scratch, layout, root_pt);
        unsafe {
            hyperlight_common::vmem::virt_to_phys(&op, 0, hyperlight_common::layout::MAX_GVA as u64)
        }
        .collect()
    };

    #[cfg(feature = "i686-guest")]
    let mappings_iter: Vec<Mapping> = {
        use std::collections::HashSet;
        let mut mappings = Vec::new();
        let mut seen_phys = HashSet::new();

        let scratch_base_gva_val =
            hyperlight_common::layout::scratch_base_gva(layout.get_scratch_size());
        for &root_pt in root_pts {
            let op = SharedMemoryPageTableBuffer::new(snap, scratch, layout, root_pt)
                .with_cow_map(cow_map);
            let root_mappings =
                unsafe { hyperlight_common::vmem::i686_guest::virt_to_phys_all(&op) };
            for m in root_mappings {
                // Skip mappings whose VA is in the scratch region - these
                // are identity-mapped helpers and would poison seen_phys for
                // legitimate user mappings that share the same scratch PAs.
                if m.virt_base >= scratch_base_gva_val {
                    continue;
                }
                if seen_phys.insert(m.phys_base) {
                    mappings.push(m);
                }
            }
        }
        mappings
    };

    mappings_iter
        .into_iter()
        .filter_map(move |mapping| {
            // the scratch map doesn't count
            if mapping.virt_base >= scratch_base_gva(layout.get_scratch_size()) {
                return None;
            }
            // neither does the mapping of the snapshot's own page tables
            #[cfg(not(feature = "i686-guest"))]
            if mapping.virt_base >= hyperlight_common::layout::SNAPSHOT_PT_GVA_MIN as u64
                && mapping.virt_base <= hyperlight_common::layout::SNAPSHOT_PT_GVA_MAX as u64
            {
                return None;
            }
            let contents =
                unsafe { guest_page(snap, scratch, regions, layout, mapping.phys_base) }?;
            Some((mapping, contents))
        })
        .collect()
}

/// Find the contents of the page which starts at gpa in guest physical
/// memory, taking into account excess host->guest regions
///
/// # Safety
/// The host side of the regions identified by MemoryRegion must be
/// alive and must not be mutated by any other thread: references to
/// these regions may be created and live for `'a`.
unsafe fn guest_page<'a>(
    snap: &'a [u8],
    scratch: &'a [u8],
    regions: &[MemoryRegion],
    layout: SandboxMemoryLayout,
    gpa: u64,
) -> Option<&'a [u8]> {
    let resolved = layout
        .resolve_gpa(gpa, regions)?
        .with_memories(snap, scratch);
    if resolved.as_ref().len() < PAGE_SIZE {
        return None;
    }
    Some(&resolved.as_ref()[..PAGE_SIZE])
}

#[cfg(not(feature = "i686-guest"))]
fn map_specials(pt_buf: &GuestPageTableBuffer, scratch_size: usize) {
    // Map the scratch region
    let mapping = Mapping {
        phys_base: scratch_base_gpa(scratch_size),
        virt_base: scratch_base_gva(scratch_size),
        len: scratch_size as u64,
        kind: MappingKind::Basic(BasicMapping {
            readable: true,
            writable: true,
            // assume that the guest will map these pages elsewhere if
            // it actually needs to execute from them
            executable: false,
        }),
    };
    unsafe { vmem::map(pt_buf, mapping) };
}

impl Snapshot {
    /// Create a new snapshot from the guest binary identified by `env`. With the configuration
    /// specified in `cfg`.
    pub(crate) fn from_env<'a, 'b>(
        env: impl Into<GuestEnvironment<'a, 'b>>,
        cfg: SandboxConfiguration,
    ) -> Result<Self> {
        let env = env.into();
        let mut bin = env.guest_binary;
        bin.canonicalize()?;
        let blob = env.init_data;

        use crate::mem::exe::ExeInfo;
        let exe_info = match bin {
            GuestBinary::FilePath(bin_path_str) => ExeInfo::from_file(&bin_path_str)?,
            GuestBinary::Buffer(buffer) => ExeInfo::from_buf(buffer)?,
        };

        // Check guest/host version compatibility.
        let host_version = env!("CARGO_PKG_VERSION");
        if let Some(v) = exe_info.guest_bin_version()
            && v != host_version
        {
            return Err(crate::HyperlightError::GuestBinVersionMismatch {
                guest_bin_version: v.to_string(),
                host_version: host_version.to_string(),
            });
        }

        let guest_blob_size = blob.as_ref().map(|b| b.data.len()).unwrap_or(0);
        let guest_blob_mem_flags = blob.as_ref().map(|b| b.permissions);

        #[cfg_attr(feature = "i686-guest", allow(unused_mut))]
        let mut layout = crate::mem::layout::SandboxMemoryLayout::new(
            cfg,
            exe_info.loaded_size(),
            guest_blob_size,
            guest_blob_mem_flags,
        )?;

        let load_addr = layout.get_guest_code_address() as u64;
        let base_va = exe_info.base_va();
        let entrypoint_va: u64 = exe_info.entrypoint().into();

        let mut memory = vec![0; layout.get_memory_size()?];

        let load_info = exe_info.load(
            load_addr.try_into()?,
            &mut memory[layout.get_guest_code_offset()..],
        )?;

        layout.write_peb(&mut memory)?;

        blob.map(|x| layout.write_init_data(&mut memory, x.data))
            .transpose()?;

        #[cfg(not(feature = "i686-guest"))]
        {
            // Set up page table entries for the snapshot
            let pt_buf = GuestPageTableBuffer::new(layout.get_pt_base_gpa() as usize);

            use crate::mem::memory_region::{GuestMemoryRegion, MemoryRegionFlags};

            // 1. Map the (ideally readonly) pages of snapshot data
            for rgn in layout.get_memory_regions_::<GuestMemoryRegion>(())?.iter() {
                let readable = rgn.flags.contains(MemoryRegionFlags::READ);
                let executable = rgn.flags.contains(MemoryRegionFlags::EXECUTE);
                let writable = rgn.flags.contains(MemoryRegionFlags::WRITE);
                let kind = if writable {
                    MappingKind::Cow(CowMapping {
                        readable,
                        executable,
                    })
                } else {
                    MappingKind::Basic(BasicMapping {
                        readable,
                        writable: false,
                        executable,
                    })
                };
                let mapping = Mapping {
                    phys_base: rgn.guest_region.start as u64,
                    virt_base: rgn.guest_region.start as u64,
                    len: rgn.guest_region.len() as u64,
                    kind,
                };
                unsafe { vmem::map(&pt_buf, mapping) };
            }

            // 2. Map the special mappings
            map_specials(&pt_buf, layout.get_scratch_size());

            let pt_bytes = pt_buf.into_bytes();
            layout.set_pt_size(pt_bytes.len())?;
            memory.extend(&pt_bytes);
        };
        #[cfg(feature = "i686-guest")]
        {
            let pt_bytes = build_initial_i686_page_tables(&layout)?;
            layout.set_pt_size(pt_bytes.len())?;
            memory.extend(&pt_bytes);
        };

        let exn_stack_top_gva = hyperlight_common::layout::MAX_GVA as u64
            - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
            + 1;

        let extra_regions = Vec::new();
        let hash = hash(&memory, &extra_regions)?;

        Ok(Self {
            sandbox_id: SANDBOX_CONFIGURATION_COUNTER.fetch_add(1, Ordering::Relaxed),
            memory: ReadonlySharedMemory::from_bytes(&memory)?,
            layout,
            regions: extra_regions,
            load_info,
            hash,
            stack_top_gva: exn_stack_top_gva,
            sregs: None,
            #[cfg(feature = "i686-guest")]
            separate_pt_bytes: Vec::new(),
            entrypoint: NextAction::Initialise(load_addr + entrypoint_va - base_va),
        })
    }

    // It might be nice to consider moving at least stack_top_gva into
    // layout, and sharing (via RwLock or similar) the layout between
    // the (host-side) mem mgr (where it can be passed in here) and
    // the sandbox vm itself (which modifies it as it receives
    // requests from the sandbox).
    #[allow(clippy::too_many_arguments)]
    /// Take a snapshot of the memory in `shared_mem`, then create a new
    /// instance of `Self` with the snapshot stored therein.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new<S: SharedMemory>(
        shared_mem: &mut SnapshotSharedMemory<S>,
        scratch_mem: &mut S,
        sandbox_id: u64,
        mut layout: SandboxMemoryLayout,
        load_info: LoadInfo,
        regions: Vec<MemoryRegion>,
        root_pt_gpas: &[u64],
        stack_top_gva: u64,
        sregs: CommonSpecialRegisters,
        entrypoint: NextAction,
    ) -> Result<Self> {
        use std::collections::HashMap;
        let mut phys_seen = HashMap::<u64, usize>::new();
        let memory = shared_mem.with_contents(|snap_c| {
            scratch_mem.with_contents(|scratch_c| {
                // Build CoW resolution map (i686 only): maps original GPAs
                // to their CoW'd scratch GPAs so the PT walker can read the
                // actual page table data instead of stale snapshot copies.
                #[cfg(feature = "i686-guest")]
                let cow_map = {
                    let kernel_root = root_pt_gpas.first().copied().ok_or_else(|| {
                        crate::new_error!("snapshot requires at least one page directory root")
                    })?;
                    build_cow_map(snap_c, scratch_c, layout, kernel_root)
                };

                // Pass 1: collect live pages
                let live_pages = filtered_mappings(
                    snap_c,
                    scratch_c,
                    &regions,
                    layout,
                    root_pt_gpas,
                    #[cfg(feature = "i686-guest")]
                    &cow_map,
                );

                // Pass 2: copy live pages and build new page tables
                // TODO: Look for opportunities to hugepage map
                #[cfg(not(feature = "i686-guest"))]
                let (snapshot_memory, pt_bytes) = {
                    let mut snapshot_memory: Vec<u8> = Vec::new();
                    let pt_buf = GuestPageTableBuffer::new(layout.get_pt_base_gpa() as usize);
                    for (mapping, contents) in live_pages {
                        let kind = match mapping.kind {
                            MappingKind::Cow(cm) => MappingKind::Cow(cm),
                            MappingKind::Basic(bm) if bm.writable => MappingKind::Cow(CowMapping {
                                readable: bm.readable,
                                executable: bm.executable,
                            }),
                            MappingKind::Basic(bm) => MappingKind::Basic(BasicMapping {
                                readable: bm.readable,
                                writable: false,
                                executable: bm.executable,
                            }),
                            MappingKind::Unmapped => continue,
                        };
                        let new_gpa = phys_seen.entry(mapping.phys_base).or_insert_with(|| {
                            let new_offset = snapshot_memory.len();
                            snapshot_memory.extend(contents);
                            new_offset + SandboxMemoryLayout::BASE_ADDRESS
                        });
                        let mapping = Mapping {
                            phys_base: *new_gpa as u64,
                            virt_base: mapping.virt_base,
                            len: PAGE_SIZE as u64,
                            kind,
                        };
                        unsafe { vmem::map(&pt_buf, mapping) };
                    }
                    map_specials(&pt_buf, layout.get_scratch_size());
                    let pt_data = pt_buf.into_bytes();
                    layout.set_pt_size(pt_data.len())?;
                    snapshot_memory.extend(&pt_data);
                    (snapshot_memory, Vec::new())
                };

                #[cfg(feature = "i686-guest")]
                let (snapshot_memory, pt_bytes) = {
                    let (mem, pt) = compact_i686_snapshot(
                        snap_c,
                        scratch_c,
                        layout,
                        live_pages,
                        root_pt_gpas,
                        &cow_map,
                        &mut phys_seen,
                    )?;
                    layout.set_pt_size(pt.len())?;
                    (mem, pt)
                };

                Ok::<(Vec<u8>, Vec<u8>), crate::HyperlightError>((snapshot_memory, pt_bytes))
            })
        })???;
        let (memory, separate_pt_bytes) = memory;
        layout.set_snapshot_size(memory.len());

        // For i686, keep the regions so the RAMFS and other map_file_cow
        // mappings are accessible after restore. For x86_64, we do not
        // need the original regions anymore, as any uses of them in the
        // guest have been incorporated into the snapshot properly.
        #[cfg(feature = "i686-guest")]
        let regions = regions;
        #[cfg(not(feature = "i686-guest"))]
        let regions = Vec::new();

        let hash = hash(&memory, &regions)?;
        Ok(Self {
            sandbox_id,
            layout,
            memory: ReadonlySharedMemory::from_bytes(&memory)?,
            regions,
            load_info,
            hash,
            stack_top_gva,
            sregs: Some(sregs),
            #[cfg(feature = "i686-guest")]
            separate_pt_bytes,
            entrypoint,
        })
    }

    /// The id of the sandbox this snapshot was taken from.
    pub(crate) fn sandbox_id(&self) -> u64 {
        self.sandbox_id
    }

    /// Get the mapped regions from this snapshot
    pub(crate) fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Return the main memory contents of the snapshot
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn memory(&self) -> &ReadonlySharedMemory {
        &self.memory
    }

    /// Return a copy of the load info for the exe in the snapshot
    pub(crate) fn load_info(&self) -> LoadInfo {
        self.load_info.clone()
    }

    pub(crate) fn layout(&self) -> &crate::mem::layout::SandboxMemoryLayout {
        &self.layout
    }

    pub(crate) fn root_pt_gpa(&self) -> u64 {
        self.layout.get_pt_base_gpa()
    }

    pub(crate) fn stack_top_gva(&self) -> u64 {
        self.stack_top_gva
    }

    /// Returns the special registers stored in this snapshot.
    /// Returns None for snapshots created directly from a binary (before preinitialisation).
    /// Returns Some for snapshots taken from a running sandbox.
    /// Note: The CR3 value in the returned struct should NOT be used for restore;
    /// use `root_pt_gpa()` instead since page tables are relocated during snapshot.
    pub(crate) fn sregs(&self) -> Option<&CommonSpecialRegisters> {
        self.sregs.as_ref()
    }

    #[cfg(feature = "i686-guest")]
    pub(crate) fn separate_pt_bytes(&self) -> &[u8] {
        &self.separate_pt_bytes
    }

    pub(crate) fn entrypoint(&self) -> NextAction {
        self.entrypoint
    }
}

impl PartialEq for Snapshot {
    fn eq(&self, other: &Snapshot) -> bool {
        self.hash == other.hash
    }
}

#[cfg(test)]
#[cfg(not(feature = "i686-guest"))]
mod tests {
    use hyperlight_common::vmem::{self, BasicMapping, Mapping, MappingKind, PAGE_SIZE};

    use crate::hypervisor::regs::CommonSpecialRegisters;
    use crate::mem::exe::LoadInfo;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::mgr::{GuestPageTableBuffer, SandboxMemoryManager, SnapshotSharedMemory};
    use crate::mem::shared_mem::{
        ExclusiveSharedMemory, HostSharedMemory, ReadonlySharedMemory, SharedMemory,
    };

    fn default_sregs() -> CommonSpecialRegisters {
        CommonSpecialRegisters::default()
    }

    const SIMPLE_PT_BASE: usize = PAGE_SIZE + SandboxMemoryLayout::BASE_ADDRESS;

    fn make_simple_pt_mem(contents: &[u8]) -> SnapshotSharedMemory<ExclusiveSharedMemory> {
        let pt_buf = GuestPageTableBuffer::new(SIMPLE_PT_BASE);
        let mapping = Mapping {
            phys_base: SandboxMemoryLayout::BASE_ADDRESS as u64,
            virt_base: SandboxMemoryLayout::BASE_ADDRESS as u64,
            len: PAGE_SIZE as u64,
            kind: MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: true,
            }),
        };
        unsafe { vmem::map(&pt_buf, mapping) };
        super::map_specials(&pt_buf, PAGE_SIZE);
        let pt_bytes = pt_buf.into_bytes();

        let mut snapshot_mem = vec![0u8; PAGE_SIZE + pt_bytes.len()];
        snapshot_mem[0..PAGE_SIZE].copy_from_slice(contents);
        snapshot_mem[PAGE_SIZE..].copy_from_slice(&pt_bytes);
        ReadonlySharedMemory::from_bytes(&snapshot_mem)
            .unwrap()
            .to_mgr_snapshot_mem()
            .unwrap()
    }

    fn make_simple_pt_mgr() -> (SandboxMemoryManager<HostSharedMemory>, u64) {
        let cfg = crate::sandbox::SandboxConfiguration::default();
        let scratch_mem = ExclusiveSharedMemory::new(cfg.get_scratch_size()).unwrap();
        let mgr = SandboxMemoryManager::new(
            SandboxMemoryLayout::new(cfg, 4096, 0x3000, None).unwrap(),
            make_simple_pt_mem(&[0u8; PAGE_SIZE]),
            scratch_mem,
            super::NextAction::None,
        );
        let (mgr, _) = mgr.build().unwrap();
        (mgr, SIMPLE_PT_BASE as u64)
    }

    #[test]
    fn multiple_snapshots_independent() {
        let (mut mgr, pt_base) = make_simple_pt_mgr();

        // Create first snapshot with pattern A
        let pattern_a = vec![0xAA; PAGE_SIZE];
        let snapshot_a = super::Snapshot::new(
            &mut make_simple_pt_mem(&pattern_a).build().0,
            &mut mgr.scratch_mem,
            1,
            mgr.layout,
            LoadInfo::dummy(),
            Vec::new(),
            &[pt_base],
            0,
            default_sregs(),
            super::NextAction::None,
        )
        .unwrap();

        // Create second snapshot with pattern B
        let pattern_b = vec![0xBB; PAGE_SIZE];
        let snapshot_b = super::Snapshot::new(
            &mut make_simple_pt_mem(&pattern_b).build().0,
            &mut mgr.scratch_mem,
            2,
            mgr.layout,
            LoadInfo::dummy(),
            Vec::new(),
            &[pt_base],
            0,
            default_sregs(),
            super::NextAction::None,
        )
        .unwrap();

        // Restore snapshot A
        mgr.restore_snapshot(&snapshot_a).unwrap();
        mgr.shared_mem
            .with_contents(|contents| assert_eq!(&contents[0..pattern_a.len()], &pattern_a[..]))
            .unwrap();

        // Restore snapshot B
        mgr.restore_snapshot(&snapshot_b).unwrap();
        mgr.shared_mem
            .with_contents(|contents| assert_eq!(&contents[0..pattern_b.len()], &pattern_b[..]))
            .unwrap();
    }
}
