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

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use hyperlight_common::flatbuffer_wrappers::util::estimate_flatbuffer_capacity;
use hyperlight_common::transport::{Buf, EncodedMessage, ExternalValueRefs, MsgKind};
use hyperlight_common::virtq::ReplyChain;
use hyperlight_common::vmem::{self, PAGE_TABLE_SIZE};
#[cfg(crashdump)]
use hyperlight_common::vmem::{BasicMapping, MappingKind};
use tracing::{Span, instrument};

use super::layout::SandboxMemoryLayout;
use super::shared_mem::{
    ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, ReadonlySharedMemory, SharedMemory,
};
use super::virtq::{self, G2hConsumer, H2gConsumer};
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::mem::memory_region::MemoryRegion;
#[cfg(crashdump)]
use crate::mem::memory_region::{CrashDumpRegion, MemoryRegionFlags, MemoryRegionType};
use crate::sandbox::snapshot::{NextAction, Snapshot};
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

// It would be nice to have a simple type alias
// `SnapshotSharedMemory<S: SharedMemory>` that abstracts over the
// fact that the snapshot shared memory is `ReadonlySharedMemory`
// normally, but there is (temporary) support for writable
// `GuestSharedMemory` with `#[cfg(gdb)]`. Unfortunately, rustc gets
// annoyed about an unused type parameter, unless one goes to a little
// bit of effort to trick it...
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
    /// Correlation ID assigned to the next guest-function call.
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
    /// Create a new `SandboxMemoryManager` with the given parameters
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        layout: SandboxMemoryLayout,
        shared_mem: SnapshotSharedMemory<S>,
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
        let shared_mem = s.memory().to_mgr_snapshot_mem()?;
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
            next_guest_cid: self.next_guest_cid,
        };
        host_mgr.update_scratch_bookkeeping()?;

        if matches!(host_mgr.next_action, NextAction::Initialise(_)) {
            host_mgr.create_virtq_consumers()?;
        }

        Ok((host_mgr, guest_mgr))
    }
}

impl SandboxMemoryManager<HostSharedMemory> {
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
        let virtq = match (&self.g2h_consumer, &self.h2g_consumer) {
            (Some(_), Some(_)) => Some(virtq::snapshot(&self.layout, &self.scratch_mem)?),
            (None, None) => None,
            _ => return Err(new_error!("virtqueue consumer ownership is incomplete")),
        };

        self.snapshot_count += 1;
        Snapshot::new(
            &mut self.shared_mem,
            &mut self.scratch_mem,
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
            self.snapshot_count,
            host_functions,
            virtq,
        )
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

    /// Restore a captured canonical transport image against this scratch mapping.
    pub(crate) fn restore_virtq(&mut self, snapshot: &virtq::VirtqSnapshot) -> Result<()> {
        if self.g2h_consumer.is_some() || self.h2g_consumer.is_some() {
            return Err(new_error!("virtqueue consumers are already attached"));
        }

        let (g2h, h2g) = virtq::restore(&self.layout, &self.scratch_mem, snapshot)?;
        self.g2h_consumer = Some(g2h);
        self.h2g_consumer = Some(h2g);
        Ok(())
    }

    /// Write a guest function call into the H2G virtqueue.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_guest_function_call(&mut self, call: &FunctionCall) -> Result<u32> {
        let cid = self.next_guest_cid;
        let params = call.parameters.as_deref().unwrap_or_default();
        let cap = estimate_flatbuffer_capacity(&call.function_name, params);

        let mut builder = FlatBufferBuilder::with_capacity(cap);
        let mut ext_vals = ExternalValueRefs::new();

        let control = call.encode(&mut builder, &mut ext_vals)?;

        let Some(message) = EncodedMessage::new(MsgKind::Request, cid, control, ext_vals) else {
            return Err(new_error!("H2G request exceeds the wire payload limit"));
        };

        let buffer_size = self.layout.get_h2g_buffer_size();
        let buffer_count = message.total_len().div_ceil(buffer_size);

        // External bytes may become owner-backed ByteChunks retained across
        // calls. If they consume every posted H2G buffer, no buffer remains
        // for a control call that releases them. External payloads therefore
        // require one extra chain. poll_exact_with_spare checks the chain and
        // leaves it available for the next call.
        let spare_buffers = usize::from(message.external_len() != 0);

        let consumer = self.h2g_consumer.as_mut().ok_or_else(|| {
            HyperlightError::VirtqTransportError("H2G consumer is not attached".into())
        })?;

        // H2G receive buffers are writable-only, so any readable payload is malformed.
        let maybe_buffers = consumer
            .poll_exact_with_spare(buffer_count, spare_buffers, 0)
            .map_err(|error| {
                HyperlightError::VirtqTransportError(format!("H2G poll failed: {error}"))
            })?;

        let Some(buffers) = maybe_buffers else {
            return Err(new_error!(
                "H2G capacity cannot provide {buffer_count} buffers with {spare_buffers} spare"
            ));
        };

        // The message is a contiguous sequence of bytes, but the buffers are a chain of possibly
        // non contiguous slices. Write the message into the buffers in order, advancing the message
        // cursor as we go.
        let mut message = message.as_buf();

        for (recv, reply) in buffers {
            let ReplyChain::Writable(mut buffer) = reply else {
                return Err(HyperlightError::VirtqTransportError(
                    "H2G receive buffer is not writable".into(),
                ));
            };

            if buffer.desc_count() != 1 || buffer.capacity() != buffer_size {
                return Err(HyperlightError::VirtqTransportError(
                    "H2G receive buffer has an invalid shape".into(),
                ));
            }

            while message.has_remaining() && buffer.remaining() != 0 {
                let written = buffer.write(message.chunk()).map_err(|error| {
                    HyperlightError::VirtqTransportError(format!("H2G write failed: {error}"))
                })?;

                message.advance(written);
            }

            consumer.complete(recv, buffer).map_err(|error| {
                HyperlightError::VirtqTransportError(format!("H2G completion failed: {error}"))
            })?;
        }

        debug_assert!(!message.has_remaining());
        self.next_guest_cid = cid.wrapping_add(1);
        if self.next_guest_cid == 0 {
            self.next_guest_cid = 1;
        }
        Ok(cid)
    }

    /// Read a guest function result from the G2H virtqueue.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_h2g_result_from_g2h(&mut self, cid: u32) -> Result<FunctionCallResult> {
        let max_recv_len = self.layout.get_g2h_queue_dims().pool_len();

        let Some(consumer) = self.g2h_consumer.as_mut() else {
            return Err(HyperlightError::VirtqTransportError(
                "G2H consumer is not attached".into(),
            ));
        };

        loop {
            let maybe_next = consumer.poll(max_recv_len).map_err(|error| {
                HyperlightError::VirtqTransportError(format!("G2H poll failed: {error}"))
            })?;

            let Some((mut recv, reply)) = maybe_next else {
                return Err(HyperlightError::VirtqTransportError(
                    "G2H has no guest function result after halt".into(),
                ));
            };

            let header = virtq::read_message_header(&mut recv).map_err(|error| {
                HyperlightError::VirtqTransportError(format!(
                    "Failed to read G2H result header: {error}"
                ))
            })?;

            if !matches!(&reply, ReplyChain::Ack(_)) {
                return Err(HyperlightError::VirtqTransportError(
                    "G2H result entry has writable buffers".into(),
                ));
            }

            match header.msg_kind() {
                Ok(MsgKind::Log) => {
                    if header.cid != 0 {
                        return Err(HyperlightError::VirtqTransportError(
                            "G2H log has a correlation ID".into(),
                        ));
                    }

                    let log = virtq::read_guest_log_data(&mut recv).map_err(|error| {
                        HyperlightError::VirtqTransportError(format!(
                            "Failed to read G2H log: {error}"
                        ))
                    })?;

                    consumer.complete(recv, reply).map_err(|error| {
                        HyperlightError::VirtqTransportError(format!(
                            "Failed to complete G2H log: {error}"
                        ))
                    })?;

                    crate::sandbox::outb::emit_guest_log(&log);
                }
                Ok(MsgKind::Response) => {
                    if header.cid != cid {
                        return Err(HyperlightError::VirtqTransportError(
                            "G2H guest function result correlation ID mismatch".into(),
                        ));
                    }

                    let result = virtq::read_guest_function_call_result(&mut recv);
                    consumer.complete(recv, reply).map_err(|error| {
                        HyperlightError::VirtqTransportError(format!(
                            "Failed to complete G2H guest function result: {error}"
                        ))
                    })?;

                    return result.map_err(|error| {
                        HyperlightError::VirtqTransportError(format!(
                            "Failed to decode G2H guest function result: {error}"
                        ))
                    });
                }
                Ok(kind) => {
                    return Err(HyperlightError::VirtqTransportError(format!(
                        "Expected G2H guest function result, got {kind:?}"
                    )));
                }
                Err(kind) => {
                    return Err(HyperlightError::VirtqTransportError(format!(
                        "Unknown G2H message kind {kind:#x}"
                    )));
                }
            }
        }
    }

    /// This function restores a memory snapshot from a given snapshot.
    pub(crate) fn restore_snapshot(
        &mut self,
        snapshot: &Snapshot,
    ) -> Result<(
        Option<SnapshotSharedMemory<GuestSharedMemory>>,
        Option<GuestSharedMemory>,
    )> {
        let virtq = snapshot.virtq();
        if let Some(virtq) = virtq {
            virtq.preflight(snapshot.layout())?;
        } else if matches!(snapshot.next_action(), NextAction::Call(_)) {
            return Err(new_error!(
                "running snapshot has no canonical transport state"
            ));
        }

        self.g2h_consumer = None;
        self.h2g_consumer = None;

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
        // Carry the guest ELF entry point across restore so crashdumps
        // report the restored image's entry.
        self.original_entrypoint = snapshot.original_entrypoint();

        self.update_scratch_bookkeeping()?;
        if let Some(virtq) = virtq {
            self.restore_virtq(virtq)?;
        } else if matches!(snapshot.next_action(), NextAction::Initialise(_)) {
            self.create_virtq_consumers()?;
        }
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

        // Record the G2H and H2G queue depths, pool page counts, and buffer sizes.
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET,
            u64::try_from(self.layout.get_g2h_queue_depth())?,
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
            SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET,
            u64::try_from(self.layout.get_h2g_queue_depth())?,
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
    #[cfg(crashdump)]
    pub(crate) fn get_guest_memory_regions(
        &mut self,
        root_pt: u64,
        mmap_regions: &[MemoryRegion],
    ) -> Result<Vec<CrashDumpRegion>> {
        use crate::sandbox::snapshot::SharedMemoryPageTableBuffer;

        let len = hyperlight_common::layout::SCRATCH_TOP_GVA;

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
}

#[cfg(test)]
mod h2g_tests {
    use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
    use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
    use hyperlight_common::transport::{
        MsgHeader, MsgKind, SIZE_PREFIX_LEN, size_prefix_payload_len, size_prefixed_len,
    };
    use hyperlight_common::virtq::DescFlags;
    use hyperlight_common::vmem;

    use super::SandboxMemoryManager;
    use crate::HyperlightError;
    #[cfg(unshared_snapshot_mem)]
    use crate::mem::shared_mem::ExclusiveSharedMemory;
    use crate::mem::shared_mem::HostSharedMemory;
    #[cfg(not(unshared_snapshot_mem))]
    use crate::mem::shared_mem::ReadonlySharedMemory;
    use crate::mem::virtq::tests::{H2G_BUFFER_SIZE, PreparedVirtq, memory_layout};
    use crate::sandbox::snapshot::NextAction;

    fn h2g_manager(prepared: &PreparedVirtq) -> SandboxMemoryManager<HostSharedMemory> {
        #[cfg(not(unshared_snapshot_mem))]
        let shared_mem =
            ReadonlySharedMemory::from_bytes(&vec![0; vmem::PAGE_SIZE], vmem::PAGE_SIZE).unwrap();
        #[cfg(unshared_snapshot_mem)]
        let shared_mem = ExclusiveSharedMemory::new(vmem::PAGE_SIZE)
            .unwrap()
            .build()
            .0;

        let mut manager = SandboxMemoryManager::new(
            memory_layout(),
            shared_mem,
            prepared.scratch.clone(),
            NextAction::None,
        );
        manager.h2g_consumer = Some(prepared.h2g_consumer());
        manager
    }

    fn h2g_call(bytes: usize) -> FunctionCall {
        let parameters = (bytes != 0).then(|| vec![ParameterValue::VecBytes(vec![0xa5; bytes])]);
        FunctionCall::new(
            "call".to_string(),
            parameters,
            FunctionCallType::Guest,
            ReturnType::Void,
        )
    }

    #[test]
    fn rejects_malformed_h2g_buffers() {
        for (len, expected) in [
            (H2G_BUFFER_SIZE as u32, "Payload data too large"),
            (0, "not writable"),
        ] {
            let prepared = PreparedVirtq::new();
            let mut manager = h2g_manager(&prepared);
            let mut desc = prepared.h2g_desc(0);
            desc.flags &= !DescFlags::WRITE.bits();
            desc.len = len;
            prepared.set_h2g_desc(0, desc);

            let error = manager.write_guest_function_call(&h2g_call(0)).unwrap_err();

            assert!(error.to_string().contains(expected), "{error:#}");
            assert!(error.is_poison_error());
            assert!(matches!(error, HyperlightError::VirtqTransportError(_)));
        }
    }

    #[test]
    fn partial_h2g_write_is_fatal() {
        let prepared = PreparedVirtq::new();
        let mut manager = h2g_manager(&prepared);
        let mut desc = prepared.h2g_desc(1);
        desc.addr = prepared.h2g_pool.end;
        prepared.set_h2g_desc(1, desc);

        let error = manager
            .write_guest_function_call(&h2g_call(H2G_BUFFER_SIZE + 1024))
            .unwrap_err();

        assert!(error.to_string().contains("Memory write"), "{error:#}");
        assert!(error.is_poison_error());
        assert!(matches!(error, HyperlightError::VirtqTransportError(_)));
        assert_eq!(
            manager.h2g_consumer.as_ref().unwrap().used_cursor().head(),
            1
        );
    }

    #[test]
    fn insufficient_h2g_capacity_rolls_back() {
        let prepared = PreparedVirtq::new();
        let mut manager = h2g_manager(&prepared);
        let cursor = manager.h2g_consumer.as_ref().unwrap().avail_cursor();

        let error = manager
            .write_guest_function_call(&h2g_call(H2G_BUFFER_SIZE * 4))
            .unwrap_err();

        assert!(error.to_string().contains("H2G capacity"), "{error:#}");
        assert!(!error.is_poison_error());
        assert_eq!(
            manager.h2g_consumer.as_ref().unwrap().avail_cursor(),
            cursor
        );
        assert_eq!(manager.write_guest_function_call(&h2g_call(0)).unwrap(), 1);
    }

    #[test]
    fn missing_g2h_result_is_fatal() {
        let prepared = PreparedVirtq::new();
        let mut manager = h2g_manager(&prepared);
        manager.g2h_consumer = Some(prepared.g2h_consumer());

        let Err(error) = manager.read_h2g_result_from_g2h(1) else {
            panic!("expected missing G2H result");
        };

        assert!(
            error
                .to_string()
                .contains("G2H has no guest function result"),
            "{error:#}"
        );
        assert!(error.is_poison_error());
        assert!(matches!(error, HyperlightError::VirtqTransportError(_)));
    }

    #[test]
    fn writes_dense_h2g_request_and_reserves_control_buffer() {
        let prepared = PreparedVirtq::new();
        let mut manager = h2g_manager(&prepared);
        let external_len = H2G_BUFFER_SIZE * 2;
        let buffers: Vec<_> = (0..4).map(|index| prepared.h2g_desc(index).addr).collect();

        let cid = manager
            .write_guest_function_call(&h2g_call(external_len))
            .unwrap();

        let used = manager.h2g_consumer.as_ref().unwrap().avail_cursor().head();
        let wire: Vec<u8> = (0..used)
            .flat_map(|index| prepared.h2g_buffer(index, buffers[index as usize]))
            .collect();
        let header = MsgHeader::from_bytes(&wire[..MsgHeader::SIZE]).unwrap();
        assert_eq!(header.msg_kind(), Ok(MsgKind::Request));
        assert_eq!(header.cid, cid);
        assert_eq!(header.payload_len as usize, wire.len() - MsgHeader::SIZE);

        let control_payload =
            size_prefix_payload_len(&wire[MsgHeader::SIZE..MsgHeader::SIZE + SIZE_PREFIX_LEN])
                .unwrap();
        let control_len = size_prefixed_len(control_payload).unwrap();
        let external = &wire[MsgHeader::SIZE + control_len..];
        assert_eq!(external, vec![0xa5; external_len]);

        let cursor = manager.h2g_consumer.as_ref().unwrap().avail_cursor();
        let error = manager.write_guest_function_call(&h2g_call(1)).unwrap_err();
        assert!(error.to_string().contains("H2G capacity"), "{error:#}");
        assert_eq!(
            manager.h2g_consumer.as_ref().unwrap().avail_cursor(),
            cursor
        );
        assert_eq!(manager.write_guest_function_call(&h2g_call(0)).unwrap(), 2);
    }

    #[test]
    fn guest_cid_wraps_without_zero() {
        let prepared = PreparedVirtq::new();
        let mut manager = h2g_manager(&prepared);
        manager.next_guest_cid = u32::MAX;

        assert_eq!(
            manager.write_guest_function_call(&h2g_call(0)).unwrap(),
            u32::MAX
        );
        assert_eq!(manager.write_guest_function_call(&h2g_call(0)).unwrap(), 1);
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use hyperlight_testing::sandbox_sizes::{LARGE_HEAP_SIZE, MEDIUM_HEAP_SIZE, SMALL_HEAP_SIZE};
    use hyperlight_testing::simple_guest_as_pathbuf;

    use super::SandboxMemoryManager;
    use crate::GuestBinary;
    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox::snapshot::Snapshot;

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
    fn build_creates_virtq_consumers_before_initialization() {
        let path = simple_guest_as_string().expect("failed to get simple guest path");
        let snapshot =
            Snapshot::from_env(GuestBinary::FilePath(path), SandboxConfiguration::default())
                .unwrap();
        let mgr = SandboxMemoryManager::from_snapshot(&snapshot).unwrap();

        let (mgr, _) = mgr.build().unwrap();

        assert!(mgr.g2h_consumer.is_some());
        assert!(mgr.h2g_consumer.is_some());
    }
}
