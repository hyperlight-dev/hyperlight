// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#[cfg(not(unshared_snapshot_mem))]
use std::marker::PhantomData;
use std::sync::Arc;

use super::{SnapshotBlob, SnapshotMemory};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionType};
use crate::mem::shared_mem::{
    ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory,
};
use crate::{Result, new_error};

/// Memory for one snapshot with one or more layers.
/// Standard builds use each layer's read-only blob. GDB builds use one writable
/// copy of each layer's data.
pub(crate) struct SnapshotMemoryBacking<S: SharedMemory> {
    memory: Arc<SnapshotMemory>,
    /// One writable copy for each layer in `memory`.
    #[cfg(unshared_snapshot_mem)]
    backings: Box<[S]>,
    #[cfg(not(unshared_snapshot_mem))]
    _phase: PhantomData<fn() -> S>,
}

impl<S: Clone + SharedMemory> Clone for SnapshotMemoryBacking<S> {
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            #[cfg(unshared_snapshot_mem)]
            backings: self.backings.clone(),
            #[cfg(not(unshared_snapshot_mem))]
            _phase: PhantomData,
        }
    }
}

impl SnapshotMemoryBacking<ExclusiveSharedMemory> {
    pub(crate) fn from_snapshot(memory: Arc<SnapshotMemory>) -> Result<Self> {
        #[cfg(unshared_snapshot_mem)]
        let backings = memory
            .layers()
            .iter()
            .map(|layer| layer.memory().copy_to_writable())
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_boxed_slice();
        Ok(Self {
            memory,
            #[cfg(unshared_snapshot_mem)]
            backings,
            #[cfg(not(unshared_snapshot_mem))]
            _phase: PhantomData,
        })
    }

    pub(crate) fn build(
        self,
    ) -> (
        SnapshotMemoryBacking<HostSharedMemory>,
        SnapshotMemoryBacking<GuestSharedMemory>,
    ) {
        #[cfg(unshared_snapshot_mem)]
        let (host_backings, guest_backings) = self
            .backings
            .into_vec()
            .into_iter()
            .map(ExclusiveSharedMemory::build)
            .unzip::<_, _, Vec<_>, Vec<_>>();
        let memory = self.memory;
        (
            SnapshotMemoryBacking {
                memory: memory.clone(),
                #[cfg(unshared_snapshot_mem)]
                backings: host_backings.into_boxed_slice(),
                #[cfg(not(unshared_snapshot_mem))]
                _phase: PhantomData,
            },
            SnapshotMemoryBacking {
                memory,
                #[cfg(unshared_snapshot_mem)]
                backings: guest_backings.into_boxed_slice(),
                #[cfg(not(unshared_snapshot_mem))]
                _phase: PhantomData,
            },
        )
    }
}

impl<S: SharedMemory> SnapshotMemoryBacking<S> {
    #[cfg(all(test, not(unshared_snapshot_mem)))]
    pub(crate) fn layers(&self) -> &[Arc<SnapshotBlob>] {
        self.memory.layers()
    }

    pub(crate) fn resolve(&self, gpa: u64, len: usize) -> Option<(usize, usize)> {
        self.memory.resolve(gpa, len)
    }

    pub(crate) fn gpa_span_len(&self) -> usize {
        self.memory.gpa_span_len()
    }

    pub(crate) fn page_table_len(&self) -> usize {
        self.memory.page_table_len()
    }
}

impl SnapshotMemoryBacking<GuestSharedMemory> {
    /// One mapping per layer, covering its whole data.
    pub(crate) fn mappings(&self) -> Vec<MemoryRegion> {
        #[cfg(not(unshared_snapshot_mem))]
        let backings = self.memory.layers().iter().map(|layer| layer.memory());
        #[cfg(unshared_snapshot_mem)]
        let backings = self.backings.iter();
        self.memory
            .layers()
            .iter()
            .zip(backings)
            .map(|(layer, backing)| {
                backing.mapping_at(layer.gpa_start(), MemoryRegionType::Snapshot)
            })
            .collect()
    }
}

impl SnapshotMemoryBacking<HostSharedMemory> {
    pub(crate) fn reusable_layers(&self) -> Option<&[Arc<SnapshotBlob>]> {
        #[cfg(not(unshared_snapshot_mem))]
        {
            Some(self.memory.layers())
        }
        #[cfg(unshared_snapshot_mem)]
        {
            None
        }
    }

    pub(crate) fn copy_layer_to_slice(
        &self,
        layer_index: usize,
        slice: &mut [u8],
        offset: usize,
    ) -> Result<()> {
        #[cfg(not(unshared_snapshot_mem))]
        let backing = self
            .memory
            .layers()
            .get(layer_index)
            .map(|layer| layer.memory());
        #[cfg(unshared_snapshot_mem)]
        let backing = self.backings.get(layer_index);
        backing
            .ok_or_else(|| new_error!("snapshot layer index is out of bounds"))?
            .copy_to_slice(slice, offset)
            .map_err(Into::into)
    }

    pub(crate) fn read_snapshot_gpa(&self, gpa: u64, slice: &mut [u8]) -> Result<()> {
        let mut copied = 0usize;
        while copied < slice.len() {
            let current_gpa = gpa
                .checked_add(u64::try_from(copied)?)
                .ok_or_else(|| new_error!("snapshot GPA range overflows"))?;
            let (layer_index, offset, available) = self
                .memory
                .resolve_chunk(current_gpa)
                .ok_or_else(|| new_error!("snapshot GPA range is not mapped: {current_gpa:#x}"))?;
            let chunk_len = available.min(slice.len() - copied);
            self.copy_layer_to_slice(layer_index, &mut slice[copied..copied + chunk_len], offset)?;
            copied += chunk_len;
        }
        Ok(())
    }

    /// Writes into a snapshot layer resolved by [`Self::resolve`].
    #[cfg(gdb)]
    pub(crate) fn write_layer(
        &self,
        layer_index: usize,
        offset: usize,
        slice: &[u8],
    ) -> Result<()> {
        self.backings
            .get(layer_index)
            .ok_or_else(|| new_error!("snapshot layer index is out of bounds"))?
            .copy_from_slice(slice, offset)
            .map_err(Into::into)
    }

    pub(crate) fn page_table_bytes(&self) -> &[u8] {
        self.memory.page_table_bytes()
    }

    #[cfg(crashdump)]
    pub(crate) fn host_range(&self, layer_index: usize) -> Result<(usize, usize)> {
        #[cfg(not(unshared_snapshot_mem))]
        let backing = self
            .memory
            .layers()
            .get(layer_index)
            .map(|layer| layer.memory());
        #[cfg(unshared_snapshot_mem)]
        let backing = self.backings.get(layer_index);
        let backing = backing.ok_or_else(|| new_error!("snapshot layer index is out of bounds"))?;
        Ok((backing.base_addr(), backing.mem_size()))
    }
}
