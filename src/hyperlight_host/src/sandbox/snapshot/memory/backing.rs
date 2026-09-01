// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#[cfg(not(unshared_snapshot_mem))]
use std::marker::PhantomData;
use std::ops::Range;
use std::sync::Arc;

use super::SnapshotMemory;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::shared_mem::{
    ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory,
    snapshot_mapping_range,
};
use crate::{Result, new_error};

/// Memory for one snapshot with one or more layers.
/// Standard builds use each layer's read-only blob. GDB builds use one writable copy per layer.
pub(crate) struct SnapshotMemoryBacking<S: SharedMemory> {
    memory: Arc<SnapshotMemory>,
    /// One writable copy for each layer in `memory`.
    #[cfg(unshared_snapshot_mem)]
    backings: Box<[S]>,
    #[cfg(not(unshared_snapshot_mem))]
    _phase: PhantomData<fn() -> S>,
}

fn layer<T>(backings: &[T], layer_index: usize) -> Result<&T> {
    backings
        .get(layer_index)
        .ok_or_else(|| new_error!("snapshot layer index is out of bounds"))
}

impl SnapshotMemoryBacking<ExclusiveSharedMemory> {
    pub(crate) fn from_snapshot(memory: Arc<SnapshotMemory>) -> Result<Self> {
        #[cfg(unshared_snapshot_mem)]
        let backings = memory
            .layers()
            .iter()
            .map(|layer| {
                let source = layer.blob().memory().as_slice();
                let mut backing = ExclusiveSharedMemory::new(source.len())?;
                backing.copy_from_slice(source, 0)?;
                Ok(backing)
            })
            .collect::<Result<Vec<_>>>()?
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
    pub(crate) fn resolve(&self, gpa: u64, len: usize) -> Option<(usize, usize)> {
        self.memory.resolve(gpa, len)
    }

    pub(crate) fn gpa_span_len(&self) -> usize {
        self.memory.gpa_span_len()
    }

    pub(crate) fn page_table_len(&self) -> usize {
        self.memory.page_table_len()
    }

    pub(crate) fn reserved_gpa_ranges(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.memory
            .layers()
            .iter()
            .filter_map(|layer| layer.blob().data_gpa_range().map(|data| data.gpa_range()))
    }
}

impl SnapshotMemoryBacking<GuestSharedMemory> {
    pub(crate) fn mappings(&self) -> Result<Vec<MemoryRegion>> {
        let mapping_count = self
            .memory
            .layers()
            .iter()
            .map(|layer| layer.live_data_ranges().len())
            .sum();
        let mut mappings = Vec::with_capacity(mapping_count);
        for (_layer_index, snapshot_layer) in self.memory.layers().iter().enumerate() {
            let Some(data) = snapshot_layer.blob().data_gpa_range() else {
                continue;
            };
            #[cfg(not(unshared_snapshot_mem))]
            let backing = snapshot_layer.blob().memory();
            #[cfg(unshared_snapshot_mem)]
            let backing = layer(&self.backings, _layer_index)?;
            #[cfg(not(unshared_snapshot_mem))]
            let flags = MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE;
            #[cfg(unshared_snapshot_mem)]
            let flags =
                MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE;
            for blob_offset in snapshot_layer.live_data_ranges() {
                let guest_start = data
                    .gpa_start()
                    .checked_add(u64::try_from(blob_offset.start)?)
                    .ok_or_else(|| new_error!("snapshot extent GPA overflows"))?;
                let mapping = snapshot_mapping_range(
                    backing,
                    data.len(),
                    blob_offset.clone(),
                    guest_start,
                    flags,
                )?;
                mappings.push(mapping);
            }
        }
        Ok(mappings)
    }
}

impl SnapshotMemoryBacking<HostSharedMemory> {
    pub(crate) fn copy_layer_to_slice(
        &self,
        layer_index: usize,
        slice: &mut [u8],
        offset: usize,
    ) -> Result<()> {
        #[cfg(not(unshared_snapshot_mem))]
        {
            let backing = layer(self.memory.layers(), layer_index)?.blob().memory();
            let end = offset
                .checked_add(slice.len())
                .ok_or_else(|| new_error!("snapshot read range overflows"))?;
            let source = backing
                .as_slice()
                .get(offset..end)
                .ok_or_else(|| new_error!("snapshot read range is out of bounds"))?;
            slice.copy_from_slice(source);
            Ok(())
        }
        #[cfg(unshared_snapshot_mem)]
        {
            layer(&self.backings, layer_index)?
                .copy_to_slice(slice, offset)
                .map_err(Into::into)
        }
    }

    pub(crate) fn read_snapshot_gpa(&self, gpa: u64, slice: &mut [u8]) -> Result<()> {
        let mut copied = 0usize;
        while copied < slice.len() {
            let current_gpa = gpa
                .checked_add(u64::try_from(copied)?)
                .ok_or_else(|| new_error!("snapshot GPA range overflows"))?;
            let (layer_index, offset, available) = self
                .memory
                .resolve_live_chunk(current_gpa)
                .ok_or_else(|| new_error!("snapshot GPA range is not live: {current_gpa:#x}"))?;
            let chunk_len = available.min(slice.len() - copied);
            self.copy_layer_to_slice(layer_index, &mut slice[copied..copied + chunk_len], offset)?;
            copied += chunk_len;
        }
        Ok(())
    }

    #[cfg(gdb)]
    pub(crate) fn write_snapshot_gpa(&self, gpa: u64, slice: &[u8]) -> Result<()> {
        let (layer_index, offset) = self
            .resolve(gpa, slice.len())
            .ok_or_else(|| new_error!("snapshot GPA range is not live: {gpa:#x}"))?;
        layer(&self.backings, layer_index)?
            .copy_from_slice(slice, offset)
            .map_err(Into::into)
    }

    pub(crate) fn read_page_tables(
        &self,
        pt_gpa_base: u64,
        gpa: u64,
        slice: &mut [u8],
    ) -> Result<()> {
        let page_tables = self
            .memory
            .restore_page_table_layer()
            .blob()
            .page_table_memory_range()
            .expect("SnapshotMemory requires restore page tables");
        let offset = usize::try_from(
            gpa.checked_sub(pt_gpa_base)
                .ok_or_else(|| new_error!("page-table GPA is below its base"))?,
        )?;
        let end = offset
            .checked_add(slice.len())
            .ok_or_else(|| new_error!("page-table read range overflows"))?;
        if end > page_tables.end - page_tables.start {
            return Err(new_error!("page-table read range is out of bounds"));
        }
        self.copy_layer_to_slice(
            self.memory.restore_page_table_layer_index(),
            slice,
            page_tables.start + offset,
        )
    }

    #[cfg(crashdump)]
    pub(crate) fn host_range(&self, layer_index: usize) -> Result<(usize, usize)> {
        #[cfg(not(unshared_snapshot_mem))]
        let backing = layer(self.memory.layers(), layer_index)?.blob().memory();
        #[cfg(unshared_snapshot_mem)]
        let backing = layer(&self.backings, layer_index)?;
        Ok((backing.base_addr(), backing.mem_size()))
    }
}
