// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Snapshot memory model:
//!
//! ```text
//! Snapshot
//! `-- memory: Arc<SnapshotMemory>
//!     |-- layers: Box<[Arc<SnapshotBlob>]>
//!     |   |-- SnapshotBlob 0
//!     |   |   |-- memory: ReadonlySharedMemory   [data | page tables]
//!     |   |   |-- gpa_start: u64
//!     |   |   `-- page_table_len: usize
//!     |   `-- SnapshotBlob 1
//!     |       `-- ...
//!     `-- page_tables: Arc<SnapshotBlob>
//! ```

use std::ops::Range;
use std::sync::Arc;

use hyperlight_common::vmem::PAGE_SIZE;

use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::shared_mem::{ReadonlySharedMemory, SharedMemory};
use crate::{Result, new_error};

mod backing;
pub(crate) use backing::SnapshotMemoryBacking;

// Arbitrary cap on the layers of one snapshot. Each layer is one mapping, which
// costs a map/unmap when a sandbox switches snapshots, so this bounds restore
// latency.
pub(crate) const MAX_SNAPSHOT_LAYERS: usize = 30;

/// Memory state assembled from immutable snapshot layers.
///
/// Layer ranges never overlap.
#[derive(Debug)]
pub(crate) struct SnapshotMemory {
    /// Blobs with guest data, sorted by start GPA, which lookups binary
    /// search.
    layers: Box<[Arc<SnapshotBlob>]>,
    /// The blob whose page tables this snapshot restores into scratch memory.
    /// It is one of `layers` when it also holds guest data.
    page_tables: Arc<SnapshotBlob>,
}

/// Immutable memory one snapshot creates: guest data followed by the page
/// tables of that snapshot. The VM maps the data whole at `gpa_start`,
/// including pages a later layer replaced. The page tables are never mapped.
/// Snapshots that reuse the data share the blob.
#[derive(Debug)]
pub(crate) struct SnapshotBlob {
    /// Its `guest_mapped_size` is the data length.
    memory: ReadonlySharedMemory,
    gpa_start: u64,
    page_table_len: usize,
}

impl SnapshotBlob {
    /// `gpa_start` is unused when the blob has no data.
    pub(crate) fn new(
        memory: ReadonlySharedMemory,
        gpa_start: u64,
        page_table_len: usize,
        scratch_base_gpa: u64,
    ) -> Result<Self> {
        let len = memory.mem_size();
        let data_len = memory.guest_mapped_size();
        let expected_len = data_len
            .checked_add(page_table_len)
            .and_then(|len| len.checked_next_multiple_of(host_page_size()));
        if !is_page_aligned(data_len as u64)
            || !page_table_len.is_multiple_of(PAGE_SIZE)
            || len == 0
            || expected_len != Some(len)
        {
            return Err(new_error!("snapshot layer size is invalid"));
        }
        if data_len > 0 {
            if !is_page_aligned(gpa_start) {
                return Err(new_error!("snapshot layer GPA is not aligned"));
            }
            if gpa_start < SandboxMemoryLayout::BASE_ADDRESS as u64 {
                return Err(new_error!("snapshot layer starts below BASE_ADDRESS"));
            }
            let gpa_end = gpa_start
                .checked_add(data_len as u64)
                .ok_or_else(|| new_error!("snapshot layer GPA range overflows"))?;
            if gpa_end > scratch_base_gpa {
                return Err(new_error!("snapshot layer data overlaps scratch memory"));
            }
        }
        Ok(Self {
            memory,
            gpa_start,
            page_table_len,
        })
    }

    pub(crate) fn memory(&self) -> &ReadonlySharedMemory {
        &self.memory
    }

    pub(crate) fn gpa_start(&self) -> u64 {
        self.gpa_start
    }

    /// Length of the guest data, which the VM maps.
    pub(crate) fn data_len(&self) -> usize {
        self.memory.guest_mapped_size()
    }

    pub(crate) fn page_table_len(&self) -> usize {
        self.page_table_len
    }

    pub(crate) fn gpa_range(&self) -> Range<u64> {
        self.gpa_start..self.gpa_start + self.data_len() as u64
    }

    fn page_table_bytes(&self) -> &[u8] {
        let data_len = self.data_len();
        &self.memory.as_slice()[data_len..data_len + self.page_table_len]
    }
}

impl SnapshotMemory {
    pub(crate) fn new(
        mut layers: Box<[Arc<SnapshotBlob>]>,
        page_tables: Arc<SnapshotBlob>,
    ) -> Result<Self> {
        if layers.is_empty() {
            return Err(new_error!("snapshot has no layers"));
        }
        if layers.len() > MAX_SNAPSHOT_LAYERS {
            return Err(new_error!(
                "snapshot layer count {} exceeds {}",
                layers.len(),
                MAX_SNAPSHOT_LAYERS
            ));
        }
        if layers.iter().any(|layer| layer.data_len() == 0) {
            return Err(new_error!("snapshot layer has no data"));
        }
        layers.sort_by_key(|layer| layer.gpa_start);
        // Layers sit between BASE_ADDRESS and scratch, so disjoint layers also
        // bound the total layer size. Overlap also rejects a blob referenced
        // twice.
        if layers
            .windows(2)
            .any(|pair| pair[0].gpa_range().end > pair[1].gpa_start)
        {
            return Err(new_error!("snapshot blob GPA ranges overlap"));
        }
        if page_tables.page_table_len == 0 {
            return Err(new_error!("snapshot page tables are empty"));
        }
        if page_tables.data_len() > 0
            && !layers.iter().any(|layer| Arc::ptr_eq(layer, &page_tables))
        {
            return Err(new_error!("snapshot page-table blob data is not a layer"));
        }

        Ok(Self {
            layers,
            page_tables,
        })
    }

    /// Builds a one-layer snapshot from `memory`, which holds guest data
    /// followed by `page_table_len` bytes of page tables.
    pub(crate) fn from_flat(
        memory: ReadonlySharedMemory,
        gpa_start: u64,
        page_table_len: usize,
        scratch_base_gpa: u64,
    ) -> Result<Self> {
        let blob = Arc::new(SnapshotBlob::new(
            memory,
            gpa_start,
            page_table_len,
            scratch_base_gpa,
        )?);
        Self::new(Box::new([blob.clone()]), blob)
    }

    pub(crate) fn layers(&self) -> &[Arc<SnapshotBlob>] {
        &self.layers
    }

    /// Every blob this snapshot holds: the layers, then the page-table blob
    /// when it holds no data.
    pub(crate) fn blobs(&self) -> impl Iterator<Item = &Arc<SnapshotBlob>> {
        let page_table_only = (self.page_tables.data_len() == 0).then_some(&self.page_tables);
        self.layers.iter().chain(page_table_only)
    }

    pub(crate) fn page_table_blob(&self) -> &Arc<SnapshotBlob> {
        &self.page_tables
    }

    pub(crate) fn page_table_bytes(&self) -> &[u8] {
        self.page_tables.page_table_bytes()
    }

    pub(crate) fn gpa_span_len(&self) -> usize {
        // Sorted, disjoint layers put the highest end in the last one.
        self.layers.last().map_or(0, |last| {
            // Blobs end below the scratch base, so the offset fits in usize.
            (last.gpa_start - SandboxMemoryLayout::BASE_ADDRESS as u64) as usize + last.data_len()
        })
    }

    pub(crate) fn page_table_len(&self) -> usize {
        self.page_tables.page_table_len
    }

    pub(crate) fn resolve(&self, gpa: u64, len: usize) -> Option<(usize, usize)> {
        let (index, offset, available) = self.resolve_chunk(gpa)?;
        (len <= available).then_some((index, offset))
    }

    /// Returns the layer index, the offset into its blob, and the data bytes
    /// left in the blob from `gpa`.
    pub(crate) fn resolve_chunk(&self, gpa: u64) -> Option<(usize, usize, usize)> {
        let index = self
            .layers
            .partition_point(|layer| layer.gpa_start <= gpa)
            .checked_sub(1)?;
        let layer = &self.layers[index];
        let offset = usize::try_from(gpa - layer.gpa_start).ok()?;
        let data_len = layer.data_len();
        (offset < data_len).then(|| (index, offset, data_len - offset))
    }

    pub(crate) fn read_page_tables(
        &self,
        pt_gpa_base: u64,
        gpa: u64,
        destination: &mut [u8],
    ) -> Result<()> {
        let source = gpa
            .checked_sub(pt_gpa_base)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| {
                self.page_table_bytes()
                    .get(offset..offset.checked_add(destination.len())?)
            })
            .ok_or_else(|| new_error!("page-table read range is out of bounds"))?;
        destination.copy_from_slice(source);
        Ok(())
    }
}

pub(crate) fn host_page_size() -> usize {
    PAGE_SIZE.max(page_size::get())
}

/// Guest and host pages are powers of two, so the larger one implies both.
fn is_page_aligned(value: u64) -> bool {
    value.is_multiple_of(host_page_size() as u64)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mem::shared_mem::ExclusiveSharedMemory;

    const SCRATCH_BASE_GPA: u64 = 0x1_0000_0000;

    /// Copies guest data and page tables into one blob. The data is padded to a
    /// host page.
    pub(crate) fn blob_bytes(data: &[u8], page_tables: &[u8]) -> Result<ReadonlySharedMemory> {
        let data_len = data.len().next_multiple_of(host_page_size());
        let mut bytes = vec![0u8; data_len + page_tables.len()];
        bytes[..data.len()].copy_from_slice(data);
        bytes[data_len..].copy_from_slice(page_tables);
        Ok(ReadonlySharedMemory::from_bytes(&bytes, data_len)?)
    }

    pub(crate) fn flat_memory(
        data: &[u8],
        page_tables: &[u8],
        gpa_start: u64,
        scratch_base_gpa: u64,
    ) -> SnapshotMemory {
        SnapshotMemory::from_flat(
            blob_bytes(data, page_tables).unwrap(),
            gpa_start,
            page_tables.len(),
            scratch_base_gpa,
        )
        .unwrap()
    }

    pub(crate) fn page_tables_from_bytes(bytes: &[u8]) -> Arc<SnapshotBlob> {
        Arc::new(SnapshotBlob::new(blob_bytes(&[], bytes).unwrap(), 0, bytes.len(), 0).unwrap())
    }

    pub(crate) fn stub_page_tables() -> Arc<SnapshotBlob> {
        page_tables_from_bytes(&vec![0u8; PAGE_SIZE])
    }

    fn blob(data_pages: usize, gpa_start: u64) -> Arc<SnapshotBlob> {
        let data_len = data_pages * page_size::get();
        let storage = ExclusiveSharedMemory::new(data_len)
            .unwrap()
            .freeze(data_len)
            .unwrap();
        Arc::new(SnapshotBlob::new(storage, gpa_start, 0, SCRATCH_BASE_GPA).unwrap())
    }

    #[test]
    fn blob_rejects_overflowing_gpa_range() {
        let host_page_size = page_size::get();
        let storage = ExclusiveSharedMemory::new(host_page_size)
            .unwrap()
            .freeze(host_page_size)
            .unwrap();
        let gpa_start = u64::MAX - host_page_size as u64 + 1;

        assert!(SnapshotBlob::new(storage, gpa_start, 0, u64::MAX).is_err());
    }

    #[test]
    fn blob_rejects_sizes_that_do_not_fill_it() {
        let host_page_size = page_size::get();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let storage = |data_len| {
            ExclusiveSharedMemory::new(2 * host_page_size)
                .unwrap()
                .freeze(data_len)
                .unwrap()
        };

        assert!(SnapshotBlob::new(storage(host_page_size), base, 0, SCRATCH_BASE_GPA).is_err());
        assert!(SnapshotBlob::new(storage(0), base, 0, SCRATCH_BASE_GPA).is_err());
        assert!(SnapshotBlob::new(storage(host_page_size), base, 1, SCRATCH_BASE_GPA).is_err());
        SnapshotBlob::new(
            storage(host_page_size),
            base,
            host_page_size,
            SCRATCH_BASE_GPA,
        )
        .unwrap();
    }

    #[test]
    fn page_tables_follow_the_data_and_stay_unmapped() {
        let host_page_size = page_size::get();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let memory = SnapshotMemory::from_flat(
            blob_bytes(&vec![0x11; host_page_size], &vec![0x22; PAGE_SIZE]).unwrap(),
            base,
            PAGE_SIZE,
            SCRATCH_BASE_GPA,
        )
        .unwrap();

        assert_eq!(memory.page_table_bytes(), vec![0x22; PAGE_SIZE]);
        assert_eq!(memory.gpa_span_len(), host_page_size);
        assert_eq!(memory.resolve(base + host_page_size as u64, 1), None);
        assert_eq!(memory.blobs().count(), 1);
    }

    #[test]
    fn memory_rejects_page_table_blob_data_outside_the_layers() {
        let host_page_size = page_size::get();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let page_tables = Arc::new(
            SnapshotBlob::new(
                blob_bytes(&vec![0; host_page_size], &vec![0; PAGE_SIZE]).unwrap(),
                base + host_page_size as u64,
                PAGE_SIZE,
                SCRATCH_BASE_GPA,
            )
            .unwrap(),
        );

        assert!(SnapshotMemory::new(Box::new([blob(1, base)]), page_tables.clone()).is_err());
        SnapshotMemory::new(Box::new([blob(1, base), page_tables.clone()]), page_tables).unwrap();
    }

    #[test]
    fn reads_page_tables_from_page_table_only_blob() {
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let page_tables = page_tables_from_bytes(&vec![0x33; PAGE_SIZE]);
        let memory = SnapshotMemory::new(Box::new([blob(1, base)]), page_tables).unwrap();
        let mut byte = [0u8; 1];

        memory.read_page_tables(0x8000, 0x8fff, &mut byte).unwrap();

        assert_eq!(byte, [0x33]);
        assert_eq!(memory.resolve(base, PAGE_SIZE), Some((0, 0)));
    }

    #[test]
    fn memory_rejects_overlapping_blob_gpas() {
        let host_page_size = page_size::get();
        let gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let layers = Box::new([blob(2, gpa), blob(1, gpa + host_page_size as u64)]);

        assert!(SnapshotMemory::new(layers, stub_page_tables()).is_err());
    }

    #[test]
    fn memory_canonicalizes_layers() {
        let host_page_size = page_size::get();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let layers = Box::new([blob(1, base + host_page_size as u64), blob(1, base)]);

        let memory = SnapshotMemory::new(layers, stub_page_tables()).unwrap();

        assert_eq!(memory.layers()[0].gpa_start(), base);
    }

    #[test]
    fn resolve_covers_whole_blob_and_rejects_past_end() {
        let host_page_size = page_size::get();
        let gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let memory = SnapshotMemory::new(Box::new([blob(3, gpa)]), stub_page_tables()).unwrap();

        assert_eq!(memory.resolve(gpa, 1), Some((0, 0)));
        assert_eq!(
            memory.resolve(gpa + host_page_size as u64, host_page_size),
            Some((0, host_page_size))
        );
        assert_eq!(
            memory.resolve(gpa + (3 * host_page_size - 1) as u64, 1),
            Some((0, 3 * host_page_size - 1))
        );
        assert_eq!(
            memory.resolve(gpa + (3 * host_page_size - 1) as u64, 2),
            None
        );
        assert_eq!(memory.resolve(gpa - 1, 1), None);
    }

    #[test]
    fn reads_reject_addresses_past_the_blob() {
        let host_page_size = page_size::get();
        let gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let memory = SnapshotMemory::new(Box::new([blob(3, gpa)]), stub_page_tables()).unwrap();
        let (backing, _) = SnapshotMemoryBacking::from_snapshot(Arc::new(memory))
            .unwrap()
            .build();
        let mut byte = [0u8; 1];

        backing
            .read_snapshot_gpa(gpa + host_page_size as u64 + 1, &mut byte)
            .unwrap();
        assert!(
            backing
                .read_snapshot_gpa(gpa + 3 * host_page_size as u64 + 1, &mut byte)
                .is_err()
        );
    }

    #[test]
    fn memory_rejects_excess_layers() {
        let host_page_size = page_size::get() as u64;
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let layers = (0..=MAX_SNAPSHOT_LAYERS as u64)
            .map(|index| blob(1, base + index * host_page_size))
            .collect();

        assert!(SnapshotMemory::new(layers, stub_page_tables()).is_err());
    }
}
