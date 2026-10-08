// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Snapshot memory model:
//!
//! ```text
//! Snapshot
//! `-- memory: Arc<SnapshotMemory>
//!     |-- layers: Box<[SnapshotLayer]>
//!     |   |-- SnapshotLayer 0
//!     |   |   |-- blob: Arc<SnapshotBlob>
//!     |   |   |   |-- memory: ReadonlySharedMemory
//!     |   |   |   `-- gpa_start: u64
//!     |   |   `-- live_data_ranges: Box<[Range<usize>]>
//!     |   `-- SnapshotLayer 1
//!     |       `-- ...
//!     `-- page_tables: Arc<SnapshotPageTables>
//! ```

use std::ops::Range;
use std::sync::Arc;

use hyperlight_common::vmem::PAGE_SIZE;

use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::shared_mem::{ReadonlySharedMemory, SharedMemory};
use crate::{Result, new_error};

mod backing;
pub(crate) use backing::SnapshotMemoryBacking;

// Arbitrary cap on the mappings of one snapshot. Each mapping costs a
// map/unmap when a sandbox switches snapshots, so bounding this bounds restore
// latency. Every layer contributes at least one mapping, so this bounds the
// layer count too.
pub(crate) const MAX_SNAPSHOT_MAPPINGS: usize = 30;
const MAX_SNAPSHOT_RETAINED_BYTES: usize = SandboxMemoryLayout::MAX_MEMORY_SIZE.saturating_mul(2);

/// Memory state assembled from immutable snapshot layers.
///
/// Layer ranges never overlap.
#[derive(Debug)]
pub(crate) struct SnapshotMemory {
    /// Layers sorted by the start GPA of each blob's data range, which lookups
    /// binary search.
    layers: Box<[SnapshotLayer]>,
    /// The complete page-table tree. Restore copies the tree into scratch
    /// memory.
    page_tables: Arc<SnapshotPageTables>,
}

/// One layer of a snapshot, backed by a single blob. The live ranges are the
/// parts of the blob's guest address range this layer contributes, and other
/// layers hold the rest. The blob is shared with any other snapshot that reuses
/// it, each with its own live ranges.
#[derive(Clone, Debug)]
pub(crate) struct SnapshotLayer {
    blob: Arc<SnapshotBlob>,
    /// Blob-relative byte ranges, sorted by start offset, disjoint, and
    /// coalesced.
    live_data_ranges: Box<[Range<usize>]>,
}

/// Immutable guest data mapped at `gpa_start`. A snapshot references a blob at
/// most once.
#[derive(Debug)]
pub(crate) struct SnapshotBlob {
    memory: ReadonlySharedMemory,
    gpa_start: u64,
}

/// The page tables one snapshot restores into scratch memory. `memory` is
/// padded to a host page, so `len` gives the tree itself.
#[derive(Debug)]
pub(crate) struct SnapshotPageTables {
    memory: ReadonlySharedMemory,
    len: usize,
}

impl SnapshotBlob {
    pub(crate) fn new(
        memory: ReadonlySharedMemory,
        gpa_start: u64,
        scratch_base_gpa: u64,
    ) -> Result<Self> {
        let len = memory.mem_size();
        if len == 0 || !is_page_aligned(len as u64) {
            return Err(new_error!("snapshot layer size is invalid"));
        }
        if !is_page_aligned(gpa_start) {
            return Err(new_error!("snapshot layer GPA is not aligned"));
        }
        if gpa_start < SandboxMemoryLayout::BASE_ADDRESS as u64 {
            return Err(new_error!("snapshot layer starts below BASE_ADDRESS"));
        }
        let gpa_end = gpa_start
            .checked_add(len as u64)
            .ok_or_else(|| new_error!("snapshot layer GPA range overflows"))?;
        if gpa_end > scratch_base_gpa {
            return Err(new_error!("snapshot layer data overlaps scratch memory"));
        }
        Ok(Self { memory, gpa_start })
    }

    pub(crate) fn memory(&self) -> &ReadonlySharedMemory {
        &self.memory
    }

    pub(crate) fn gpa_start(&self) -> u64 {
        self.gpa_start
    }

    pub(crate) fn len(&self) -> usize {
        self.memory.mem_size()
    }

    pub(crate) fn gpa_range(&self) -> Range<u64> {
        self.gpa_start..self.gpa_start + self.len() as u64
    }
}

impl SnapshotPageTables {
    pub(crate) fn new(memory: ReadonlySharedMemory, len: usize) -> Result<Self> {
        let storage_len = memory.mem_size();
        if len == 0
            || !len.is_multiple_of(PAGE_SIZE)
            || len > storage_len
            || !is_page_aligned(storage_len as u64)
            || storage_len - len >= page_size::get()
        {
            return Err(new_error!("snapshot page-table size is invalid"));
        }
        Ok(Self { memory, len })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.memory.as_slice()[..self.len]
    }

    pub(crate) fn storage_bytes(&self) -> &[u8] {
        self.memory.as_slice()
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

impl SnapshotLayer {
    pub(crate) fn new(
        blob: Arc<SnapshotBlob>,
        live_data_ranges: Box<[Range<usize>]>,
    ) -> Result<Self> {
        if live_data_ranges.is_empty() {
            return Err(new_error!("snapshot layer has no live data"));
        }
        let last = live_data_ranges.len() - 1;
        let mut previous_end = None;
        for (index, range) in live_data_ranges.iter().enumerate() {
            // The last range may end inside the blob's last host page. The VM
            // maps the rest of that page, which is the blob's zero padding.
            let end_is_valid = is_page_aligned(range.end as u64)
                || (index == last
                    && range.end.is_multiple_of(PAGE_SIZE)
                    && range.end.next_multiple_of(host_page_size()) == blob.len());
            if range.start >= range.end
                || !is_page_aligned(range.start as u64)
                || !end_is_valid
                || range.end > blob.len()
            {
                return Err(new_error!("snapshot layer has an invalid live-data range"));
            }
            if previous_end.is_some_and(|end| end >= range.start) {
                return Err(new_error!("snapshot live-data ranges are not coalesced"));
            }
            previous_end = Some(range.end);
        }

        Ok(Self {
            blob,
            live_data_ranges,
        })
    }

    pub(crate) fn blob(&self) -> &Arc<SnapshotBlob> {
        &self.blob
    }

    pub(crate) fn live_data_ranges(&self) -> &[Range<usize>] {
        &self.live_data_ranges
    }

    /// Live ranges rounded up to whole host pages.
    pub(crate) fn mapped_ranges(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        self.live_data_ranges
            .iter()
            .map(|range| range.start..range.end.next_multiple_of(host_page_size()))
    }

    pub(crate) fn resolve(&self, gpa: u64, len: usize) -> Option<usize> {
        let (offset, available) = self.resolve_live_chunk(gpa)?;
        (len <= available).then_some(offset)
    }

    fn resolve_live_chunk(&self, gpa: u64) -> Option<(usize, usize)> {
        let offset = usize::try_from(gpa.checked_sub(self.blob.gpa_start)?).ok()?;
        let range_index = self
            .live_data_ranges
            .partition_point(|range| range.start <= offset)
            .checked_sub(1)?;
        let range = &self.live_data_ranges[range_index];
        (offset < range.end).then(|| (offset, range.end - offset))
    }
}

impl SnapshotMemory {
    pub(crate) fn new(
        mut layers: Box<[SnapshotLayer]>,
        page_tables: Arc<SnapshotPageTables>,
    ) -> Result<Self> {
        if layers.is_empty() {
            return Err(new_error!("snapshot has no layers"));
        }
        layers.sort_by_key(|layer| layer.blob.gpa_start);

        let mut mapping_count = 0usize;
        let mut mapped_bytes = 0usize;
        let mut retained_bytes = page_tables.memory.mem_size();
        let mut previous_end = None;
        for layer in layers.iter() {
            // Overlap also rejects a blob referenced twice.
            let range = layer.blob.gpa_range();
            if previous_end.is_some_and(|end| end > range.start) {
                return Err(new_error!("snapshot blob GPA ranges overlap"));
            }
            previous_end = Some(range.end);
            mapping_count += layer.live_data_ranges.len();
            mapped_bytes += layer
                .mapped_ranges()
                .map(|range| range.end - range.start)
                .sum::<usize>();
            retained_bytes = retained_bytes
                .checked_add(layer.blob.len())
                .ok_or_else(|| new_error!("snapshot retained byte count overflows"))?;
        }
        if mapping_count > MAX_SNAPSHOT_MAPPINGS {
            return Err(new_error!(
                "snapshot mapping count {} exceeds {}",
                mapping_count,
                MAX_SNAPSHOT_MAPPINGS
            ));
        }
        if mapped_bytes > SandboxMemoryLayout::MAX_MEMORY_SIZE {
            return Err(new_error!(
                "snapshot mapped byte count {} exceeds {}",
                mapped_bytes,
                SandboxMemoryLayout::MAX_MEMORY_SIZE
            ));
        }
        if retained_bytes > MAX_SNAPSHOT_RETAINED_BYTES {
            return Err(new_error!(
                "snapshot retained byte count {} exceeds {}",
                retained_bytes,
                MAX_SNAPSHOT_RETAINED_BYTES
            ));
        }

        Ok(Self {
            layers,
            page_tables,
        })
    }

    pub(crate) fn from_flat(
        memory: ReadonlySharedMemory,
        gpa_start: u64,
        page_tables: Arc<SnapshotPageTables>,
        scratch_base_gpa: u64,
    ) -> Result<Self> {
        let blob = Arc::new(SnapshotBlob::new(memory, gpa_start, scratch_base_gpa)?);
        let layer = SnapshotLayer::new(blob.clone(), std::iter::once(0..blob.len()).collect())?;
        Self::new(Box::new([layer]), page_tables)
    }

    pub(crate) fn layers(&self) -> &[SnapshotLayer] {
        &self.layers
    }

    pub(crate) fn page_tables(&self) -> &Arc<SnapshotPageTables> {
        &self.page_tables
    }

    pub(crate) fn gpa_span_len(&self) -> usize {
        // Sorted, disjoint layers put the highest end in the last one.
        self.layers.last().map_or(0, |last| {
            // Blobs end below the scratch base, so the offset fits in usize.
            (last.blob.gpa_start - SandboxMemoryLayout::BASE_ADDRESS as u64) as usize
                + last.blob.len()
        })
    }

    pub(crate) fn page_table_len(&self) -> usize {
        self.page_tables.len()
    }

    pub(crate) fn resolve(&self, gpa: u64, len: usize) -> Option<(usize, usize)> {
        let index = self.layer_for_gpa(gpa)?;
        self.layers[index]
            .resolve(gpa, len)
            .map(|offset| (index, offset))
    }

    pub(crate) fn resolve_live_chunk(&self, gpa: u64) -> Option<(usize, usize, usize)> {
        let index = self.layer_for_gpa(gpa)?;
        self.layers[index]
            .resolve_live_chunk(gpa)
            .map(|(offset, len)| (index, offset, len))
    }

    fn layer_for_gpa(&self, gpa: u64) -> Option<usize> {
        self.layers
            .partition_point(|layer| layer.blob.gpa_start <= gpa)
            .checked_sub(1)
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
                self.page_tables
                    .bytes()
                    .get(offset..offset.checked_add(destination.len())?)
            })
            .ok_or_else(|| new_error!("page-table read range is out of bounds"))?;
        destination.copy_from_slice(source);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn page_tables_from_bytes(bytes: &[u8]) -> Arc<SnapshotPageTables> {
    Arc::new(
        SnapshotPageTables::new(
            ReadonlySharedMemory::from_bytes(bytes).unwrap(),
            bytes.len(),
        )
        .unwrap(),
    )
}

#[cfg(test)]
pub(crate) fn stub_page_tables() -> Arc<SnapshotPageTables> {
    page_tables_from_bytes(&vec![0u8; PAGE_SIZE])
}

fn host_page_size() -> usize {
    PAGE_SIZE.max(page_size::get())
}

/// Guest and host pages are powers of two, so the larger one implies both.
fn is_page_aligned(value: u64) -> bool {
    value.is_multiple_of(host_page_size() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::shared_mem::ExclusiveSharedMemory;

    const SCRATCH_BASE_GPA: u64 = 0x1_0000_0000;

    fn blob(data_pages: usize, gpa_start: u64) -> Arc<SnapshotBlob> {
        let storage = ExclusiveSharedMemory::new(data_pages * page_size::get())
            .unwrap()
            .freeze()
            .unwrap();
        Arc::new(SnapshotBlob::new(storage, gpa_start, SCRATCH_BASE_GPA).unwrap())
    }

    #[test]
    fn blob_rejects_overflowing_gpa_range() {
        let host_page_size = page_size::get();
        let storage = ExclusiveSharedMemory::new(host_page_size)
            .unwrap()
            .freeze()
            .unwrap();
        let gpa_start = u64::MAX - host_page_size as u64 + 1;

        assert!(SnapshotBlob::new(storage, gpa_start, u64::MAX).is_err());
    }

    #[test]
    fn page_tables_reject_zero_length() {
        let storage = ExclusiveSharedMemory::new(page_size::get())
            .unwrap()
            .freeze()
            .unwrap();

        assert!(SnapshotPageTables::new(storage, 0).is_err());
    }

    #[test]
    fn reads_separate_page_tables() {
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let layer = SnapshotLayer::new(
            blob(1, base),
            std::iter::once(0..page_size::get()).collect(),
        )
        .unwrap();
        let page_tables = page_tables_from_bytes(&vec![0x33; PAGE_SIZE]);
        let memory = SnapshotMemory::new(Box::new([layer]), page_tables).unwrap();
        let mut byte = [0u8; 1];

        memory.read_page_tables(0x8000, 0x8fff, &mut byte).unwrap();

        assert_eq!(byte, [0x33]);
        assert_eq!(memory.resolve(base, PAGE_SIZE), Some((0, 0)));
    }

    #[test]
    fn memory_rejects_layer_without_live_data() {
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        assert!(SnapshotLayer::new(blob(1, base), Box::new([])).is_err());
    }

    #[test]
    fn layer_rejects_adjacent_ranges() {
        let host_page_size = page_size::get();
        let blob = blob(2, SandboxMemoryLayout::BASE_ADDRESS as u64);

        assert!(
            SnapshotLayer::new(
                blob,
                Box::new([0..host_page_size, host_page_size..2 * host_page_size]),
            )
            .is_err()
        );
    }

    #[test]
    fn memory_rejects_overlapping_blob_gpas() {
        let host_page_size = page_size::get();
        let gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let first =
            SnapshotLayer::new(blob(2, gpa), std::iter::once(0..host_page_size).collect()).unwrap();
        let second = SnapshotLayer::new(
            blob(1, gpa + host_page_size as u64),
            std::iter::once(0..host_page_size).collect(),
        )
        .unwrap();

        assert!(SnapshotMemory::new(Box::new([first, second]), stub_page_tables()).is_err());
    }

    #[test]
    fn memory_canonicalizes_layers() {
        let host_page_size = page_size::get();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let lower = SnapshotLayer::new(blob(1, base), std::iter::once(0..host_page_size).collect())
            .unwrap();
        let upper = SnapshotLayer::new(
            blob(1, base + host_page_size as u64),
            std::iter::once(0..host_page_size).collect(),
        )
        .unwrap();

        let memory = SnapshotMemory::new(Box::new([upper, lower]), stub_page_tables()).unwrap();

        assert_eq!(memory.layers()[0].blob().gpa_start(), base);
    }

    #[test]
    fn resolve_accepts_live_edges_and_rejects_holes() {
        let host_page_size = page_size::get();
        let gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let layer = SnapshotLayer::new(
            blob(3, gpa),
            Box::new([0..host_page_size, 2 * host_page_size..3 * host_page_size]),
        )
        .unwrap();
        let memory = SnapshotMemory::new(Box::new([layer]), stub_page_tables()).unwrap();

        assert_eq!(memory.resolve(gpa, 1), Some((0, 0)));
        assert_eq!(
            memory.resolve(gpa + (3 * host_page_size - 1) as u64, 1),
            Some((0, 3 * host_page_size - 1))
        );
        assert_eq!(memory.resolve(gpa + host_page_size as u64, 1), None);
        assert_eq!(memory.resolve(gpa + (host_page_size - 1) as u64, 2), None);
    }

    #[test]
    fn sparse_reads_reject_holes_and_addresses_past_the_blob() {
        let host_page_size = page_size::get();
        let gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let layer = SnapshotLayer::new(
            blob(3, gpa),
            Box::new([0..host_page_size, 2 * host_page_size..3 * host_page_size]),
        )
        .unwrap();
        let memory = SnapshotMemory::new(Box::new([layer]), stub_page_tables()).unwrap();
        let (backing, _) = SnapshotMemoryBacking::from_snapshot(Arc::new(memory))
            .unwrap()
            .build();
        let mut byte = [0u8; 1];

        assert!(
            backing
                .read_snapshot_gpa(gpa + host_page_size as u64 + 1, &mut byte)
                .is_err()
        );
        assert!(
            backing
                .read_snapshot_gpa(gpa + 3 * host_page_size as u64 + 1, &mut byte)
                .is_err()
        );
    }

    #[test]
    fn memory_rejects_excess_mappings() {
        let host_page_size = page_size::get();
        let gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let data_pages = 2 * MAX_SNAPSHOT_MAPPINGS + 1;
        let live_data = (0..=MAX_SNAPSHOT_MAPPINGS)
            .map(|index| {
                let start = 2 * index * host_page_size;
                start..start + host_page_size
            })
            .collect();
        let layer = SnapshotLayer::new(blob(data_pages, gpa), live_data).unwrap();

        assert!(SnapshotMemory::new(Box::new([layer]), stub_page_tables()).is_err());
    }

    #[test]
    fn layer_rejects_unaligned_range() {
        let host_page_size = page_size::get();
        let blob = blob(1, SandboxMemoryLayout::BASE_ADDRESS as u64);
        for range in [1..host_page_size, 0..host_page_size - 1] {
            assert!(SnapshotLayer::new(blob.clone(), Box::new([range])).is_err());
        }
        if host_page_size > PAGE_SIZE {
            assert!(
                SnapshotLayer::new(blob, std::iter::once(PAGE_SIZE..host_page_size).collect())
                    .is_err()
            );
        }
    }

    #[test]
    fn layer_maps_partial_tail_up_to_blob_end() {
        let host_page_size = page_size::get();
        if host_page_size == PAGE_SIZE {
            return;
        }
        let layer = SnapshotLayer::new(
            blob(2, SandboxMemoryLayout::BASE_ADDRESS as u64),
            std::iter::once(host_page_size..host_page_size + PAGE_SIZE).collect(),
        )
        .unwrap();
        let padding_gpa = layer.blob().gpa_start() + (host_page_size + PAGE_SIZE) as u64;

        assert!(
            layer
                .mapped_ranges()
                .eq(std::iter::once(host_page_size..2 * host_page_size))
        );
        assert_eq!(layer.resolve(padding_gpa, 1), None);
    }

    #[test]
    fn layer_rejects_partial_end_before_last_host_page() {
        let host_page_size = page_size::get();
        if host_page_size == PAGE_SIZE {
            return;
        }
        let blob = blob(2, SandboxMemoryLayout::BASE_ADDRESS as u64);
        assert!(SnapshotLayer::new(blob.clone(), std::iter::once(0..PAGE_SIZE).collect()).is_err());
        assert!(
            SnapshotLayer::new(
                blob,
                Box::new([0..PAGE_SIZE, host_page_size..2 * host_page_size])
            )
            .is_err()
        );
    }

    #[test]
    fn layer_rejects_range_past_blob() {
        let blob = blob(1, SandboxMemoryLayout::BASE_ADDRESS as u64);
        assert!(
            SnapshotLayer::new(blob, std::iter::once(0..2 * page_size::get()).collect()).is_err()
        );
    }
}
