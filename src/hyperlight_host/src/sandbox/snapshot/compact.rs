// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use super::memory::host_page_size;
use super::*;

impl Snapshot {
    /// Compacts live memory into a new snapshot without changing this snapshot.
    ///
    /// With no `base`, live pages are packed into a single memory layer. With a
    /// base, referenced layers identical to the base's layers are retained,
    /// including their serialized blob contents; other live pages are packed
    /// into at most one new memory layer. Intermediate snapshots are not needed
    /// to save or restore the result.
    ///
    /// Base layers are matched by GPA, geometry, and complete blob contents,
    /// not pointer identity, so a separately loaded base can be used. Unused
    /// layers and unreferenced pages in merged layers are discarded, except
    /// for minimal padding required by the snapshot format. Retained base
    /// layers are kept whole.
    /// The result records this snapshot and the specified base as ancestors,
    /// including their inherited bases, for [`Snapshot::load_overlay`]. Provenance
    /// does not require retaining any otherwise unused layer.
    ///
    /// Registers, metadata, transport state, generation, and page-table roots
    /// are preserved. The result uses the existing snapshot file format.
    ///
    /// # Errors
    ///
    /// Returns an error if the base has a different memory layout, allocation
    /// fails, or the compacted memory cannot fit within the address-space or
    /// layer limits.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub fn compact(&self, base: Option<&Snapshot>) -> Result<Arc<Self>> {
        if let Some(base) = base
            && self.state.layout != base.state.layout
        {
            return Err(crate::new_error!(
                "compaction base has an incompatible memory layout"
            ));
        }

        let memory = &self.state.memory;
        let preserve: Vec<bool> = memory
            .layers()
            .iter()
            .map(|layer| {
                base.is_some_and(|base| {
                    base.state.memory.layers().iter().any(|candidate| {
                        Arc::ptr_eq(layer, candidate)
                            || (layer.gpa_start() == candidate.gpa_start()
                                && layer.data_len() == candidate.data_len()
                                && layer.page_table_len() == candidate.page_table_len()
                                && layer.memory().as_slice() == candidate.memory().as_slice())
                    })
                })
            })
            .collect();
        let mut reused = vec![false; preserve.len()];
        let mut pages = Vec::new();
        let mut page_tables = memory.page_table_bytes().to_vec();

        // Snapshot tables use guest-page leaves. Intermediate-table pointers,
        // scratch, and IO mappings lie outside the data layers. Visiting every
        // entry preserves all roots and shared tables at their original GPAs.
        for bytes in page_tables.as_chunks::<PTE_SIZE>().0 {
            let entry = vmem::PageTableEntry::from_le_bytes(*bytes);
            if entry & vmem::PAGE_PRESENT == 0 {
                continue;
            }
            let gpa = entry & vmem::PTE_ADDR_MASK;
            if let Some((index, offset)) = memory.resolve(gpa, PAGE_SIZE) {
                if preserve[index] {
                    reused[index] = true;
                } else {
                    pages.push(NewPage {
                        source_gpa: gpa,
                        backing: GuestBacking {
                            source: BackingSource::Snapshot(index),
                            offset,
                        },
                    });
                }
            }
        }
        pages.sort_unstable_by_key(|page| page.source_gpa);
        pages.dedup_by_key(|page| page.source_gpa);
        let mut layers: Vec<_> = memory
            .layers()
            .iter()
            .zip(reused)
            .filter(|(_, reused)| *reused)
            .map(|(layer, _)| layer.clone())
            .collect();
        let alignment = host_page_size();
        let data_len = packed_data_len(pages.len(), alignment)?;
        let base_gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let required_memory_size = self.state.layout.get_memory_size()?;
        let preserves_span = layers
            .last()
            .is_some_and(|layer| layer.gpa_range().end - base_gpa >= required_memory_size as u64);
        // The loader requires the GPA span to cover the original code region.
        // Place packed data high enough without retaining unused code bytes.
        let data_len = if !preserves_span && data_len == 0 {
            alignment
        } else {
            data_len
        };
        let minimum_gpa = if preserves_span {
            base_gpa
        } else {
            base_gpa + required_memory_size.saturating_sub(data_len) as u64
        };
        let scratch_base = scratch_base_gpa(self.state.layout.get_scratch_size());
        let new_gpa = if data_len == 0 {
            None
        } else {
            Some(
                first_fit_blob_gpa(data_len, &layers, minimum_gpa, scratch_base)
                    .ok_or_else(|| crate::new_error!("no address space for compacted memory"))?,
            )
        };
        let runs = match new_gpa {
            Some(gpa) => new_page_runs(&pages, gpa)?,
            None => Vec::new(),
        };
        for bytes in page_tables.as_chunks_mut::<PTE_SIZE>().0 {
            let entry = vmem::PageTableEntry::from_le_bytes(*bytes);
            if entry & vmem::PAGE_PRESENT != 0
                && let Some(destination) = page_destination(&runs, entry & vmem::PTE_ADDR_MASK)
            {
                *bytes = ((entry & !vmem::PTE_ADDR_MASK) | destination).to_le_bytes();
            }
        }
        let blob_len = data_len
            .checked_add(page_tables.len())
            .and_then(|len| len.checked_next_multiple_of(alignment))
            .ok_or_else(|| crate::new_error!("compacted snapshot size overflows"))?;
        let mut allocation = ExclusiveSharedMemory::new(blob_len)?;
        for copy in new_page_copies(&pages)? {
            let BackingSource::Snapshot(index) = copy.backing.source else {
                return Err(crate::new_error!(
                    "compaction source is not snapshot memory"
                ));
            };
            let source = memory.layers()[index]
                .memory()
                .as_slice()
                .get(copy.backing.offset..)
                .and_then(|source| source.get(..copy.destination.len()))
                .ok_or_else(|| crate::new_error!("compaction source range is out of bounds"))?;
            allocation.copy_from_slice(source, copy.destination.start)?;
        }
        allocation.copy_from_slice(&page_tables, data_len)?;
        let blob = Arc::new(SnapshotBlob::new(
            allocation.freeze(data_len)?,
            new_gpa.unwrap_or_default(),
            page_tables.len(),
            scratch_base,
        )?);
        if data_len > 0 {
            layers.push(blob.clone());
        }
        let mut memory = SnapshotMemory::new(layers.into_boxed_slice(), blob)?;
        memory.record_base(self.snapshot_memory());
        if let Some(base) = base {
            memory.record_base(base.snapshot_memory());
        }
        Ok(Arc::new(Self {
            state: Arc::new(SnapshotState {
                memory: Arc::new(memory),
                ..(*self.state).clone()
            }),
            metadata: self.metadata.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::shared_mem::ReadonlySharedMemory;

    fn layered_snapshot() -> Snapshot {
        let layout = SandboxMemoryLayout::new(SandboxConfiguration::default(), PAGE_SIZE).unwrap();
        let start = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let alignment = host_page_size();
        let pt = GuestPageTableBuffer::new(layout.get_pt_base_gpa() as usize);
        let kinds = [
            MappingKind::Basic(BasicMapping {
                readable: true,
                writable: false,
                executable: true,
            }),
            MappingKind::Cow(CowMapping {
                readable: true,
                executable: false,
            }),
            MappingKind::Cow(CowMapping {
                readable: true,
                executable: false,
            }),
            MappingKind::ZeroInit(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        ];
        for (index, kind) in kinds.into_iter().enumerate() {
            // SAFETY: The local buffer has no concurrent access and mappings
            // are aligned guest pages.
            unsafe {
                vmem::map(
                    &pt,
                    Mapping {
                        phys_base: start + if index == 0 { 0 } else { 4 * alignment as u64 },
                        virt_base: start + (index * PAGE_SIZE) as u64,
                        len: PAGE_SIZE as u64,
                        kind,
                    },
                );
            }
        }
        map_specials(&pt, layout.get_scratch_size());
        let layers = [0x11, 0x22, 0x33]
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                let bytes = vec![value; 2 * alignment];
                Arc::new(
                    SnapshotBlob::new(
                        ReadonlySharedMemory::from_bytes(&bytes, bytes.len()).unwrap(),
                        start + (index * 4 * alignment) as u64,
                        0,
                        scratch_base_gpa(layout.get_scratch_size()),
                    )
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        Snapshot {
            state: Arc::new(SnapshotState {
                memory: Arc::new(
                    SnapshotMemory::new(
                        layers.into_boxed_slice(),
                        super::super::memory::tests::page_tables_from_bytes(&pt.into_bytes()),
                    )
                    .unwrap(),
                ),
                layout,
                load_info: LoadInfo::dummy(),
                stack_top_gva: start,
                sregs: None,
                #[cfg(target_arch = "x86_64")]
                msrs: None,
                next_action: NextAction::None,
                original_entrypoint: start,
                snapshot_generation: 7,
                host_functions: HostFunctionDetails::default(),
                virtq: None,
            }),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn compact_packs_live_pages_and_preserves_aliases_and_permissions() {
        let original = layered_snapshot();
        let start = SandboxMemoryLayout::BASE_ADDRESS as u64;
        for preserve in [false, true] {
            let compacted = original.compact(preserve.then_some(&original)).unwrap();
            let memory = &compacted.state.memory;
            assert_eq!(memory.layers().len(), if preserve { 2 } else { 1 });
            assert_eq!(
                memory
                    .layers()
                    .iter()
                    .map(|layer| layer.data_len())
                    .sum::<usize>(),
                if preserve {
                    4 * host_page_size()
                } else {
                    packed_data_len(2, host_page_size()).unwrap()
                }
            );
            // SAFETY: Both immutable snapshots own their page tables.
            let before = unsafe { vmem::virt_to_phys(&original, start, 4 * PAGE_SIZE as u64) }
                .collect::<Vec<_>>();
            let after =
                unsafe { vmem::virt_to_phys(compacted.as_ref(), start, 4 * PAGE_SIZE as u64) }
                    .collect::<Vec<_>>();
            assert_eq!(before.len(), after.len());
            for (index, (before, after)) in before.iter().zip(&after).enumerate() {
                assert_eq!(before.virt_base, after.virt_base);
                assert_eq!(before.kind, after.kind);
                if index < 3 {
                    let (layer, offset) = memory.resolve(after.phys_base, PAGE_SIZE).unwrap();
                    assert_eq!(
                        &memory.layers()[layer].memory().as_slice()[offset..offset + PAGE_SIZE],
                        vec![if index == 0 { 0x11 } else { 0x22 }; PAGE_SIZE]
                    );
                }
            }
            assert_eq!(after[1].phys_base, after[2].phys_base);
            if preserve {
                for (actual, expected) in memory.layers().iter().zip(original.state.memory.layers())
                {
                    assert!(Arc::ptr_eq(actual, expected));
                }
                assert_eq!(memory.page_table_blob().data_len(), 0);
            }
            assert_eq!(compacted.snapshot_generation(), 7);
        }
        assert_eq!(original.state.memory.layers().len(), 3);
    }

    #[test]
    fn compact_preserves_sparse_code_span_with_and_without_base_layers() {
        let mut original = layered_snapshot();
        let alignment = host_page_size();
        original.state = Arc::new(SnapshotState {
            layout: SandboxMemoryLayout::new(SandboxConfiguration::default(), 10 * alignment)
                .unwrap(),
            ..(*original.state).clone()
        });
        for preserve in [false, true] {
            let compacted = original.compact(preserve.then_some(&original)).unwrap();
            let memory = &compacted.state.memory;
            assert_eq!(memory.layers().len(), if preserve { 3 } else { 1 });
            assert!(memory.gpa_span_len() >= 10 * alignment);
            assert!(
                memory
                    .layers()
                    .iter()
                    .map(|layer| layer.data_len())
                    .sum::<usize>()
                    < 10 * alignment
            );
            if preserve {
                for (actual, expected) in memory.layers()[..2]
                    .iter()
                    .zip(original.state.memory.layers())
                {
                    assert!(Arc::ptr_eq(actual, expected));
                }
                let padding = memory.layers().last().unwrap();
                assert_eq!(padding.data_len(), alignment);
                assert!(
                    padding.memory().as_slice()[..alignment]
                        .iter()
                        .all(|byte| *byte == 0)
                );
            }
        }
    }

    #[test]
    fn compact_rejects_incompatible_base_layout() {
        let current = layered_snapshot();
        let mut state = (*current.state).clone();
        state.layout = state
            .layout
            .with_scratch_size(2 * state.layout.get_scratch_size())
            .unwrap();
        let base = Snapshot {
            state: Arc::new(state),
            metadata: BTreeMap::new(),
        };
        let error = current.compact(Some(&base)).err().unwrap();
        assert!(error.to_string().contains("incompatible memory layout"));
    }

    #[test]
    fn compact_preserves_only_identical_base_blobs() {
        let base = layered_snapshot();
        let mut current = layered_snapshot();
        let mut layers = current.state.memory.layers().to_vec();
        let replaced = &layers[1];
        layers[1] = Arc::new(
            SnapshotBlob::new(
                ReadonlySharedMemory::from_bytes(
                    &vec![0x44; replaced.data_len()],
                    replaced.data_len(),
                )
                .unwrap(),
                replaced.gpa_start(),
                0,
                scratch_base_gpa(current.state.layout.get_scratch_size()),
            )
            .unwrap(),
        );
        current.state = Arc::new(SnapshotState {
            memory: Arc::new(
                SnapshotMemory::new(
                    layers.into_boxed_slice(),
                    current.state.memory.page_table_blob().clone(),
                )
                .unwrap(),
            ),
            ..(*current.state).clone()
        });
        let compacted = current.compact(Some(&base)).unwrap();
        let layers = compacted.state.memory.layers();
        assert_eq!(layers.len(), 2);
        assert!(Arc::ptr_eq(&layers[0], &current.state.memory.layers()[0]));
        assert!(!Arc::ptr_eq(&layers[0], &base.state.memory.layers()[0]));
        assert_eq!(
            layers[0].memory().as_slice(),
            base.state.memory.layers()[0].memory().as_slice()
        );
        assert_eq!(layers[1].data_len(), host_page_size());
        assert_eq!(
            &layers[1].memory().as_slice()[..PAGE_SIZE],
            vec![0x44; PAGE_SIZE]
        );
    }
}
