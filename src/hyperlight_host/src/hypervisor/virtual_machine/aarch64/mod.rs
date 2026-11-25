// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use crate::mem::mgr::GuestPhysicalMemoryView;
use crate::sandbox::snapshot::PageTableReader;

/// Translates a stopped guest's address and rejects unbacked physical memory.
pub(crate) fn translate_gva(
    memory: &GuestPhysicalMemoryView<'_>,
    gva: u64,
    root_pt: u64,
) -> crate::Result<u64> {
    let reader = PageTableReader::new(memory, root_pt);
    // SAFETY: Debug requests run with the vCPU stopped. The reader bounds-checks table accesses.
    let mapping = unsafe { hyperlight_common::vmem::virt_to_phys(&reader, gva, 1) }.next();
    reader.finish()?;
    let gpa = mapping
        .filter(|mapping| {
            matches!(
                mapping.kind,
                hyperlight_common::vmem::MappingKind::Basic(_)
                    | hyperlight_common::vmem::MappingKind::Cow(_)
            )
        })
        .and_then(|mapping| {
            let offset = gva.checked_sub(mapping.virt_base)?;
            (offset < mapping.len)
                .then(|| mapping.phys_base.checked_add(offset))
                .flatten()
        })
        .filter(|&gpa| memory.resolve(gpa, 1).is_some());
    gpa.ok_or_else(|| crate::new_error!("GVA is not mapped: {gva:#x}"))
}
