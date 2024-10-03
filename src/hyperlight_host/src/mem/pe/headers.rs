use super::pe_info::PEInfo;

/// An immutable set of PE File headers.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct PEHeaders {
    /// Stack reserve size.
    pub(super) stack_reserve: u64,

    /// Stack commit size.
    pub(super) stack_commit: u64,

    /// Heap reserve size.
    pub(super) heap_reserve: u64,

    /// Heap commit size.
    pub(super) heap_commit: u64,

    /// Entrypoint offset.
    pub(crate) entrypoint_offset: u64,

    /// Preferred load address.
    pub(super) preferred_load_address: u64,
}

impl From<&PEInfo> for PEHeaders {
    fn from(pe_info: &PEInfo) -> PEHeaders {
        PEHeaders {
            entrypoint_offset: pe_info.entry_point_offset(),
            stack_reserve: pe_info.stack_reserve(),
            stack_commit: pe_info.stack_commit(),
            heap_reserve: pe_info.heap_reserve(),
            heap_commit: pe_info.heap_commit(),
            preferred_load_address: pe_info.preferred_load_address(),
        }
    }
}
