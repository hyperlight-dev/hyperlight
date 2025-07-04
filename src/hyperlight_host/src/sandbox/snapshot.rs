use crate::mem::shared_mem_snapshot::SharedMemorySnapshot;

/// A snapshot capturing the state of the memory in a `MultiUseSandbox`.
#[derive(Clone)]
pub struct Snapshot {
    /// TODO: Use Arc<SharedMemorySnapshot>
    pub(crate) inner: SharedMemorySnapshot,
}
