# HIP 0002 - Memory-Efficient File Mapping

<!-- toc -->

- [Summary](#summary)
- [Motivation](#motivation)
    - [Goals](#goals)
    - [Non-Goals](#non-goals)
- [Proposal](#proposal)
    - [User Stories](#user-stories)
        - [Story 1: High-Density Serverless Deployment](#story-1-high-density-serverless-deployment)
        - [Story 2: Memory-Mapped Data Files](#story-2-memory-mapped-data-files)
    - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
    - [Comparison with Current Implementation](#comparison-with-current-implementation)
    - [Binary Caching](#binary-caching)
    - [User Files](#user-files)
    - [Mapping Modes](#mapping-modes)
    - [Lazy Page Table Creation](#lazy-page-table-creation)
    - [Guest Page Fault Handler](#guest-page-fault-handler)
    - [Snapshot Integration](#snapshot-integration)
- [Test Plan](#test-plan)
- [Implementation History](#implementation-history)
- [Drawbacks](#drawbacks)
<!-- /toc -->

## Summary

This HIP proposes a memory-efficient file mapping infrastructure for Hyperlight that enables
sharing the guest binary across multiple sandboxes while maintaining isolation through guest-side
copy-on-write (COW). The design extends Hyperlight's existing `map_file_cow` capability (which
currently only supports host-side COW via `MAP_PRIVATE` and does not integrate with snapshots)
to provide:

1. **Shared binary mapping** - The relocated binary is cached and mmap'd once, then shared across
   all sandboxes via hypervisor memory slots
2. **Unified file mapping** - Guest binaries and user files use the same mapping infrastructure,
   with configurable read-only or read-write (COW) modes
3. **Guest-side COW for user files** - User-mapped files can now be written to, with writes
   triggering guest-side COW that properly integrates with snapshot/restore
4. **Lazy page table creation** - Guest page tables are populated on-demand via page faults,
   avoiding the cost of creating PTEs for pages that are never accessed
5. **Bootstrap code refactoring** - The existing guest initialization code is refactored into
   an eagerly-mapped stub, ensuring the page fault handler is installed before any lazy
   page access occurs
6. **Snapshot integration** - The mapping infrastructure integrates with snapshot/restore,
   designed to support future snapshot persistence to disk

The design supports both Linux (KVM, MSHV) and Windows (WHP) platforms.

## Motivation

Hyperlight currently loads guest binaries inefficiently. When creating a sandbox:

1. The guest ELF is loaded and relocated
2. The entire binary is copied into a `Vec<u8>` snapshot
3. Each sandbox gets its own copy of this snapshot
4. The snapshot is used for both initialization and restore operations

This approach has several problems:

- **Memory waste**: Read-only segments (executable code, read-only data) are identical across all sandboxes,
  yet each maintains its own copy. Worse, each sandbox also keeps a `Vec<u8>` snapshot of its
  memory, effectively doubling the overhead. For example, with 1000 sandboxes on a host:
  - `hyperlight-js` (~1.7MB) × 1000 × 2 = **3.4GB** for identical binaries (sandbox + snapshot)
  - `wasm_runtime` (~1.25MB) × 1000 × 2 = **2.5GB** for identical binaries (sandbox + snapshot)
- **Inefficient creation**: Copying the binary for each sandbox wastes CPU cycles. This is
  particularly noticeable in debug builds where binaries are much larger (~43MB for `wasm_runtime`,
  ~20MB for `hyperlight-js`).
- **Density limits**: Memory scales linearly with sandbox count, capping how many sandboxes
  can run on a single host.
- **Inefficient snapshots**: Every snapshot contains a full `Vec<u8>` copy of the sandbox's
  memory image, duplicating the binary yet again. This wastes memory and would make future
  snapshot persistence larger than necessary.

### Goals

1. **Share read-only content**: Map the binary once, share across sandboxes via page tables
2. **Maintain isolation**: Each sandbox has isolated writable state via guest-side COW
3. **Unify file handling**: Guest binary and user files use the same infrastructure
4. **Lazy PTE creation**: Only create page table entries for pages actually accessed
5. **Snapshot integration**: Track mapped files and dirty pages for correct restore
6. **Future-proof for persistence**: Design supports eventual snapshot serialization to disk
7. **Cross-platform**: Support Linux (KVM, MSHV) and Windows (WHP)

### Non-Goals

1. **Snapshot persistence to disk**: This HIP focuses on in-process snapshot/restore, though
   the design prepares for future disk persistence (content hashing, serializable metadata).
2. **Cross-sandbox restore**: Snapshots restore to the same sandbox instance that created them.
   Cross-sandbox restore is a future enhancement.
3. **OCI image format**: Packaging and distribution is out of scope for this HIP.
4. **Live migration**: Moving running sandboxes between hosts is out of scope.

## Proposal

We propose extending Hyperlight's memory management to support shared, memory-mapped files with
guest-side copy-on-write. The guest binary becomes a special case of a mapped file - it's cached
after relocation and shared across all sandboxes using it.

Hypervisor memory slots (KVM) or regions (MSHV/WHP) can map the same host memory into multiple guest address spaces. Combined with guest-side page fault handling, this enables efficient sharing with isolation.

### User Stories

#### Story 1: High-Density Serverless Deployment

As a serverless platform operator, I want to run hundreds of sandboxes executing the same
WebAssembly runtime binary so that I can maximize concurrent function invocations per host
while minimizing memory overhead.

**Current behavior**: Each sandbox copies the full binary, plus keeps a snapshot copy.
1000 sandboxes × `wasm_runtime` (1.25MB) × 2 = 2.5GB for identical binaries.

**Proposed behavior**: One shared 1.25MB mapping + bootstrap/page tables (maybe 64KB per sandbox?) +
per-sandbox dirty pages. Memory scales with actual writes, not sandbox count.

#### Story 2: Memory-Mapped Data Files with COW

As an application developer, I want to map a configuration or data file into my sandbox
and be able to modify it, with changes isolated per-sandbox and properly preserved across
snapshot/restore cycles.

**Current behavior**: `map_file_cow` maps files as read-only (no WRITE permission). The file
content is copied into snapshots, negating the memory-sharing benefit (see `guest_page()` and
`snapshot_memory.extend(contents)` in `snapshot.rs`).

**Proposed behavior**: Unified file mapping with guest-side COW that allows writes while
maintaining sharing. Unmodified pages remain shared; only written pages are copied into snapshots.
Files are locked (shared/read lock) while mapped to prevent external modification or deletion.
Since snapshots are in-process only, the mmap'd file remains valid for the snapshot's lifetime.
Future disk persistence would copy user files into the cache at persistence time - these cached
copies would be shared across all persisted snapshots referencing the same content (validated via
content hash).

### Risks and Mitigations

**Risk**: Guest page fault handler bugs could cause security vulnerabilities or crashes.

**Mitigation**: The handler is minimal and well-defined. It validates addresses against a
region table built during initialization. Invalid accesses terminate the sandbox, not the host.
Testing validates correctness.

**Risk**: Lazy PTE creation adds latency to first access of each page.

**Mitigation**: The page fault cost is amortized across the page lifetime. Importantly, PTEs
are preserved across snapshot/restore cycles - once a page is faulted in, it remains mapped
after restore. If a sandbox reaches steady state (all needed pages accessed) before taking a
snapshot, subsequent restores incur no page fault overhead. For most workloads, the memory
savings outweigh the fault overhead. Benchmarking will validate this assumption. If needed,
we could add an option for eager PTE creation for latency-sensitive workloads.

**Risk**: Cache files deleted or corrupted.

**Mitigation**: On Linux, mmap'd files remain accessible even if deleted from the filesystem
(data persists until unmapped). On Windows, open file handles prevent deletion. Files are
locked while mapped to prevent external modification. Cache integrity is operator responsibility.

**Risk**: Cache management burden on users.

**Mitigation**: Cache location is well-documented. Cache entries are keyed by content hash,
so stale entries are naturally replaced. A cache cleanup utility can be provided in the future.

**Risk**: Extending guest-side page fault handler.

**Mitigation**: The existing page fault handler already implements COW for stack expansion
(PR #1205) and snapshot region writes. File-backed COW uses the same pattern: fault →
allocate private page → copy → update PTE → resume. The extension adds region table lookup
which is O(n) with small n (typically <10 regions).

## Design Details

### Comparison with Current Implementation

**Current approach:**

```
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   Sandbox 1   │     │   Sandbox 2   │     │   Sandbox 3   │
├───────────────┤     ├───────────────┤     ├───────────────┤
│  Binary Copy  │     │  Binary Copy  │     │  Binary Copy  │
│   (1.25 MB)   │     │   (1.25 MB)   │     │   (1.25 MB)   │
├───────────────┤     ├───────────────┤     ├───────────────┤
│   Snapshot    │     │   Snapshot    │     │   Snapshot    │
│   (1.25 MB)   │     │   (1.25 MB)   │     │   (1.25 MB)   │
├───────────────┤     ├───────────────┤     ├───────────────┤
│ Heap/Stack/etc│     │ Heap/Stack/etc│     │ Heap/Stack/etc│
└───────────────┘     └───────────────┘     └───────────────┘

Total memory: N × (2 × binary_size) + N × heap/stack/etc size
```

**Proposed approach:**

```
                    ┌─────────────────────────────────┐
                    │     Shared Binary (mmap'd)      │
                    │            (1.25 MB)            │
                    └───────────┬─────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│   Sandbox 1   │       │   Sandbox 2   │       │   Sandbox 3   │
├───────────────┤       ├───────────────┤       ├───────────────┤
│  Bootstrap +  │       │  Bootstrap +  │       │  Bootstrap +  │
│  Page Tables  │       │  Page Tables  │       │  Page Tables  │
│   (~64 KB)    │       │   (~64 KB)    │       │   (~64 KB)    │
├───────────────┤       ├───────────────┤       ├───────────────┤
│  Dirty Pages  │       │  Dirty Pages  │       │  Dirty Pages  │
├───────────────┤       ├───────────────┤       ├───────────────┤
│ Heap/Stack/etc│       │ Heap/Stack/etc│       │ Heap/Stack/etc│
└───────────────┘       └───────────────┘       └───────────────┘

Total memory: 1 × binary_size + N × (bootstrap + dirty_pages + heap/stack/etc size)
```

| Aspect | Current | Proposed |
|--------|---------|----------|
| Memory for binary (N sandboxes) | N × 2B (sandbox + snapshot) | B + (N × D) |
| Sandbox creation time | O(B) copy | O(1) slot setup |
| Page table creation | Eager (all PTEs) | Lazy (on-demand) |
| Snapshot size | Full memory image | File refs + dirty pages |
| Binary isolation | Private copy per sandbox | Shared + COW on write |

Where B = binary size, D = dirty pages per sandbox.

**Bootstrap code**: The "Bootstrap" shown in the diagram is a small stub injected by
the host at sandbox creation time (not linked into the guest binary). This is a
refactoring of the existing guest initialization code in `hyperlight_guest`. The
bootstrap performs minimal initialization (set stack pointer, install IDT with page
fault handler) then calls `hyperlight_main` in the guest binary. The bootstrap must
be eagerly mapped by the host because it executes before the guest can handle page
faults. It's mapped at a fixed GPA known to both host and guest.

### Binary Caching

Relocated binaries are cached on disk so they can be mmap'd and shared across sandboxes.
The file must exist on disk (not just in memory) because hypervisor memory slots require
a host virtual address backed by a file mapping:

```
~/.cache/hyperlight/binaries/
├── <source-hash>-<load-addr>.bin    # Relocated binary (still valid ELF)
└── ...
```

The cache key combines the source binary hash and load address, since relocation is
address-dependent.

**Note on future ASLR**: This design does not address base address randomization.
Per-sandbox ASLR would negate the memory sharing benefits. If ASLR is required in the
future, options such as a pool of pre-relocated variants or guest-side relocation should
be considered.

**Future extension for snapshot persistence**: When snapshot persistence to disk is
implemented, this cache will be extended to store user data files as well. At persistence
time, user-mapped files would be copied into the cache (keyed by content hash), allowing
persisted snapshots to reference stable, immutable file content rather than paths or content that
may change. Multiple snapshots referencing the same file content would share the cached
copy.

```rust
pub struct BinaryCache {
    cache_dir: PathBuf,
    /// In-memory cache of path → content hash, so we only hash and relocate each file
    /// once per process. Benefits:
    /// - Avoids re-hashing and re-relocating the same binary
    /// - Allows the original binary to be deleted after first access
    /// - Subsequent sandbox creations use the cached relocated copy
    ///
    /// Trade-off: If the binary changes on disk after first access, the process will
    /// continue using the original version. This is typically desirable for consistency
    /// within a process lifetime.
    path_to_hash: Mutex<HashMap<PathBuf, ContentHash>>,
}

impl BinaryCache {
    /// Get or create a cached relocated binary.
    /// Returns an mmap'd read-only view of the binary.
    ///
    /// The cache key is `<content-hash>-<load-addr>.bin`. The content hash is
    /// computed from the source binary on first access and cached in memory,
    /// so subsequent calls don't need to read or hash the original file.
    pub fn get_or_create(
        &self,
        source_path: &Path,
        load_address: u64,
    ) -> Result<(MappedBinary, ContentHash)> {
        // Check in-memory path→hash cache first
        let source_hash = {
            let cache = self.path_to_hash.lock().unwrap();
            cache.get(source_path).cloned()
        };

        let source_hash = match source_hash {
            Some(hash) => hash,
            None => {
                // First time seeing this path - hash the file and cache it
                let hash = hash_file(source_path)?;
                let mut cache = self.path_to_hash.lock().unwrap();
                cache.insert(source_path.to_owned(), hash.clone());
                hash
            }
        };

        // Try to open existing cached binary
        if let Ok(mapped) = self.open_by_hash(&source_hash, load_address) {
            return Ok((mapped, source_hash));
        }

        // Cache miss - relocate and cache (requires original file to still exist)
        let relocated = relocate_binary(source_path, load_address)?;
        let cache_path = self.cache_path(&source_hash, load_address);
        std::fs::write(&cache_path, &relocated)?;

        Ok((self.open_by_hash(&source_hash, load_address)?, source_hash))
    }

    /// Open a previously cached binary by its content hash.
    /// Used when restoring from a snapshot that references the binary by hash,
    /// or when creating additional sandboxes after the original file was deleted.
    pub fn open_by_hash(
        &self,
        content_hash: &ContentHash,
        load_address: u64,
    ) -> Result<MappedBinary> {
        let cache_path = self.cache_path(content_hash, load_address);
        MappedBinary::open(&cache_path)
    }

    fn cache_path(&self, content_hash: &ContentHash, load_address: u64) -> PathBuf {
        let cache_key = format!("{}-{:x}.bin", content_hash, load_address);
        self.cache_dir.join(&cache_key)
    }
}

pub struct MappedBinary {
    mmap: memmap2::Mmap,
}
```

**Trade-offs:**

- (+) Avoids repeated relocation work across sandbox creations
- (+) Enables sharing via mmap (kernel page cache deduplicates across processes)
- (+) Original binary can be deleted after first sandbox creation
- (+) Binary changes on disk don't affect running process (consistent behavior)
- (-) Disk space usage for cached binaries
- (-) Stale cache entry cleanup is user's responsibility
- (-) Binary updates require process restart to take effect

**Alternatives considered:**

1. **Content-addressable storage (CAS)**: Stores deduplicated chunks/sections, allowing
   sharing across different binaries with common content. Rejected because Hyperlight
   guests are monolithic images unlikely to share content across different binaries - 
   simple hash-based cache is sufficient.

### User Files

Unlike guest binaries, **user-provided files are not cached** - they are mmap'd directly
from the path specified by the user via `map_file()`. This is because:

1. User files don't require relocation (no address-dependent processing)
2. User files may be large data files that shouldn't be copied to cache - but will need to be in future to support snapshot persistence
3. The same file may be mapped by multiple sandboxes (shared via kernel page cache)

**File locking**: Files are locked (shared/read lock) while mapped to prevent external
modification. Multiple processes can map the same file simultaneously since all mappings
are read-only at the host level (writes go through COW). The lock is released when the
sandbox is dropped or the file is unmapped.

**Snapshot considerations**: For in-process snapshot/restore, user files remain mmap'd -
the file handles are still valid. On restore, the content hash is validated to detect
if the file was modified (which would indicate a bug, since files should be locked).
Future disk persistence will need to cache user files with the
snapshot - this is out of scope for this HIP.

### Mapping Modes

Three mapping modes are supported, with the guest binary having special handling:

```rust
pub enum FileMappingMode {
    /// Read-only mapping. Writes from guest cause fault and sandbox termination.
    /// Used for read-only data files.
    ReadOnly,

    /// Read-write with copy-on-write. First write to each page creates private copy.
    /// Entire mapping has uniform RW permissions. Used for user data files.
    ReadWriteCow,

    /// Guest binary with per-segment permissions and COW for writable segments.
    /// Segment metadata is read directly from the cached ELF file's PT_LOAD headers.
    /// Typical layout: RX segment (code) → R-X, RW segment (data) → RW- with COW.
    GuestBinary,
}

/// Serializable metadata about a file mapping, stored in snapshots.
/// For in-process restore, the sandbox still has the mmap handles open, so
/// we only need the hash (for validation) and GPA range (for `is_file_backed_gpa`).
///
/// For future disk persistence, this struct would need to include either:
/// - The source path (to re-open the file), or
/// - A cache key (if user files are copied into the cache at persistence time)
pub struct FileMappingInfo {
    /// Content hash for validation on restore (detects unexpected file changes)
    pub content_hash: Hash,

    /// Guest address where file is mapped (GVA == GPA in Hyperlight's identity-mapped layout)
    pub guest_address: u64,

    /// Size of the mapping
    pub size: u64,

    /// Mapping mode
    pub mode: FileMappingMode,
}
```

For user file mappings at runtime, we also need to track the source path (for error messages
and potential future disk persistence):

```rust
/// Runtime state for a user file mapping. The `MappedFile` (holding the mmap handle)
/// is stored in `SandboxMemoryManager`. This struct tracks the metadata needed for
/// the region table and snapshots.
pub struct UserFileMapping {
    /// Metadata stored in snapshots
    pub info: FileMappingInfo,

    /// Source path - kept for error messages and future disk persistence
    pub source_path: PathBuf,

    /// The mmap'd file (stored here or in SandboxMemoryManager)
    pub mapped_file: Arc<MappedFile>,
}

The guest binary loading changes in `Snapshot::from_env()` to use the cache:

```rust
// In Snapshot::from_env() - simplified
pub(crate) fn from_env<'a, 'b>(
    env: impl Into<GuestEnvironment<'a, 'b>>,
    cfg: SandboxConfiguration,
    cache: &BinaryCache,
) -> Result<Self> {
    let env = env.into();
    let mut bin = env.guest_binary;
    bin.canonicalize()?;

    // Get cached, relocated, mmap'd binary
    let load_addr = layout.get_guest_code_address() as u64;
    let mapped_binary = cache.get_or_create(&bin, load_addr)?;

    // Record file mapping info (for snapshot metadata, not copied into memory)
    let file_mapping = FileMappingInfo {
        content_hash: mapped_binary.hash(),
        guest_address: load_addr,
        size: mapped_binary.size() as u64,
        mode: FileMappingMode::GuestBinary,
    };

    // Memory buffer now contains only heap/stack/bootstrap - NOT the binary
    let memory = vec![0; layout.get_non_binary_memory_size()?];

    // ... set up page tables, etc.

    Ok(Self {
        memory,
        file_mappings: vec![file_mapping], // Metadata only, for restore validation
        // ...
    })
}
```

The actual `MappedBinary` (holding the mmap file handle) is stored in `SandboxMemoryManager`,
not in the `Snapshot`. The snapshot only contains serializable metadata.

User files (not the guest binary) can be mapped via `map_file()`, which replaces the
existing `map_file_cow()` API. The new API adds:

- Explicit mapping modes (`ReadOnly` vs `ReadWriteCow`)
- Snapshot integration (file mappings are tracked and validated on restore)

```rust
// User file mapping (read-only) - entire file is R--
sandbox.map_file(&data_path, guest_addr, FileMappingMode::ReadOnly)?;

// User file mapping (read-write with COW) - entire file is RW- with COW
sandbox.map_file(&config_path, guest_addr, FileMappingMode::ReadWriteCow)?;
```

**Trade-offs:**

- (+) Unified infrastructure for binary and user files
- (+) `GuestBinary` mode captures per-segment permissions cleanly
- (+) `ReadOnly` and `ReadWriteCow` are simple for user files (no segment complexity)
- (-) No "ephemeral" mode (not tracked in snapshot) - can be added later if needed

### Lazy Page Table Creation

Page tables are created on-demand via page faults, not eagerly during sandbox initialization.
This avoids the cost of creating PTEs for pages that are never accessed.

**Initialization sequence:**

```
Host                                    Guest
────                                    ─────
1. mmap binary (PROT_READ)
2. Create hypervisor memory slot
   mapping host pages to guest GPA
3. Set up minimal bootstrap page tables
   (only bootstrap code is mapped)
4. VM Enter at bootstrap entry point
                                        5. Bootstrap initializes (stack, IDT)
                                        6. Bootstrap installs page fault handler
                                        7. Bootstrap jumps to guest entry point
                                        8. Guest accesses unmapped page → PAGE FAULT
                                        9. Handler creates PTE, resumes execution
                                        10. Guest continues...
```

This approach means the guest binary and user files are mapped into hypervisor memory
slots (making them accessible at their GPAs), but no PTEs exist initially. When the
guest accesses a page, the fault handler creates a PTE pointing to the shared file
mapping (read-only) or triggers COW for writable pages.

**Bootstrap requirements:**

The bootstrap code solves a chicken-and-egg problem: lazy PTE creation requires a page
fault handler, but the handler itself needs to be mapped before it can run. This is a
refactoring of the existing guest initialization code in `hyperlight_guest` - the same
initialization that currently happens is restructured so that:

1. A small stub is eagerly mapped by the host (PTEs pre-created)
2. The stub executes immediately on VM entry and installs the page fault handler
3. Once installed, all subsequent page accesses (including the guest binary) are handled lazily

The bootstrap stub contains:

- Minimal startup (set stack pointer)
- IDT setup (install page fault handler)
- Call to `hyperlight_main` in the guest binary

The stub is injected by the host at sandbox creation time, not linked into the guest binary.
It's mapped at a fixed GPA known to both host and guest. The host creates initial page tables
that map only the bootstrap region, scratch region, and page tables themselves - using the
existing `GuestPageTableBuffer` infrastructure.

```rust
// Host-side: create initial page tables with minimal mappings
fn setup_initial_page_tables(
    pt_buf: &GuestPageTableBuffer,
    scratch_size: usize,
) {
    // Map bootstrap region (small, eagerly mapped)
    let bootstrap_mapping = Mapping {
        phys_base: BOOTSTRAP_GPA,
        virt_base: BOOTSTRAP_GVA,
        len: BOOTSTRAP_SIZE as u64,
        kind: MappingKind::BasicMapping(BasicMapping {
            readable: true,
            writable: false,
            executable: true,
        }),
    };
    unsafe { vmem::map(pt_buf, bootstrap_mapping) };

    // Map scratch region (for COW private pages)
    let scratch_mapping = Mapping {
        phys_base: scratch_base_gpa(scratch_size),
        virt_base: scratch_base_gva(scratch_size),
        len: scratch_size as u64,
        kind: MappingKind::BasicMapping(BasicMapping {
            readable: true,
            writable: true,
            executable: true,
        }),
    };
    unsafe { vmem::map(pt_buf, scratch_mapping) };

    // Map page tables themselves (so guest can update them)
    // ... (grows as more PTEs are added)
}
```

**Trade-offs:**

- (+) No wasted PTEs for unaccessed pages
- (+) Faster sandbox creation (no PTE setup time)
- (+) Memory savings (fewer page table pages)
- (-) First access to each page incurs fault overhead
- (-) Requires bootstrap code and page fault handler in guest

**Alternatives considered:**

1. **Eager PTE creation by host**: Simpler but wasteful. The host would parse ELF segments
   and create all PTEs before guest entry. Rejected because most pages may never be accessed
   in short-lived sandboxes.

2. **Eager code PTEs, lazy data PTEs**: Compromise that might reduce fault overhead for
   hot code paths. Could be added as optimization if benchmarks show it's needed.

### Guest Page Fault Handler

Hyperlight already has a guest-side exception handler (`hl_exception_handler` in
`hyperlight_guest_bin`) that handles page faults for:

1. **Stack expansion**: Faults in the stack GVA range allocate new pages on demand
   (implemented in PR #1205)
2. **Snapshot region COW**: Faults in the snapshot data region (addresses below the
   snapshot page table base) trigger copy-on-write - the snapshot is mapped read-only,
   so writes cause faults that allocate private pages in the scratch region

This HIP extends the existing handler to also handle file-backed pages:

3. **File mapping access**: Faults in file-mapped regions create PTEs pointing to the
   shared file mapping, with permissions based on the region table

The extended handler logic (additions shown):

```rust
// In hl_exception_handler - extended for file mappings
pub extern "C" fn hl_exception_handler(
    stack_pointer: u64,
    exception_number: u64,
    page_fault_address: u64,
) {
    // Existing setup: extract error_code from exception info on stack
    let exn_info = (stack_pointer + size_of::<Context>() as u64) as *mut ExceptionInfo;
    let error_code = unsafe { (&raw const (*exn_info).error_code).read_volatile() };

    // Existing: Handle stack expansion
    if exception_number == 14 &&
        page_fault_address >= MAIN_STACK_LIMIT_GVA &&
        page_fault_address <= MAIN_STACK_TOP_GVA {
        // ... existing stack expansion logic ...
        return;
    }

    // Existing: Handle snapshot region COW
    if exception_number == 14 &&
        page_fault_address <= snapshot_pt_gpa_base_gva() {
        // ... existing COW logic (alloc page, copy, remap) ...
        return;
    }

    // NEW: Handle file-backed regions (guest binary and user files)
    if exception_number == 14 {
        if let Some(region) = REGION_TABLE.lookup(page_fault_address) {
            let page_addr = page_fault_address & !0xfff;
            let is_write = (error_code & 0x2) != 0;  // CAUSED_BY_WRITE
            let is_present = (error_code & 0x1) != 0; // PROTECTION_VIOLATION

            let is_cow_region = matches!(
                region.region_type,
                RegionType::ElfRW | RegionType::UserFileRW
            );

            if !is_present {
                // First access - create PTE pointing to shared file mapping
                // For COW regions, map read-only initially (COW triggers on write)
                let file_page_gpa = region.file_gpa_base +
                    region.file_offset +
                    (page_addr - region.start);
                paging::map_page(
                    file_page_gpa,
                    page_addr as *mut u8,
                    /*writable=*/ false,  // Always map read-only initially
                    /*executable=*/ matches!(region.region_type, RegionType::ElfRX),
                );
                return;
            }

            if is_write && is_present && is_cow_region {
                // Write to read-only mapped COW page - make private copy
                let new_page = alloc_phys_pages(1);
                ptr::copy(
                    page_addr as *const u8,
                    ptov(new_page).unwrap(),
                    PAGE_SIZE,
                );
                paging::map_page(new_page, page_addr as *mut u8, /*writable=*/ true, /*executable=*/ false);
                asm!("invlpg [{}]", in(reg) page_addr);
                return;
            }

            if is_write && !is_cow_region {
                // Write to genuinely read-only region (ElfRX, ElfRO, UserFileRO)
                abort!(ErrorCode::GuestError, "Write to read-only region");
            }
        }
    }

    // ... existing fallthrough to abort ...
}
```

**Region table:**

Built by the **host** during sandbox initialization and placed in the eagerly-mapped bootstrap
region at a fixed address (e.g., `REGION_TABLE_GVA = BOOTSTRAP_GVA + BOOTSTRAP_CODE_SIZE`).
This ensures the table is accessible before the page fault handler runs.
The guest bootstrap code simply reads this pre-built table - no ELF parsing required in the guest.

For `GuestBinary` mappings, the host parses PT_LOAD segments from the cached ELF and creates
a region entry for each (typically one RX region for code, one RW region for data).
For `ReadOnly` and `ReadWriteCow` user file mappings, a single entry covers the whole file.

```rust
// Host-side: build region table during sandbox initialization
// This is placed in guest memory at a known address (e.g., part of bootstrap data)

/// Type of memory region - used by page fault handler to determine behavior
#[repr(u32)]  // Stable layout for host-guest ABI
enum RegionType {
    // ELF loadable segments (from PT_LOAD headers)
    ElfRX = 0,      // Executable code segment (read-execute)
    ElfRO = 1,      // Read-only data segment (read-only, no execute)
    ElfRW = 2,      // Writable data segment (read-write, COW)

    // User-mapped files
    UserFileRO = 3,   // Read-only user file
    UserFileRW = 4,   // Read-write user file (COW)
}

#[repr(C)]  // Stable layout for host-guest ABI
struct RegionEntry {
    start: u64,
    end: u64,
    region_type: RegionType,
    // GPA of the backing file data (for calculating page GPA from GVA)
    file_gpa_base: u64,
    file_offset: u64,  // Offset within file where this region starts
}

#[repr(C)]
struct RegionTable {
    count: u32,
    entries: [RegionEntry; MAX_REGIONS],
}

// Host builds this table:
fn build_region_table(
    mapped_binary: &MappedBinary,
    user_file_mappings: &[UserFileMapping],
) -> Result<RegionTable> {
    let mut table = RegionTable::default();

    // Parse PT_LOAD headers from the cached ELF (host-side only)
    let elf = elf::ElfBytes::<elf::endian::LittleEndian>::minimal_parse(
        mapped_binary.as_slice()
    )?;

    let segments = elf.segments()
        .ok_or_else(|| Error::InvalidElf("no program headers"))?;

    for phdr in segments.iter().filter(|p| p.p_type == elf::abi::PT_LOAD) {
        let is_write = (phdr.p_flags & 0x2) != 0;  // PF_W
        let is_exec = (phdr.p_flags & 0x1) != 0;   // PF_X

        let region_type = match (is_write, is_exec) {
            (true, _) => RegionType::ElfRW,   // Writable (COW)
            (false, true) => RegionType::ElfRX,  // Executable code
            (false, false) => RegionType::ElfRO, // Read-only data
        };

        table.push(RegionEntry {
            start: phdr.p_vaddr,
            end: phdr.p_vaddr + phdr.p_memsz,
            region_type,
            file_gpa_base: mapped_binary.gpa_base(),
            file_offset: phdr.p_offset,
        })?;
    }

    // Add user file mappings
    for mapping in user_file_mappings {
        let region_type = match mapping.info.mode {
            FileMappingMode::ReadOnly => RegionType::UserFileRO,
            FileMappingMode::ReadWriteCow => RegionType::UserFileRW,
            FileMappingMode::GuestBinary => {
                return Err(Error::InvalidArgument("GuestBinary not expected here"));
            }
        };

        table.push(RegionEntry {
            start: mapping.info.guest_address,
            end: mapping.info.guest_address + mapping.info.size,
            region_type,
            file_gpa_base: mapping.mapped_file.gpa_base(),
            file_offset: 0,
        })?;
    }

    Ok(table)
}
```

The guest-side page fault handler simply reads from the region table at the known address:

```rust
// Guest-side: read pre-built region table (no ELF parsing needed)
impl RegionTable {
    fn lookup(&self, addr: u64) -> Option<&RegionEntry> {
        self.entries[..self.count as usize]
            .iter()
            .find(|e| addr >= e.start && addr < e.end)
    }
}

// In page fault handler:
static REGION_TABLE: &RegionTable = unsafe { &*(REGION_TABLE_GVA as *const RegionTable) };
```

**Trade-offs:**

- (+) Region table lookup is fast (small number of regions)
- (+) Handles both PTE creation and COW in one handler
- (-) Every first access to a page incurs fault overhead

**COW behavior by region type:**

- `ElfRX`, `ElfRO`, `UserFileRO`: Read-only, writes abort the sandbox
- `ElfRW`, `UserFileRW`: COW - first write triggers private copy

```
Initial state (page not yet accessed):
┌─────────────────┐
│ Guest PT Entry  │ → Not present
└─────────────────┘

After first read:
┌─────────────────┐     ┌─────────────────┐
│ Guest PT Entry  │ ──► │ Shared Page     │
│ (Read-only)     │     │ (in mmap'd file)│
└─────────────────┘     └─────────────────┘

After first write (COW triggered):
┌─────────────────┐     ┌─────────────────┐
│ Guest PT Entry  │ ──► │ Private Page    │
│ (Read-Write)    │     │ (in scratch rgn)│
└─────────────────┘     └─────────────────┘
                        (copy of original)
```

**Dirty page identification:**

Hyperlight already uses GPA-range-based dirty detection: pages pointing to the scratch region
are dirty (private COW'd pages), while pages pointing to the snapshot region are clean.
The existing `filtered_mappings` function in `snapshot.rs` walks page tables and excludes
scratch region pages. This HIP extends this mechanism to also exclude file-backed pages
(which point to the shared mmap'd file GPA range).

### Snapshot Integration

**Current snapshot mechanism (already implemented):**

Hyperlight already has a page-table-walking snapshot mechanism in `Snapshot::new()`:

1. `filtered_mappings()` walks page tables using `virt_to_phys` to enumerate all mapped pages
2. Pages in scratch region or snapshot page table region are excluded
3. All other mapped pages are copied into the snapshot `Vec<u8>`
4. New page tables are built pointing to the compacted snapshot memory
5. On restore, snapshot memory is copied back and page tables rebuilt

```rust
// Current Snapshot struct (after PR #1205)
pub struct Snapshot {
    sandbox_id: u64,
    layout: SandboxMemoryLayout,
    memory: Vec<u8>,              // All live pages, compacted
    regions: Vec<MemoryRegion>,   // Extra host->guest mappings (replaced by file_mappings)
    load_info: LoadInfo,
    hash: [u8; 32],
    root_pt_gpa: u64,
    stack_top_gva: u64,           // Added in PR #1205
}
```

**Changes required for file mapping:**

The existing snapshot mechanism needs these modifications:

1. **Skip content copy for clean file-backed pages**: When walking page tables at snapshot time,
   check if GPA points to a file-backed region. If so, skip copying content (it's shared).
   If GPA points to scratch (COW'd page), copy the content as usual.

2. **Replace `regions` with `file_mappings`**: The existing `regions: Vec<MemoryRegion>`
   field is replaced by `file_mappings` which tracks which files are mapped and their GPA ranges.
   This is used to identify file-backed GPAs during snapshot/restore.

The existing PTE rebuild logic on restore remains unchanged - it already walks the snapshot's
page tables and recreates all PTEs. The GPAs stored in the snapshot are already correct:
file-backed pages point to file GPAs, dirty pages point to snapshot memory GPAs.

```rust
// Proposed changes to Snapshot struct
pub struct Snapshot {
    sandbox_id: u64,
    layout: SandboxMemoryLayout,
    memory: Vec<u8>,              // Dirty pages + page tables (no clean file content)
    load_info: LoadInfo,
    hash: [u8; 32],
    root_pt_gpa: u64,
    stack_top_gva: u64,           // Added in PR #1205

    // REMOVED: regions: Vec<MemoryRegion>

    // ADDED: file_mappings tracks which files are mapped (GPA ranges + validation hash)
    file_mappings: Vec<FileMappingInfo>,
}
```

**Removed functions/logic:**

```rust
// REMOVED: guest_page() no longer checks regions
// Before:
unsafe fn guest_page(..., regions: &[MemoryRegion], ...) -> Option<&[u8]> {
    // Check if GPA falls within a MemoryRegion (host memory)
    for rgn in regions {
        if gpa >= rgn.guest_region.start && gpa + PAGE_SIZE <= rgn.guest_region.end {
            // Return slice from host memory
            return Some(std::slice::from_raw_parts(...));
        }
    }
    // Fall back to snapshot/scratch memory
    ...
}

// After: regions parameter removed, file-backed GPAs are excluded earlier
unsafe fn guest_page(snap: ..., scratch: ..., scratch_size: usize, gpa: u64) -> Option<&[u8]> {
    // Only check snapshot and scratch memory
    let (mem, off) = access_gpa(snap, scratch, scratch_size, gpa)?;
    ...
}

// REMOVED: hash() no longer includes regions
// Before:
fn hash(memory: &[u8], regions: &[MemoryRegion]) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(memory);
    for rgn in regions { ... }  // Include region metadata
    Ok(hasher.finalize().into())
}

// After: regions parameter removed, file_mappings included instead
fn hash(memory: &[u8], file_mappings: &[FileMappingInfo]) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(memory);
    for fm in file_mappings {
        hasher.update(&fm.content_hash);  // Include file content hash
        hasher.update(&fm.guest_address.to_le_bytes());
    }
    Ok(hasher.finalize().into())
}
```

**Modified `filtered_mappings` logic:**

Pages are categorized by where their GPA points:

1. **File-backed GPA (clean)**: GPA points to the mmap'd file region → skip content copy
2. **Scratch GPA (dirty file page)**: GPA points to scratch (COW'd file page) → copy content
3. **Non-file pages**: heap, stack, etc. → copy content (existing behavior)

```rust
// In filtered_mappings - skip content copy for clean file-backed pages
fn filtered_mappings(...) -> Vec<(u64, u64, BasicMapping, Option<&[u8]>)> {
    virt_to_phys(...)
        .filter_map(|(gva, gpa, bm)| {
            // Exclude scratch region GVAs (internal allocations)
            if gva >= scratch_base_gva(scratch_size) {
                return None;
            }
            // Exclude snapshot page tables
            if gva >= SNAPSHOT_PT_GVA_MIN && gva <= SNAPSHOT_PT_GVA_MAX {
                return None;
            }

            // Check if GPA points to a file-backed region
            if is_file_backed_gpa(gpa, file_mappings) {
                // Clean file-backed page - no content to copy
                return Some((gva, gpa, bm, None));
            }

            // Dirty page - copy content from scratch or snapshot memory
            let contents = guest_page(snap, scratch, scratch_size, gpa)?;
            Some((gva, gpa, bm, Some(contents)))
        })
        .collect()
}
```

**How COW'd file pages are captured:**

When a write occurs to a file-backed COW page (e.g., `.data` section):
1. Page fault handler allocates new page in scratch region via `alloc_phys_pages(1)`
2. Copies content from file page to new scratch page
3. Remaps PTE: same GVA, but GPA now points to scratch region (with RW permissions)

At snapshot time:
- The GVA is still in the file-mapped range (e.g., `.data` section address)
- But the GPA points to scratch, not to the file
- `is_file_backed_gpa(gpa, ...)` returns false
- Content is copied from scratch region

On restore, `rebuild_page_tables` walks the snapshot's page tables and recreates all PTEs.
The GPAs are already correct in the snapshot - file-backed pages point to file GPAs,
dirty pages point to snapshot memory GPAs:

```rust
fn rebuild_page_tables(&mut self, snapshot: &Snapshot) -> Result<()> {
    let pt_buf = GuestPageTableBuffer::new(pt_base_gpa);

    // Walk the snapshot's page tables and recreate all PTEs
    for (gva, gpa, bm) in virt_to_phys(snapshot, ...) {
        let mapping = Mapping {
            phys_base: gpa,
            virt_base: gva,
            len: PAGE_SIZE as u64,
            kind: MappingKind::BasicMapping(bm),
        };
        unsafe { vmem::map(&pt_buf, mapping) };
    }

    // Map special regions
    map_specials(&pt_buf, self.layout.get_scratch_size());

    Ok(())
}
```

**Key points:**
- **Clean file-backed pages**: RO PTEs preserved exactly (same GVA → same GPA, same permissions)
- **Dirty file-backed pages (COW'd)**: Content captured in snapshot, restored with original permissions
- No content duplication for clean file-backed pages
- Pages never accessed before snapshot remain unmapped (lazy creation on first access)

**Restore process:**

For in-process restore (restoring to the same sandbox instance that created the snapshot),
the file mappings are already in place - the sandbox keeps the `MappedBinary` and
`MappedFile` handles alive, and the hypervisor memory slots remain configured. The restore
process only needs to:

1. Validate the sandbox ID matches
2. Verify file content hashes (defense-in-depth - should never fail since files are locked)
3. Copy snapshot memory (dirty pages)
4. Rebuild page tables

```rust
fn restore_snapshot(sandbox: &mut Sandbox, snapshot: &Snapshot) -> Result<()> {
    // Existing: validate sandbox ID
    if sandbox.id() != snapshot.sandbox_id {
        return Err(Error::SnapshotMismatch);
    }

    // Verify file mappings match what the snapshot expects.
    // `file_mappings` includes both the guest binary (FileMappingMode::GuestBinary)
    // and any user-mapped files (ReadOnly or ReadWriteCow).
    //
    // For in-process restore, the sandbox already has these files mapped into
    // hypervisor memory slots at the correct GPAs. We verify the content hashes
    // as defense-in-depth (should never fail since files are locked while mapped).
    for file_info in &snapshot.file_mappings {
        // Lookup the file mapping by GPA - searches both MappedBinary and MappedFiles
        let mapped_file = sandbox.get_file_mapping_at_gpa(file_info.guest_address)
            .ok_or(Error::MissingFileMapping)?;
        if mapped_file.content_hash() != file_info.content_hash {
            return Err(Error::ContentMismatch);
        }
    }

    // Existing: copy snapshot memory (dirty pages only - file content is shared)
    sandbox.shared_mem.restore_from_slice(&snapshot.memory)?;

    // Existing: rebuild page tables (PTEs point to file GPAs or snapshot memory GPAs)
    sandbox.rebuild_page_tables(&snapshot)?;

    Ok(())
}
```

For future disk persistence (restoring a snapshot in a new process), the restore would
need to first re-establish the file mappings:

```rust
fn restore_persisted_snapshot(snapshot: &PersistedSnapshot, cache: &BinaryCache) -> Result<Sandbox> {
    // Re-establish file mappings from cache.
    // `file_mappings` includes both the guest binary and user files - all are
    // stored in the cache (keyed by content hash) when a snapshot is persisted.
    let mut file_mappings = Vec::new();
    for file_info in &snapshot.file_mappings {
        // Lookup by content hash - requires file to be in cache
        let mapped = cache.open_by_hash(&file_info.content_hash, file_info.guest_address)?;
        file_mappings.push(mapped);
    }

    // Create sandbox with the mapped files
    let sandbox = Sandbox::new_with_file_mappings(file_mappings, ...)?;

    // Then proceed with normal restore...
    sandbox.shared_mem.restore_from_slice(&snapshot.memory)?;
    sandbox.rebuild_page_tables(&snapshot)?;

    Ok(sandbox)
}
```

**Result:** Snapshots remain compact (file content is not duplicated), while restore
is fast and preserves exact page permissions.

**Design for future persistence:**

While this HIP focuses on in-process restore (same sandbox instance), the design supports
future disk persistence:

- File mappings reference content by hash, not path (enables validation on restore)
- No pointers or handles in `FileMappingInfo` (serializable to disk)

When persistence is implemented, the `Snapshot` struct can be serialized to disk and
restored in a new process by:

1. Re-establishing file mappings via cache (lookup by hash)
2. Applying dirty pages
3. Recreating page tables
4. Restoring CPU state

**Trade-offs:**

- (+) Snapshots are smaller (file refs + dirty pages, not full memory)
- (+) Design supports future persistence without restructuring
- (+) Content hashing enables validation
- (-) More complex than simple Vec<u8> snapshot. The complexity comes from managing the
  relationship between snapshots and their associated file caches - a snapshot is no longer
  self-contained but depends on external cached files being present and unchanged. This could
  be mitigated with tooling e.g.:
  - `hyperlight snapshot package` - bundle a snapshot with its required cached files into a
    single distributable artifact. Moreover these single redistributable artifacts could published and shared to OCI compatible registries for easy distribution.
  - `hyperlight snapshot validate` - verify all referenced files exist and content hashes match
  - `hyperlight snapshot info` - query snapshot metadata (file mappings, sizes, content hashes)
  - (-) Restore must re-validate file content (content hash verification adds latency)


## Test Plan

**Unit Tests:**

- Binary cache: `get_or_create`, concurrent access, cache key correctness
- Region table: lookup correctness, boundary cases, empty table
- `build_region_table`: PT_LOAD parsing, user file mapping inclusion

**Integration Tests:**

- Single sandbox with mmap'd binary executes correctly
- Multiple sandboxes share binary (verify via `/proc/*/smaps` Pss on Linux)
- COW triggers correctly: first read creates read-only PTE, first write triggers COW
- Write to executable segment (RX) terminates sandbox (not COW-eligible)
- Snapshot restore rebuilds page tables pointing to shared file mapping
- Restore validates file content hash (fails if cached file changed)
- `map_file` API works for user files (ReadOnly and ReadWriteCow modes)

**Memory Tests:**

- 100 sandboxes with shared binary use less memory than 100 copies
- Dirty pages grow proportionally to writes, not total mapped size

**Performance Tests:**

- Sandbox creation time (expect faster due to no binary copy)
- First page access latency (measure fault overhead)
- Memory usage at scale (100, 1000 sandboxes)

## Implementation History

- 2025-02-03: Initial HIP draft

## Drawbacks

1. **Increased complexity**: Region table and extended page fault handler logic add
   guest-side complexity on top of the existing exception handling infrastructure.

2. **First-access latency**: Each page's first access incurs a page fault. For
   latency-critical code paths, this could be noticeable.

3. **Cache management**: Users must manage disk cache. Stale entries accumulate until
   manually cleaned.
