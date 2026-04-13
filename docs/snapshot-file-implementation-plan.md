# Snapshot File Format

## Overview

Save a `Snapshot` to disk and load it back via zero-copy file
mapping, so that a `MultiUseSandbox` can be created directly from a
file without re-parsing the guest ELF or re-running guest init code.

- **Linux**: `mmap(MAP_PRIVATE)` at page-aligned offset - zero copy,
  demand-paged by the kernel.
- **Windows**: `CreateFileMappingA(PAGE_READONLY)` +
  `MapViewOfFile(FILE_MAP_READ)` - zero copy, demand-paged by the OS.

Cross-platform (Linux + Windows). Default feature flags only
(`nanvix-unstable`, `crashdump`, `gdb` not handled).

---

## File Format

The file uses a versioned header with two independent version checks:

- **Format version** (`FormatVersion` enum): controls the byte layout
  of the header itself. A format version mismatch may be convertible
  by re-serializing the header.
- **ABI version** (`SNAPSHOT_ABI_VERSION` constant): covers the
  contents and interpretation of the memory blob. An ABI mismatch
  means the snapshot must be regenerated from the guest binary.

```
Offset  Size     Field
------  -------  --------------------------------------------------
0       4        Magic bytes: "HLS\0"
4       4        Format version (u32 LE: 1 = V1)
8       4        Architecture tag (u32 LE: 1 = x86_64, 2 = aarch64)
12      4        ABI version (u32 LE: must match SNAPSHOT_ABI_VERSION)
16      32       Content hash (blake3, over memory blob only)
48      8        stack_top_gva (u64 LE)
56      8        Entrypoint tag (u64 LE: 0 = Initialise, 1 = Call)
64      8        Entrypoint address (u64 LE)
72      8        input_data_size (u64 LE)
80      8        output_data_size (u64 LE)
88      8        heap_size (u64 LE)
96      8        code_size (u64 LE)
104     8        init_data_size (u64 LE)
112     8        init_data_permissions (u64 LE: 0 = None, else bits)
120     8        scratch_size (u64 LE)
128     8        snapshot_size (u64 LE)
136     8        pt_size (u64 LE: 0 = None)
144     8        memory_size (u64 LE) - byte length of memory blob
                   Derivable from layout fields today, but stored for
                   forward compat (e.g. compression).
152     8        memory_offset (u64 LE) - byte offset from file start
                   Always SNAPSHOT_HEADER_SIZE today, but stored so a
                   future format can relocate the blob without breaking.
160     8        has_sregs (u64 LE: 1 = present, 0 = absent)
168     8        hypervisor_tag (u64 LE: 1 = KVM, 2 = MSHV, 3 = WHP)
176     952      sregs fields (all widened to u64 LE, see below)
1120    2976     Zero padding to 4096-byte boundary
4096    *        Memory blob (page-aligned, uncompressed, mmap target)
*+4096  4096     Trailing zero padding (guard page backing for Windows)
```

Total header before padding: 1128 bytes, well within the 4096-byte
page.

The trailing PAGE_SIZE padding exists because Windows read-only file
mappings cannot extend beyond the file's actual size.
`ReadonlySharedMemory::from_file_windows` maps the entire file and
uses `VirtualProtect(PAGE_NOACCESS)` on both the first page (header)
and last page (trailing padding) as guard pages. Linux ignores this
padding - its guard pages come from an anonymous mmap reservation.

### Layout fields

The 9 layout fields (offsets 72-136) are the primary inputs to
`SandboxMemoryLayout::new()`. On load, a `SandboxConfiguration` is
reconstructed from `input_data_size`, `output_data_size`, `heap_size`,
and `scratch_size`; the remaining fields (`code_size`,
`init_data_size`, `init_data_permissions`) are passed directly.
`snapshot_size` and `pt_size` are set after construction.

### Hypervisor tag

Segment register hidden-cache fields (`unusable`, `type_`,
`granularity`, `db`) differ between KVM, MSHV, and WHP for the same
architectural state. Restoring sregs captured on one hypervisor into
another may be rejected or produce subtly wrong behavior. The
`hypervisor_tag` field ensures snapshots are only loaded on the same
hypervisor that created them. See "Cross-hypervisor snapshot
portability" under Future Work for how this restriction could be
relaxed.

### Special registers (sregs)

The vCPU special registers are persisted because the guest init
code sets up a GDT, IDT, TSS, and segment descriptors that differ
from `standard_64bit_defaults`. Without the captured sregs, the guest
triple-faults on dispatch. Specifically, the guest init sets:

- cs/ds/es/fs/gs/ss with proper selectors, limits, and granularity
- GDT and IDT base/limit pointing into guest high memory
- TSS (task register) with a valid base, selector, and limit
- LDT marked as unusable

All fields widened to u64 LE: 8 segment regs x 13 fields + 2 table
regs x 2 fields + 7 control regs + 4 interrupt bitmap = 119 u64s
(952 bytes). Always written; ignored on load when `has_sregs = 0`.

### What is NOT persisted

| Field | Reason |
|---|---|
| `sandbox_id` | Process-local counter; fresh ID assigned on load |
| `LoadInfo` | Debug-only; reconstructible from ELF if needed |
| `regions` | Always empty after snapshot (absorbed into memory) |
| Runtime config | Defaults used at load time |
| Host function defs | Deferred to a follow-up PR |

### What IS persisted

The memory blob contains **only the snapshot region**: guest code,
PEB, heap, init data, and page tables (`ReadonlySharedMemory`).

The **scratch region** is recreated fresh on load via
`ExclusiveSharedMemory::new()`, then initialized by
`update_scratch_bookkeeping()` (copies page tables from snapshot to
scratch, writes I/O buffer metadata).

---

## Saving and Loading

### `Snapshot::to_file(&self, path)` / `Snapshot::from_file(path)`

Manual binary serialization via `SnapshotPreamble` + `SnapshotHeaderV1`
structs with `write_to` / `read_from` methods, followed by the raw
memory blob and trailing padding. `from_file` maps the memory blob
via `ReadonlySharedMemory::from_file(&file, offset, len)`.
`from_file_unchecked` skips the blake3 hash verification for trusted
environments.

On load, the header is validated in order: magic, format version,
architecture, ABI version, hypervisor tag. Any mismatch produces a
descriptive error.

### `ReadonlySharedMemory::from_file(file, offset, len)`

Cross-platform entry point that dispatches to platform-specific
implementations:

- **Linux** (`from_file_linux`): Allocates anonymous `PROT_NONE`
  region (with guard pages), then `MAP_FIXED` the file content over
  the usable portion with `PROT_READ | PROT_WRITE` + `MAP_PRIVATE`.
  KVM/MSHV need writable host mappings for CoW page fault handling.
  `HostMapping::Drop` calls `munmap` on the full region.

- **Windows** (`from_file_windows`): `CreateFileMappingA(PAGE_READONLY)`
  + `MapViewOfFile(FILE_MAP_READ)` covering the full file (header +
  blob + trailing padding). The header becomes the leading guard page
  and the trailing padding becomes the trailing guard page, both via
  `VirtualProtect(PAGE_NOACCESS)`. The `HostMapping` carries the file
  mapping handle for the surrogate process. `HostMapping::Drop` calls
  `UnmapViewOfFile` + `CloseHandle`.

Both paths produce a `HostMapping` with the standard layout:
`ptr` = start of first guard page, `size` = guard + usable + guard.
`base_ptr() = ptr + PAGE_SIZE`, `mem_size() = size - 2*PAGE_SIZE`.

### `MultiUseSandbox::from_snapshot(snapshot: Arc<Snapshot>)`

Creates a sandbox bypassing `UninitializedSandbox` and `evolve()`:

1. Create default `FunctionRegistry`
2. Build `SandboxConfiguration` from snapshot layout fields
3. `SandboxMemoryManager::from_snapshot()` - clones the
   `ReadonlySharedMemory`, creates fresh scratch
4. `mgr.build()` - splits into host/guest views, runs
   `update_scratch_bookkeeping()`
5. `setup_signal_handlers()` (Linux only - VCPU interrupt signaling)
6. `set_up_hypervisor_partition()` - creates VM (KVM/MSHV on Linux,
   WHP on Windows), maps slot 0 (snapshot) and slot 1 (scratch)
7. `vm.initialise()` - runs guest init if `NextAction::Initialise`,
   no-op if `NextAction::Call`
8. For post-init snapshots, `vm.apply_sregs()` applies captured
   sregs (sets sregs + pending TLB flush, no redundant GPR/debug/FPU
   resets)
9. Returns `MultiUseSandbox`

Host functions are not yet supported when loading from snapshot.
A `SnapshotLoader` builder with `.with_host_function()` is planned
as future work.

### Supporting changes

- `SandboxMemoryLayout` simplified to 9 `pub(crate)` fields with
  computed `#[inline]` offset methods; `new()` takes
  `SandboxConfiguration`, `code_size`, `init_data_size`,
  `init_data_permissions`
- `HyperlightPEB::write_to()` and `GuestMemoryRegion::write_to()`
  added to `hyperlight_common`
- `HyperlightVm::apply_sregs()` added to `hyperlight_vm/x86_64.rs`
  for efficient sreg restore without redundant register resets

---

## Files

| File | Purpose |
|---|---|
| `src/hyperlight_host/src/sandbox/snapshot.rs` | File format types, `to_file`, `from_file`, `from_file_unchecked`, sregs serialization, `HypervisorTag`, 10 tests |
| `src/hyperlight_host/src/sandbox/initialized_multi_use.rs` | `MultiUseSandbox::from_snapshot(Arc<Snapshot>)` (cross-platform) |
| `src/hyperlight_host/src/mem/shared_mem.rs` | `ReadonlySharedMemory::from_file()` (cross-platform dispatch to `from_file_linux` / `from_file_windows`) |
| `src/hyperlight_host/src/mem/memory_region.rs` | `SurrogateMapping` routing for `Snapshot` regions |
| `src/hyperlight_host/src/mem/layout.rs` | Simplified to 9 fields, computed offset methods, `write_peb()` uses `HyperlightPEB::write_to()` |
| `src/hyperlight_common/src/mem.rs` | `HyperlightPEB::write_to()`, `GuestMemoryRegion::write_to()` |
| `src/hyperlight_host/src/hypervisor/hyperlight_vm/x86_64.rs` | `apply_sregs()` method |
| `src/hyperlight_host/benches/benchmarks.rs` | `snapshot_files` benchmark group |

---

## Tests

All in `snapshot_file_tests` module inside `snapshot.rs`:

1. `from_snapshot_in_memory` - pre-init snapshot (Initialise entrypoint)
2. `from_snapshot_post_init_in_memory` - post-init snapshot (Call
   entrypoint)
3. `round_trip_save_load_call` - save post-init snapshot, load from
   file, create sandbox, call guest function
4. `hash_verification_detects_corruption` - corrupt memory blob byte,
   verify load fails
5. `arch_mismatch_rejected` - modify arch tag, verify load fails
6. `format_version_mismatch_rejected` - modify version, verify load
   fails with "convertible" hint
7. `abi_version_mismatch_rejected` - modify ABI version, verify load
   fails with "regenerated" hint
8. `restore_from_loaded_snapshot` - load, mutate, snapshot, mutate,
   restore, verify
9. `multiple_sandboxes_from_same_file` - two sandboxes from same file,
   verify independence
10. `snapshot_then_save_round_trip` - load, mutate, save, load again,
    verify mutated state persisted

---

## Benchmarks

Benchmark group `snapshot_files` with 5 benchmarks per size (default,
small/8MB, medium/64MB, large/256MB):

- `save_snapshot` - `snapshot.to_file()`
- `load_snapshot` - `Snapshot::from_file()` (mmap + hash verify)
- `cold_start_via_evolve` - `new()` + `evolve()` + `call("Echo")`
- `cold_start_via_snapshot` - `from_file()` + `from_snapshot()`
  + `call("Echo")`
- `cold_start_via_snapshot_unchecked` - same with `from_file_unchecked()`

---

## Results (Linux/KVM)

All three paths measure end-to-end wall-clock time from zero state to
a completed guest function call (`Echo("hello\n") -> "hello\n"`).
Each path includes creating the VM, mapping memory, and dispatching
one guest call.

- **evolve path**: parse ELF, build page tables, create VM, run guest
  init code, call guest function
- **snapshot path (verified)**: open file, read header, mmap memory
  blob from file at page-aligned offset, hash-verify entire blob,
  create VM from snapshot, call guest function
- **snapshot path (unverified)**: same but skip hash verification

| Heap size | evolve path | snapshot (verified) | snapshot (unverified) | Speedup (unverified vs evolve) |
|---|---|---|---|---|
| 128 KB (default) | 3.09 ms | 2.32 ms | 2.24 ms | 1.4x |
| 8 MB | 7.29 ms | 4.91 ms | 2.39 ms | 3.1x |
| 64 MB | 24.1 ms | 22.3 ms | 2.74 ms | 8.8x |
| 256 MB | 78.9 ms | 57.3 ms | 2.64 ms | 30x |

The unverified snapshot path is constant time (~3 ms) regardless of
snapshot size because the mmap is lazy - pages are only faulted in as
the guest touches them. Hash verification dominates for larger
snapshots since it touches the entire memory blob.

---

## Future Work

- **`SnapshotLoader` builder**: Replace `from_snapshot(snapshot)`
  with a builder that takes `.with_host_function()`,
  `.with_interrupt_retry_delay()`, validates host functions at
  `build()`.
- **Host function defs in file format**: Serialize function signatures
  into the snapshot file, validate on load
- **Typed error variants**: `SnapshotVersionMismatch`, etc.
- **Feature-gate support**: `nanvix-unstable`, `crashdump`, `gdb` cfgs
- **Single-mmap loading**: mmap the entire snapshot file once and parse
  the header from the mapped bytes instead of `read()` + separate mmap.
  Requires refactoring `HostMapping` guard page assumptions. Saves ~1 us
  per load (negligible vs ~3 ms total), but simplifies the I/O path.
- **Fuzz target**: Fuzz `from_file` with arbitrary bytes
- **CLI tool**: `hl snap bake?`
- **CoW overlay layers**
- **Cross-hypervisor snapshot portability**: The `hypervisor_tag`
  rejects cross-hypervisor loads because segment register hidden-cache
  fields differ between KVM, MSHV, and WHP. Could potentially be
  relaxed in the future (needs sregs normalization and maybe more).
- **Huge page support**: The 4 KB header is sufficient for transparent
  huge pages via `madvise(MADV_HUGEPAGE)`. Explicit `MAP_HUGETLB`
  would require a 2 MB-aligned blob offset; the `memory_offset` field
  already supports this without a format version bump.
- **OCI distribution**
- **Malicious header hardening**: The header is currently trusted after
  magic/version/arch/ABI/hypervisor validation. A crafted snapshot
  file could supply out-of-range layout fields (e.g. huge heap_size,
  memory_size larger than the file, overlapping regions) that cause
  excessive allocation, out-of-bounds access, or other misbehavior.
  The blake3 hash covers the memory blob but not the header itself.
  Consider: validating header fields against sane bounds, hashing the
  full header, and fuzzing `from_file` with arbitrary bytes.
