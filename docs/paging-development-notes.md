# Guest-aided Copy-on-Write snapshots

When running on a Type 1 hypervisor, servicing a Stage 2 translation
page fault is relatively quite expensive, since it requires quite a
lot of context switches.  To help alleviate this, Hyperlight uses a
design in which the guest is aware of a readonly snapshot from
which it is being run, and manages its own copy-on-write.

Because of this, there are two very fundamental regions of the guest
physical address space, which are always populated: one, near the
bottom of memory (starting at GPA `0x1000`), is a
(hypervisor-enforced) readonly mapping of the base snapshot from which
this guest is being evolved. Another, at the top of memory, is simply
a large bag of blank pages: scratch memory into which this VM can
write.

```
  Guest Physical Address Space (GPA)

  +-------------------------------+ MAX_GPA
  |    Exn Stack, Bookkeeping     |
  |    (scratch size, allocator   |
  |     state, reserved PT slot)  |
  +-------------------------------+
  |      Free Scratch Memory      |
  +-------------------------------+
  |         Output Data           |
  +-------------------------------+
  |         Input Data            |
  +-------------------------------+
  |                               |
  |     (unmapped — no RAM        |
  |      backing these addrs)     |
  |                               |
  +-------------------------------+
  |                               |
  |  Snapshot (RO / CoW on write) |
  |    Guest Page Tables          |
  |    Init Data                  |
  |    Guest Heap                 |
  |    PEB                        |
  |    Guest Binary               |
  |                               |
  +-------------------------------+ 0x1000
  |    (null guard page)          |
  +-------------------------------+ 0x0000
```



## The scratch map

Whenever the guest needs to write to a page in the snapshot region, it
will need to copy it into a page in the scratch region, and change the
original virtual address to point to the new page.

```
  CoW page fault flow:

  BEFORE (guest writes to CoW page -> fault)

    PTE for VA 0x5000:
    +----------+-----+-----+
    | GPA      | CoW | R/O |    Points to snapshot page
    | 0x5000   |  1  |  1  |
    +----------+-----+-----+
         |
         v
    Snapshot region (readonly)
    +--------------------+
    | original content   |  GPA 0x5000
    +--------------------+

  AFTER (fault handler resolves)

    1. Allocate fresh page from scratch (bump allocator)
    2. Copy snapshot page -> new scratch page
    3. Update PTE to point to scratch page

    PTE for VA 0x5000:
    +----------+-----+-----+
    | GPA      | CoW | R/W |    Points to scratch page
    | 0xf_ff.. |  0  |  1  |
    +----------+-----+-----+
         |
         v
    Scratch region (writable)
    +--------------------+
    | copied content     |  (new GPA in scratch)
    +--------------------+

    Snapshot page at GPA 0x5000 is untouched.
```

The page table
entries to do this will likely need to be copied themselves, and so a
ready supply of already-mapped scratch pages to use for replacement
page tables is set up by the Host. The guest keeps a mapping of the entire scratch
physical memory into virtual memory at a fixed offset
(`scratch_base_gva - scratch_base_gpa`), so that any scratch physical
address can be accessed by adding this offset.

The host and the guest need to agree on the location of this mapping,
so that (a) the host can create it when first setting up a blank guest
and (b) the host can ignore it when taking a snapshot (see below).

The host creates the scratch map at the top of virtual memory
(`MAX_GVA - scratch_size + 1`) and at the top of physical memory
(`MAX_GPA - scratch_size + 1`). In the future, we may add support for a guest to
request that it be moved.

## The snapshot mapping

The snapshot page tables must be mapped at some virtual address so
that the guest can read and copy them during CoW operations.
Today, the host simply
copies the page tables into scratch when restoring a sandbox, and the
guest works on those scratch copies directly. 

## Top-of-scratch metadata layout

The top page of the scratch region contains structured metadata at
fixed offsets down from the top:

| Offset from top | Field                                |
|-----------------|--------------------------------------|
| `0x08`          | Scratch size (`u64`)                 |
| `0x10`          | Allocator state (`u64`)              |
| `0x18`          | Reserved snapshot PT base (`u64`)    |
| `0x20`          | Exception stack starts here          |

These offsets are defined as `SCRATCH_TOP_*` constants in
`hyperlight_common::layout`.

## The physical page allocator

The host needs to be able to reset the state of the physical page
allocator when resuming from a snapshot. We use a simple bump
allocator as a physical page allocator, with no support for free,
since pages not in use will automatically be omitted from a snapshot.
The allocator state is a single `u64` tracking the address of the
first free page, located at offset `0x10` from the top of scratch
(see layout above). The guest advances it atomically via `lock xadd`.

## The guest exception stack

Similarly, the guest needs a stack that is always writable, in order
to be able to take exceptions to it. The exception stack begins at
offset `0x20` from the top of the scratch region (below the metadata
fields described above) and grows downward through the remainder of
the top page.

## Taking a snapshot

When the host takes a snapshot of a guest, it will traverse the guest
page tables, collecting every (non-page-table) physical page that is
mapped (outside of the scratch map) in the guest. It will write out a
new compacted snapshot with precisely those pages in order, and a new
set of page tables which produce precisely the same virtual memory
layout, except for the scratch map.

### Pre-sizing the scratch region

When creating a snapshot, the host must provide the size of the
scratch region that will be used when this snapshot is next restored
into a sandbox. This will then be baked into the guest page tables
created in the snapshot.

TODO: add support, if found to be useful operationally, for either
dynamically growing the scratch region, or changing its size between
taking a snapshot and restoring it.

### Call descriptors

Taking a snapshot is presently only supported in between top-level
calls, i.e. there may be no calls in flight at the time of
snapshotting. This is not enforced, but odd things may happen if it is
violated.

I/O buffers are statically allocated at the bottom of the scratch
region:

```
+-------------------------------------------+ (top of scratch)
|       Exn Stack, Bookkeeping              |
|  (scratch size, allocator state,          |
|   reserved PT base)                       |
+-------------------------------------------+
|           Free Scratch Memory             |
+-------------------------------------------+
|                Output Data                |
+-------------------------------------------+
|                Input Data                 |
+-------------------------------------------+ (scratch base)
```

The minimum scratch size (`min_scratch_size()`) accounts for these
buffers plus overhead for the Task State Segment (TSS), Interrupt Descriptor Table (IDT), page table CoW, a minimal
non-exception stack, and the exception stack and metadata.

## Creating a fresh guest

When a fresh guest is created, the snapshot region will contain the
loadable pages of the input ELF and an initial set of page tables,
which simply map the segments of that ELF to the appropriate places in
virtual memory.  If the ELF has segments whose virtual addresses
overlap with the scratch map, an error will be returned.

In the current startup path, the host enters the guest with
`RSP` pointing to the exception stack. Early guest init then
allocates the main stack at `MAIN_STACK_TOP_GVA`, switches to it,
and continues generic initialization.

# Architecture-specific details of virtual memory setup

## amd64

Hyperlight unconditionally uses 48-bit virtual addresses (4-level
paging) and enables PAE.  The guest is always entered in long mode.
