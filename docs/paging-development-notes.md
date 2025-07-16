# Guest-aided Copy-on-Write snapshots

When running on a Type 1 hypervisor, servicing a Stage 2 translation
page fault is relatively quite expensive, since it requires quite a
lot of context switches.  To help alleviate this, Hyperlight uses an
unusual design in which the guest is aware of readonly snapshot from
which it is being run, and manages its own copy-on-write.

Because of this, there are two very fundamental regions of the guest
physical address space, which are always populated: one, at the very
bottom of memory, is a (hypervisor-enforced) readonly mapping of the
base snapshot from which this guest is being evolved. Another, at the
top of memory, is simply a large bag of blank pages: scratch memory
into which this VM can write.

## The scratch map

Whenever the guest needs to write to a page in the snapshot region, it
will need to copy it into a page in the scratch region, and change the
original virtual address to point to the new page.  The page table
entries to do this will likely need to be copied themselves, and so a
ready supply of already-mapped scratch pages to use for replacement
page tables is needed. Currently, the guest accomplishes this by
keeping an identity mapping of the entire scratch memory around.

The host and the guest need to agree on the location of this mapping,
so that (a) the host can create it when first setting up a blank guest
and (b) the host can ignore it when taking a snapshot (see below).

Currently, the host always creates the scratch map at the top of
virtual memory.  In the future, we may add support for a guest to
request that it be moved.

## The snapshot mapping

Do we actually need to have a physmap type mapping of the entire
snapshot memory? We only really use it when copying from it in which
case we ought to have the VA that we need to copy from already. There
is one major exception to this, which is the page tables
themselves. The page tables themselves must be mapped at some VA so
that we can copy them.

Setting this VA statically on the host is a bit annoying, since we are
already using the top of memory for the scratchmap. Unfortunately,
since the size of the page tables changes as the sandbox evolves
through e.g. snapshot/restore, we cannot preallocate it...

Let's just be stupid and leave them at 0xffff_0000_0000_0000 for now.

## The physical page allocator

The host needs to be able to reset the state of the physical page
allocator when resuming from a snapshot. Currently, we use a simple
bump allocator as a physical page allocator, with no support for free,
since pages not in use will automatically be omitted from a snapshot.
Therefore, the allocator state is nothing but a single `u64` that
tracks the address of the first free page. This `u64` will always be
located at the top of scratch physical memory.

## The guest exception stack

Similarly, the guest needs a stack that is always writable, in order
to be able to take exceptions to it.  The remainder of the top page of
the scratch memory is used for this.

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

When a snapshot is taken, any outstanding buffers which the guest has
indicated it is waiting for the host to write to will be moved to the
bottom of the new scratch region and zeroed.

Q: how will the guest know about this?  Maybe A: The guest nominates a
virtual address that it wants to have this sort of bookkeeping
information mapped at, and the snapshot creation process treats that
address specially writing out a manifest

Q: how do we want to manage buffer
allocation/freeing/reallocation/etc? Maybe A: for now we will mostly
ignore because we only need 1-2 buffers inflight at a time. We can
emulate the current paradigm by recreating a new buffer out of the
free space in the original buffer on call, etc etc.

## Creating a fresh guest

When a fresh guest is created, the snapshot region will contain the
loadable pages of the input ELF and an initial set of page tables,
which simply map the segments of that ELF to the appropriate places in
virtual memory.  If the ELF has segments whose virtual addresses
overlap with the scratch map, an error will be returned.

The initial stack pointer will point to the top of the second-highest
page of the scratch map, but this should usually be changed by early
init code in the guest, since it will otherwise be difficult to detect
collisions between the guest stack and the scratch physical page
allocator.

# Architecture-specific details of virtual memory setup

## amd64

Hyperlight unconditionally uses 48-bit virtual addresses (4-level
paging) and enables PAE.  The guest is always entered in long mode.
