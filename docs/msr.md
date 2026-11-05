# MSR state across restore

## Requirement

A snapshot represents the state of a VM at a point in time. This includes MSR
state that can affect later execution.

After `Sandbox::restore`, the destination sandbox's MSR state must match
the supplied snapshot, regardless of prior execution in the sandbox.

## How snapshot and restore work

A snapshot saves the value of two groups of MSRs:

* The MSRs you list with `SandboxBuilder::guest_msrs`. List the ones your
  guest reads or writes.
* A small fixed core the guest can change without a `WRMSR`, so Hyperlight
  always saves it: `KERNEL_GS_BASE` (via `SWAPGS`), `TSC`, and active SSP on
  Hyper-V (via CET instructions).

`restore()` writes those saved values back and resets every other MSR to a
clean default. Nothing the guest did to an MSR after the snapshot carries
across restore.

On KVM, listing an MSR also lets the guest use it. The guest faults if it reads
or writes an MSR that is not listed. MSHV and WHP cannot enforce this, so there
the list only controls what is saved and restored.

## The reset set

Each backend provides the MSR indices it resets. VM creation reads them before
guest execution and stores the values as the destination baseline. Restore
writes the snapshot's value for each index it captured and the baseline for the
rest.

The backend owns discovery because register mappings and capabilities differ.
Sorting, deduplication, baseline capture, snapshot validation, and the fallback
to the destination baseline are shared in `MsrResetState`.

Every reset entry must represent guest-writable state the host can read
and write. On the Hyper-V backends the candidate table is derived from the
Hyper-V source and must be audited when that source, register mappings, or
feature exposure changes. VM creation probes each entry with a host read and a
host write. A candidate whose read fails is a feature absent on this host and is
dropped. A candidate that reads but cannot be written fails VM creation.

## Snapshot validation

Snapshot state is untrusted. Every `MsrEntry` in a snapshot must name a
declared guest MSR or a core MSR the destination resets. That set is
backend-independent, so a snapshot a KVM destination rejects is rejected the
same way on MSHV and WHP. A snapshot cannot carry an MSR the destination does
not restore. A read, validation, or write failure aborts restore and poisons
the sandbox.

The snapshot stores captured values only. It does not store the declared MSR
set. Restore applies each captured value and scrubs the rest of the reset set to
the destination baseline, so the destination configuration alone governs guest
MSR access.

`SandboxBuilder::guest_msrs` accepts at most 16 distinct indices. KVM
also supports at most 16 contiguous filter ranges. Each declared index must be
resettable, host-readable, and host-writable. Write-only command MSRs such as
`PRED_CMD` and `FLUSH_CMD` hold no resettable state and cannot be declared.

Some reset MSRs cannot be declared. Active SSP (`0x7A0`) survives restore
on the Hyper-V backends but cannot be declared. It has no architectural
`RDMSR`/`WRMSR` and is reachable only through the VP register API, so no guest
`WRMSR` sets it and no filter range names it.

MSHV and WHP cannot enforce declared MSRs during guest execution. There the
declared set governs only which MSRs survive restore. KVM additionally enforces
it as the guest's access filter.

## State restored elsewhere

Not all architecturally MSR-backed state uses the MSR reset path.

| State | Restore owner |
| --- | --- |
| `EFER`, `APIC_BASE`, `FS_BASE`, `GS_BASE` | Special-register snapshot state. |
| PASID (`0xD93`) on MSHV | XSAVE state. |

Keeping one owner avoids restoring the same state through two backend APIs.

## KVM

KVM installs a default-deny MSR filter. The declared guest MSRs supply the
only permitted filter ranges. VM creation rejects a declared index unless KVM
lists it and the host can read and write it.

The KVM reset set contains:

* Every declared guest MSR.
* `KERNEL_GS_BASE`, because `WRGSBASE` followed by `SWAPGS` can change it
  without `WRMSR`.
* `TSC`, so restore rewinds guest time on every backend.

The default-deny filter also covers KVM's custom MSR namespace
`0x4B56_4D00..=0x4B56_4DFF`.

Some CPU state does not pass through the filter. Hyperlight addresses those
paths separately:

* VMX and SVM are absent from guest CPUID, so the guest cannot enter VMX or
  SVM operation. Nested VMCS and VMCB state, including MSRs the CPU loads or
  stores through dedicated VMCS fields that the filter does not cover, is
  unreachable. Their setup MSRs remain denied.
* CET is absent from guest CPUID, so the guest cannot enable shadow stacks and
  cannot move active SSP. Active SSP has no architectural MSR, so it is absent
  from the KVM reset set and the backend never restores it. The CET MSRs stay
  denied and cannot be declared.
* x2APIC is absent from guest CPUID, so a guest never uses it. `IA32_APIC_BASE`
  (`0x1B`) is not declared, so the default-deny filter denies a `WRMSR` that
  enables x2APIC. Snapshot restore rejects the same value. The x2APIC range
  `0x800..=0x8FF` is exempt from the filter, so KVM permits it. Every access
  raises `#GP` because the guest is never in x2APIC mode. By default there is no
  in-kernel LAPIC to serve those MSRs. With the `hw-interrupts` feature the LAPIC
  stays in xAPIC mode. Either case leaves x2APIC unreachable.
* `FS_BASE` and `GS_BASE` are restored through special-register state.

A denied guest access raises `#GP`. Hyperlight reports `GuestAborted` and
poisons the sandbox.

## Hyper-V backends

MSHV and WHP cannot filter guest MSR access, so restore scrubs a broad set of
MSRs that hold guest state to the destination baseline before writing the saved
core and declared-MSR values. The scrub set is built from:

* Candidates the backend maps and can read, including state reachable only
  through the VP register API such as active SSP.
* MTRRs required by the virtual CPU's `MTRRCAP`.

The candidate table is not an intercept list. Hyper-V also intercepts read-only,
command, and host-derived MSRs that keep no guest-controlled value. An entry
belongs in the table only when guest execution can leave state that affects
later execution. The table ignores the host's MSR index list. That list does
not show which MSRs keep guest state.

Guest CPU features limit which MSRs MSHV and WHP guests can reach. See
[Guest CPU features](./guest-cpu.md).

A future partition-scrub hypercall will reset all MSRs directly and replace the
candidate table. WHP has kernel support. MSHV support is in progress. The saved
set stays the core plus the declared MSRs across that migration, so restore
behavior does not change.

### MTRRs

MSHV and WHP read `IA32_MTRRCAP` during VM creation. The reset set includes
`MTRR_DEF_TYPE`, every variable base and mask pair reported by `VCNT`, and all
fixed MTRRs. Hyper-V accepts fixed-MTRR writes even when `MTRRCAP.FIX` is
clear.

VM creation fails if `VCNT` exceeds the supported maximum of 16 or required
MTRRs cannot be read.

## Guest-state inventory

These MSRs hold guest-writable state. A backend resets each one the host
exposes. MSHV and WHP guests lack the features behind many of them.

| MSR (index) | State |
| --- | --- |
| SYSENTER CS, ESP, EIP (`0x174`-`0x176`) | System-call entry state. |
| STAR, LSTAR, CSTAR, SFMASK (`0xC000_0081`-`0xC000_0084`) | System-call target state. |
| KERNEL_GS_BASE (`0xC000_0102`) | Kernel GS base, including `SWAPGS` changes. |
| PAT (`0x277`) | Page attribute state. |
| DEBUGCTL (`0x1D9`) | Debug control state. |
| SPEC_CTRL (`0x48`), VIRT_SPEC_CTRL (`0xC001_011F`) | Speculation control state. |
| CET (`0x6A0`, `0x6A2`, `0x6A4`-`0x6A8`) | CET control and shadow-stack state. |
| Active SSP (`0x7A0`) | Shadow-stack pointer. Reset on Hyper-V backends through the VP register API. Cannot be declared: no architectural `RDMSR`/`WRMSR`. |
| XSS (`0xDA0`) | Extended supervisor state mask. |
| TSC, TSC_ADJUST, TSC_AUX (`0x10`, `0x3B`, `0xC000_0103`) | Guest clock state. |
| MTRRs (`0x2FF`, `0x200`-`0x21F`, `0x250`, `0x258`-`0x259`, `0x268`-`0x26F`) | Memory-type state. |
| TSX_CTRL (`0x122`) | TSX control state. |
| XFD, XFD_ERR (`0x1C4`, `0x1C5`) | Extended-feature disable state. |
| UMWAIT_CONTROL (`0xE1`) | WAITPKG control state. |
| TSC_DEADLINE (`0x6E0`) | Deadline-timer state. |
| BNDCFGS (`0xD90`) | MPX bounds configuration. |
| MPERF, APERF (`0xE7`, `0xE8`) | Per-VP performance counters. |

These classes do not need MSR reset entries.

| MSR (index) | Reason |
| --- | --- |
| PRED_CMD (`0x49`) | Write-only command. Issues a prediction barrier. |
| FLUSH_CMD (`0x10B`) | Write-only command. Flushes caches. |
| MISC_ENABLE (`0x1A0`) | Hyper-V discards writes. AMD faults the access. |
| FRED (`0x1CC`-`0x1D4`) | Hyperlight exposes no FRED feature. |
| PMU (`0xC1`, `0x186`, `0x38D`, `0x38F`) | Hyperlight leaves perfmon disabled. |
| LBR (`0x1C8`, `0x1C9`, `0x14CE`, `0x14CF`) | Hyperlight leaves perfmon disabled. |

## Testing

Focused tests cover:

* Guest-written MSR values across snapshot, restore, and clone lifecycles.
* Saving and restoring the core and declared MSRs, and scrubbing of undeclared
  MSRs on the Hyper-V backends.
* Backend reset-set discovery and snapshot index validation.
* `SWAPGS`, TSC, MTRR, and feature-gated Hyper-V state.
* KVM nested-virtualization, x2APIC, and custom-MSR denial.

The ignored full-window audit probes additional Hyper-V MSR ranges on the CI
CPU. It is a regression tool, not a complete inventory of vendor MSRs.

## Future work

* Replace the Hyper-V candidate table with the partition-scrub hypercall as
  MSHV gains kernel support. WHP already has it.
* Exercise MSHV and WHP on more CPU models. Their reachable MSR surfaces depend
  on host features.
* Extend the inventory when Hyperlight enables new CPU features such as
  perfmon, FRED, or nested virtualization.