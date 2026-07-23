# MSR state across restore

## Requirement

A snapshot represents the state of a VM at a point in time. This includes MSR
state that can affect later execution.

After `MultiUseSandbox::restore`, the destination sandbox's MSR state must match
the supplied snapshot, regardless of prior execution in the sandbox.

## How restore works

Each backend provides the MSR indices it must reset. VM creation reads these
indices before guest execution and stores the values as the destination
baseline.

A snapshot captured from a VM stores:

* The value of every MSR in the source VM's reset set.
* The source sandbox's MSR allow list.

Restore resolves the snapshot against the destination reset set. A value stored
in the snapshot is restored directly. An index present only in the destination
uses the destination baseline. This supports restoring into a sandbox whose
allow list is a superset of the source allow list.

The backend writes the complete resolved set before guest execution resumes. A
read, validation, or write failure aborts restore and poisons the sandbox.

## Why the reset set is backend-specific

KVM can deny individual guest `RDMSR` and `WRMSR` operations. Its reset set can
therefore be limited to allowed MSRs and state changed through other CPU
instructions.

MSHV and WHP do not provide Hyperlight with an equivalent per-MSR filter.
Their reset sets must include every retained MSR state reachable through the
partition's exposed CPU features. Hyperlight keeps a shared candidate table for
these Hyper-V backends and lets each backend select entries it can map and read.

The backend owns discovery because register mappings and capabilities differ.
Sorting, deduplication, baseline capture, snapshot validation, and fallback to
the destination baseline are shared in `MsrResetState`.

Every reset entry must represent guest-writable retained state that the host can
read and write. The shared candidate table is derived from the Hyper-V source
and must be audited when that source, register mappings, or feature exposure
changes. VM creation probes host reads. Table construction and round-trip
tests currently cover host write support.

## Snapshot validation and access policy

Snapshot state is untrusted. Every `MsrEntry` stored in a snapshot must name an
index in the destination VM's reset set. This prevents a snapshot from using
the backend register interface to write arbitrary host-visible registers.

The allow list is separate from the captured values:

* `msrs` contains the complete source reset state.
* `allowed_msrs` records which MSRs the source guest could access through the
  configured policy.

The source allow list must be a subset of the destination allow list. The
destination configuration remains authoritative. Snapshot data cannot expand
the destination policy or replace its KVM filter.

`SandboxConfiguration::allow_msrs` accepts at most 16 distinct indices. KVM
also supports at most 16 contiguous filter ranges. Each allowed index must be
resettable, host-readable, and host-writable. Write-only command MSRs such as
`PRED_CMD` and `FLUSH_CMD` hold no resettable state and cannot be allowed.

Reset and allowable are not the same set. Active SSP (`0x7A0`) is reset on the
Hyper-V backends but cannot be allowed. It has no architectural `RDMSR`/`WRMSR`
and is reachable only through the VP register API, so no guest `WRMSR` sets it
and no filter range names it.

MSHV and WHP cannot enforce the allow list during guest execution. They retain
it in snapshots so restore compatibility has the same meaning on every
backend.

## State restored elsewhere

Not all architecturally MSR-backed state uses the MSR reset path.

| State | Restore owner |
| --- | --- |
| `EFER`, `APIC_BASE`, `FS_BASE`, `GS_BASE` | Special-register snapshot state. |
| PASID (`0xD93`) on MSHV | XSAVE state. |

Keeping one owner avoids restoring the same state through two backend APIs.

## KVM

KVM installs a default-deny MSR filter. The configured allow list supplies the
only permitted filter ranges. VM creation rejects an allowed index unless KVM
lists it and the host can read and write it.

The KVM reset set contains:

* Every allowed MSR.
* `KERNEL_GS_BASE`, because `WRGSBASE` followed by `SWAPGS` can change it
  without `WRMSR`.
* `TSC`, so restore rewinds guest time on every backend.

The default-deny filter also covers KVM's custom MSR namespace
`0x4B56_4D00..=0x4B56_4DFF`.

Some CPU state does not pass through the filter. Hyperlight addresses those
paths separately:

* VMX and SVM are removed from guest CPUID, so nested VMCS and VMCB state is
  unreachable. Their setup MSRs remain denied.
* Hyperlight keeps the APIC in xAPIC mode. Guest writes to `APIC_BASE` and the
  x2APIC range `0x800..=0x8FF` are denied. Snapshot restore also rejects an
  `APIC_BASE` value with the x2APIC enable bit set.
* `FS_BASE` and `GS_BASE` are restored through special-register state.

A denied guest access raises `#GP`. Hyperlight reports `GuestAborted` and
poisons the sandbox.

## Hyper-V backends

MSHV and WHP build their reset sets from:

* Retained-state candidates the backend maps and can read, including state
  reachable only through the VP register API such as active SSP.
* MTRRs required by the virtual CPU's `MTRRCAP`.
* The validated allow list.

The shared candidate table is not an intercept list. Hyper-V also intercepts
read-only, command, and host-derived MSRs that retain no guest-controlled
value. An entry belongs in the table only when guest execution can leave state
that affects later execution.

### MSHV

MSHV enables the processor features supported by the host unless a partition
feature mask disables them. Its guest-visible MSR surface therefore varies by
host CPU.

MSHV maps `IA32_XSS` through `MSR_IA32_REGISTER_U_XSS`. It maps `IA32_MPERF`
and `IA32_APERF` through the per-VP `MCount` and `ACount` registers. TSX,
WAITPKG, CET, XFD, MPX, and deadline-timer state enter the reset set when the
host exposes and maps them.

The host's enumerated MSR index list does not identify retained state, so it
does not define the reset set.

On capable Intel hosts MSHV can expose ENQCMD and PASID. PASID is a supervisor
XSAVE component, so XSAVE restore owns it.

### WHP

WHP's default feature banks disable speculation control, experimental
`DEBUGCTL` bits, and performance monitoring. Its supported feature mask omits
ENQCMD and defines no FRED feature, so WHP does not expose PASID or FRED.

WHP maps supported MSRs to `WHV_REGISTER_NAME` values. The same mapping is used
for snapshot reads and restore writes.

### MTRRs

MSHV and WHP read `IA32_MTRRCAP` during VM creation. The reset set includes
`MTRR_DEF_TYPE`, every variable base and mask pair reported by `VCNT`, and all
fixed MTRRs. Hyper-V accepts fixed-MTRR writes even when `MTRRCAP.FIX` is
clear.

VM creation fails if `VCNT` exceeds the supported maximum of 16 or required
MTRRs cannot be read.

### TSC

Hyper-V stores `TSC` and `TSC_ADJUST` independently. While time runs, it
preserves `TSC - TSC_ADJUST`: writing `TSC` also changes `TSC_ADJUST`, while
writing `TSC_ADJUST` changes the internal TSC offset.

Restore writes `TSC` before `TSC_ADJUST`. The two writes remove the guest's
delta without freezing partition time. KVM also restores `TSC` so all backends
use the same guest-time semantics.

## Retained-state inventory

These MSRs are reset when supported by the selected backend and host.

| MSR (index) | Retained state |
| --- | --- |
| SYSENTER CS, ESP, EIP (`0x174`-`0x176`) | System-call entry state. |
| STAR, LSTAR, CSTAR, SFMASK (`0xC000_0081`-`0xC000_0084`) | System-call target state. |
| KERNEL_GS_BASE (`0xC000_0102`) | Kernel GS base, including `SWAPGS` changes. |
| PAT (`0x277`) | Page attribute state. |
| DEBUGCTL (`0x1D9`) | Debug control state. |
| SPEC_CTRL (`0x48`), VIRT_SPEC_CTRL (`0xC001_011F`) | Speculation control state. |
| CET (`0x6A0`, `0x6A2`, `0x6A4`-`0x6A8`) | CET control and shadow-stack state. |
| Active SSP (`0x7A0`) | Shadow-stack pointer. Reset on Hyper-V backends through the VP register API. Not allowable: no architectural `RDMSR`/`WRMSR`. |
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
* Source and destination allow-list compatibility.
* Backend reset-set discovery and snapshot index validation.
* `SWAPGS`, TSC, MTRR, and feature-gated Hyper-V state.
* KVM nested-virtualization, x2APIC, and custom-MSR denial.

The ignored full-window audit probes additional Hyper-V MSR ranges on the CI
CPU. It is a regression tool, not a complete inventory of vendor MSRs.

## Future work

* Verify host write support for every resolved filterless reset entry during VM
  creation. Allowed entries already receive a read and write check.
* Exercise MSHV and WHP on more CPU models. Their reachable MSR surfaces depend
  on host features.
* Extend the inventory when Hyperlight enables new CPU features such as
  perfmon, FRED, or nested virtualization.