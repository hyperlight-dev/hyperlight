# MSR state across restore

## Requirement

A snapshot restore must remove all model-specific register (MSR) state written
after the snapshot. The guest must observe the MSR values saved with the
restored state.

## Reset set

The reset set contains every MSR whose guest-written value can persist. Each
running snapshot stores values for this set. A snapshot created from a guest
binary has no saved MSR values, so restore uses the baseline captured when the
VM was created.

`MSR_TABLE` lists the MSRs that hold retained state restore must write. A
write-only command MSR holds no state, so it is absent from the table.

The resolved reset set contains the backend core set, required MTRRs, and the
validated allow list. Hyperlight sorts and deduplicates the indices before
capturing the initialization baseline.

The required invariant is:

```text
guest-writable retained state => host-readable and host-writable state
```

Host-readable state need not be guest-writable. Extra reset entries are safe.
`EFER`, `APIC_BASE`, `FS_BASE`, and `GS_BASE` belong to the special-register
state.

The two halves are established differently. Resolution checks the
host-readable half at run time: a candidate index enters the set only when the
host read succeeds, so an unreadable MSR is dropped. Nothing checks the
host-writable half at run time. It holds by construction. Every reset MSR is
stored in VP register state that the Hyper-V host interface both reads and
writes, except `KERNEL_GS_BASE`, a real register the host reads and writes
directly. Round-trip tests plant a guest value, restore, and assert that it does
not survive. Every future entry must remain host-readable and host-writable.

## Reset set justification

Each entry is grounded in how the Hyper-V hypervisor handles a guest access to
that register, confirmed against the Hyper-V source.

A register is reset when the guest can write it and Hyper-V keeps the written
value. Hyper-V keeps it in one of two ways: it stores the value in the VP's
saved register state, or it lets the guest write the real register directly.
Only `FS_BASE`, `GS_BASE`, and `KERNEL_GS_BASE` are written directly. Every
other register below is intercepted and stored. Hyper-V stores the value on both
Intel and AMD hosts.

Interception alone is not the test. Hyper-V also intercepts registers the guest
can only read, or that return a host-derived value. Those keep no
guest-controlled state and are not reset. Each row below names the guest state
that persists.

| MSR (index) | Retained guest state |
| --- | --- |
| SYSENTER CS, ESP, EIP (`0x174`-`0x176`) | Guest write retained. |
| STAR, LSTAR, CSTAR, SFMASK (`0xC000_0081`-`0xC000_0084`) | Guest write retained (syscall targets). |
| KERNEL_GS_BASE (`0xC000_0102`) | Guest write retained. Written to the real register, and reachable through `SWAPGS` without a `WRMSR`. |
| PAT (`0x277`) | Guest write retained. |
| DEBUGCTL (`0x1D9`) | Guest write retained. |
| SPEC_CTRL (`0x48`) | Guest write retained. |
| CET U_CET, S_CET, PL0-3_SSP, INTERRUPT_SSP_TABLE_ADDR (`0x6A0`, `0x6A2`, `0x6A4`-`0x6A8`) | Guest write retained. |
| XSS (`0xDA0`) | Guest write retained. |
| TSC (`0x10`) | Guest write retained. Hyper-V forbids intercepting its implemented TSC, so restore rewrites the captured value. |
| TSC_ADJUST (`0x3B`) | Guest write retained, independent of TSC. |
| TSC_AUX (`0xC000_0103`) | Guest write retained. |
| MTRRs (`0x2FF`, `0x200`-`0x21F`, `0x250`, `0x258`-`0x259`, `0x268`-`0x26F`) | Guest write retained (memory-type state). |
| TSX_CTRL (`0x122`) | Guest write retained. |
| XFD, XFD_ERR (`0x1C4`, `0x1C5`) | Guest write retained. |
| UMWAIT_CONTROL (`0xE1`) | Guest write retained. Intel only. |
| TSC_DEADLINE (`0x6E0`) | Guest write retained. |
| BNDCFGS (`0xD90`) | Guest write retained when the host supports MPX. A guest access faults otherwise. |
| MPERF, APERF (`0xE7`, `0xE8`) | Guest write retained in per-VP counters. |

Write-only command MSRs hold no state. A guest write performs an action and
leaves nothing to restore, so they are absent from the reset table and cannot
be allowed.

| MSR (index) | Behavior |
| --- | --- |
| PRED_CMD (`0x49`) | Guest write issues a prediction barrier. |
| FLUSH_CMD (`0x10B`) | Guest write flushes caches. |

Some registers are deliberately absent because guest access cannot leave state
outside another reset mechanism.

| MSR (index) | Why excluded |
| --- | --- |
| MISC_ENABLE (`0x1A0`) | Intercepted, but Hyper-V discards a guest write and returns a fixed value. No retained state. On AMD the access faults. See below. |
| FRED (`0x1CC`-`0x1D4`) | Retained only when the host exposes FRED, which Hyperlight does not. A guest access faults otherwise. |
| PASID (`0xD93`) | MSHV exposes ENQCMD on capable Intel hosts. PASID is a supervisor XSAVE component, so XSAVE reset clears it. WHP does not expose ENQCMD. |
| PMU: PMC0, PERFEVTSEL0, FIXED_CTR_CTRL, PERF_GLOBAL_CTRL (`0xC1`, `0x186`, `0x38D`, `0x38F`) | Heads of the performance-monitoring class. Hyper-V leaves these unimplemented for the guest and installs guest-accessible descriptors, sized to the CPU counter count, only when perfmon is enabled. Hyperlight enables no perfmon, so a guest access faults and retains nothing. |
| LBR: LBR_SELECT, LASTBRANCH_TOS, LBR_CTL, LBR_DEPTH (`0x1C8`, `0x1C9`, `0x14CE`, `0x14CF`) | Last-branch registers, gated with perfmon. A guest access faults and retains nothing while perfmon stays off. |

Hyper-V virtualizes `BNDCFGS`, `FRED`, and `PASID` only when the matching CPU
feature is exposed. `BNDCFGS` is reset because MPX is exposed by default on
capable hosts. `FRED` stays excluded because Hyperlight does not expose it.
MSHV can expose ENQCMD, but its XSAVE state mask then includes PASID. Hyperlight
clears PASID during XSAVE reset before restoring MSRs. The performance-monitoring
and last-branch registers remain inaccessible while perfmon is off.

## Snapshot validation

Snapshot MSR entries are untrusted. A snapshot records the reset values and the
capturing sandbox's allow list. `validate_snapshot` enforces two rules against
the destination VM's reset set:

* The snapshot's allow list must be a subset of the destination's. A
  destination that allows at least as much accepts the snapshot.
* Every supplied index must belong to the destination reset set.

Indices the destination resets but the snapshot omits take the destination's
creation-time baseline. A rejected restore poisons the sandbox before the guest
can run. Equivalent allow lists produce the same sorted reset set, regardless of
insertion order.

## Restore across allow lists

A restore or `from_snapshot` succeeds when the destination allow list is a
superset of the snapshot's, on every backend. The snapshot's allowed MSRs keep
their captured values. An MSR the destination allows but the snapshot did not
resets to the destination baseline. A non-superset allow list is rejected
uniformly.

The rule is backend independent even though each backend sizes its reset set
differently. KVM derives its reset set from the allow list. MSHV and WHP reset
the full host table. The allow-list subset check gates the restore before either
reset set is applied, so a flow that succeeds on one backend succeeds on all.

The superset check is the common rule across backends. MSHV and WHP accept any
allow list on their own. The shared check gives every backend KVM's constraint.

## Allow list

`SandboxConfiguration::allow_msrs` adds indices to the requested allow list. It
enforces capacity only. VM creation verifies that each index is resettable and
supported by the selected backend.

KVM requires the index in `KVM_GET_MSR_INDEX_LIST` and a successful host read
and write. MSHV and WHP require a named-register mapping and a successful host
read.

At most 16 distinct MSRs may be requested. KVM also limits the resulting
contiguous filter groups to 16.

## KVM

KVM installs a deny filter over the full MSR space. Allowed indices form the
only guest `RDMSR` and `WRMSR` paths through that filter. A denied access exits
to Hyperlight, injects `#GP`, and poisons the sandbox. The denied write stores
no state.

The KVM reset set contains the allow list plus `KERNEL_GS_BASE` and `TSC`.
`KERNEL_GS_BASE` is required because `WRGSBASE` followed by `SWAPGS` changes it
without `WRMSR`. `TSC` gives restore the same clock semantics on every backend.

KVM does not filter x2APIC indices `0x800..=0x8FF`. Hyperlight keeps the APIC in
xAPIC mode, where MSR access to that range raises `#GP`. `APIC_BASE` is not an
allowable MSR, so a guest cannot enable x2APIC. Snapshots created by Hyperlight
therefore retain `APIC_BASE.EXTD = 0`. File snapshots serialize `APIC_BASE`
without semantic validation, so the caller must trust the snapshot source as
required by the snapshot format.

## MTRRs

MSHV and WHP read `IA32_MTRRCAP` when the VM is created. The required set
contains `MTRR_DEF_TYPE`, each variable pair reported by `VCNT`, and all fixed
MTRRs.

Hyper-V accepts fixed-MTRR writes even when `MTRRCAP.FIX` is clear. All fixed
MTRRs are therefore required. Hyper-V supports at most 16 variable pairs. VM
creation fails when the count is larger or a required MTRR cannot be read.

## MSHV

MSHV has no per-MSR filter. Hyper-V permits an MSR intercept only for an
unimplemented index, which already faults for the guest, and cannot intercept
the implemented MSRs that hold retained state. Isolation therefore comes from
reset, not a deny filter.

The MSHV reset set contains every table entry that has a Hyper-V
register mapping and can be read, plus the allow list.

`msr_to_hv_reg_name` determines which indices the get and set path can reach.
The enumerated host index list does not identify retained state, so it does not
define the reset set.

MSHV maps `IA32_XSS` through `MSR_IA32_REGISTER_U_XSS`. It maps `IA32_MPERF`
and `IA32_APERF` to the per-VP `MCount` and `ACount` registers. TSX control,
XFD, MPX (`BNDCFGS`), WAITPKG (`UMWAIT_CONTROL`), and the TSC deadline timer
enter the reset set when their host-register probes succeed.

MSHV enables every host-supported processor feature unless the caller supplies
an explicit disabled-feature mask. Hyperlight supplies no mask. On capable
Intel hosts this can expose ENQCMD and its PASID MSR. MSHV reports PASID in the
partition XSAVE state mask, and Hyperlight's XSAVE reset clears it.

## WHP

WHP has no per-MSR filter. Its reset set contains every table entry
that has a WHP register name and can be read, plus the allow list.

WHP uses Germanium compatibility. Speculation control is off in its default
feature banks, and perfmon (the PMU and architectural LBR) is a separate
property WHP leaves off. Experimental `DEBUGCTL` bits stay disabled. The WHP
API defines no FRED feature and its supported feature mask omits ENQCMD, so WHP
cannot expose FRED or PASID.

Each guest MSR write is either captured for restore or unsupported by the
partition. Unsupported writes store no state.

## TSC

MSHV and WHP expose `TSC` as a host-writable register. Hyper-V stores `TSC` and
`TSC_ADJUST` independently, so restoring `TSC_ADJUST` cannot undo a guest
`WRMSR(TSC)`.

While time is running, Hyper-V preserves `TSC - TSC_ADJUST`: writing `TSC`
adds the same delta to `TSC_ADJUST`, and writing `TSC_ADJUST` adds its delta to
the internal TSC offset. Restoring `TSC` followed by `TSC_ADJUST` therefore
cancels any guest-controlled delta. Freezing partition time is not required for
isolation.

Hyper-V does not permit an intercept for its implemented `TSC` MSR. Restore
must therefore write the captured `TSC` value. KVM also restores `TSC` so all
backends rewind guest time with the rest of the snapshot state.

## Feature exposure

On MSHV and WHP a guest reaches an MSR only when the hypervisor exposes that
CPU feature to the partition. This gives three cases:

* Not exposed. Features the partition does not enable, such as the
  performance-monitoring unit, last-branch records, and FRED. Hyper-V may still
  model the register, but a guest access faults and stores no state until the
  feature is exposed.
* Exposed by default. Features the host CPU supports, such as TSC deadline,
  UMWAIT, TSX control, CET, `MPERF`/`APERF`, XFD, AMX, and MPX. Their MSRs
  must be in the reset set.
* Reset through another state class. MSHV can expose ENQCMD and PASID on
  capable Intel hosts. PASID is cleared by XSAVE reset, so it is not duplicated
  in the MSR reset set.

MSHV and WHP enable partition features differently. MSHV creates the partition
without an explicit feature mask, so it enables every processor feature the host
supports. WHP starts from the host-supported set with speculation control off.
MSHV exposes the broader surface and determines which registers the reset set
must cover.

Perfmon is not part of either default. The performance-monitoring unit and the
last-branch registers are a separate opt-in partition property, off by default
on both backends. Hyperlight never enables it, so those registers stay
unreachable regardless of the enable-everything processor-feature default.

Only reachable, retained MSRs need coverage, and retained state is always held
in a host-readable and writable register. The mapped registers therefore bound
the reset set: coverage is complete when every mapped register is in the reset
table and reset.

## Host-addressable but not guest-writable

A host register mapping does not imply the guest can write the MSR.
`IA32_MISC_ENABLE` (`0x1A0`) is the notable case. Hyper-V emulates it, discards
a guest write, and returns a fixed value to the guest regardless of what was
written. A guest cannot change it to any value, so it retains no guest state
and needs no reset. On AMD the guest access faults.

## Failed access reporting

A KVM-denied or Hyper-V-unsupported MSR access does not persist and poisons the
sandbox. The error type and its detail differ by backend.

* KVM traps the access at the deny filter. Hyperlight reports
  `MsrReadViolation` or `MsrWriteViolation`, naming the MSR index and, for a
  write, the value. The report is host-verified.
* MSHV and WHP have no host MSR trap. An unsupported access faults inside the
  guest as a general protection fault from Hyper-V, so Hyperlight reports
  `GuestAborted`. The message records the fault and the faulting instruction but
  does not identify the MSR. An exposed MSR can succeed even when absent from
  the allow list. Its retained state must be in the reset table.

Future work: the guest exception handler could decode a faulting `RDMSR` or
`WRMSR` and report the index, promoting the abort to a typed MSR violation on
MSHV and WHP. That index would be guest-reported and therefore advisory. It is
not implemented.

## Limitations

KVM's security boundary is structural because its deny filter bounds guest
writes. MSHV and WHP depend on the reset table and exposed processor
features.

The filterless backend tests run on one CPU model per runner. Model-specific
state absent on that CPU is not exercised. A backend that exposes a new
retained MSR feature needs a matching table entry before Hyperlight can use it
safely.

The ignored full-window audit probes fixed index ranges with a small set of
values. It cannot prove that every vendor MSR or accepted value is covered.
