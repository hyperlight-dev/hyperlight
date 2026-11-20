# Guest CPU features

Hyperlight exposes only the CPU features its guests need. Each extra feature
adds guest state that restore must reset.

## MSHV and WHP

MSHV and WHP guests see one set of CPU features, limited by the host. Both
backends pass the list in `partition_features.rs` to Hyper-V at partition
creation.

The list holds only features of the 21H2 compatibility version. The MSHV
driver creates every partition at that version. Hyper-V hides newer features
from such partitions.

The list keeps instruction-set features such as SSE4.2, BMI2, and AES. They
hold no state. It also keeps AVX through AVX-512. Restore resets their state
with the rest of the XSAVE area. It leaves out:

| Features | Reason |
| --- | --- |
| Speculation control: IBRS, STIBP, IBPB, SSBD, PSFD, BHI_DIS, VIRT_SPEC_CTRL | Guest `SPEC_CTRL` state. A guest is one trust domain. |
| TSX | `TSX_CTRL` state. |
| CET | Shadow-stack state and CET MSRs. |
| `TSC_ADJUST` | A write to `TSC` or `TSC_ADJUST` shifts both registers equally. Restoring both would undo the TSC rewind. |
| `TSC_DEADLINE`, WAITPKG, MPERF/APERF, RDPRU | Timer, wait, and counter state. RDPRU reads MPERF/APERF. |
| MPX, XFD, AMX | `BNDCFGS` and `XFD` MSR state. AMX needs XFD. |
| Supervisor XSAVE state | Used only by CET and PASID. |
| Hyper-V enlightenments | Guests do not use them. |

## KVM

KVM guests get the CPUID that KVM supports, minus VMX, SVM, x2APIC, and CET.
KVM's MSR filter denies every MSR the sandbox does not declare. See
[MSR state across restore](./msr.md).
