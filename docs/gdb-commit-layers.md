# GDB commit layers

Each layer is one signed commit. Backend layers depend on shared GDB support,
not on another backend's debugger.

```text
main
|-- A: shared GDB support
|   |-- B: WHP ARM64 GDB
|   `-- C: KVM ARM64 GDB
`-- D: ARM64 MSHV backend and CI
    `-- E: cherry-pick of A
        `-- F: MSHV ARM64 GDB
```

| Layer | Branch | Parent | Contents |
|---|---|---|---|
| A | `cshung/gdb-shared` | `main` | Architecture adapters, protocol handling, software breakpoints, page-sized memory access, guest debug vectors, snapshot recovery, common tests |
| B | `cshung/whp-aarch64-gdb` | A | WHP register access, HVC exits, debug registers, cache synchronization, platform enablement and tests |
| C | `cshung/kvm-aarch64-gdb` | A | KVM debug exits, debug registers, platform enablement and CI |
| D | `cshung/mshv-aarch64` | `main` | MSHV VM implementation, register access, reset, runner configuration and bounded CI scheduling |
| E | `cshung/mshv-aarch64-gdb-shared` | D | A's shared patch |
| F | `cshung/mshv-aarch64-gdb` | E | MSHV HVC exits, exception context, debug registers, platform enablement and tests |

A retains the existing x86_64 GDB platform guard. B, C and F enable their ARM64
backend. D and E provide an MSHV backend without ARM64 GDB enablement.
F rejects KVM debugging until C is integrated.

## Updating layers

* Update A for shared behavior. Rebuild B and C on A, cherry-pick A onto D as E,
  then rebuild F on E. Validate all three backend tips before publication.
* Update B or C for a backend-only debugger change. The sibling branch is independent.
* Update D for MSHV backend or CI changes. Rebuild E and F on D.
* Update F for an MSHV-only debugger change.
* Keep A and E patch-equivalent. E's parent and commit ID differ from A's.
* Squash each layer to one commit. Keep historical tips in local archive branches
  before rewriting published refs. Push with an explicit lease on each old remote tip.

Run formatting and Clippy on each affected tip. Rebuild guests for guest changes.
Run the common debugger tests, backend tests and real GDB client tests on WHP,
KVM and MSHV for shared updates. Validate both the default Linux driver selection
and the backend-only feature configuration. A history-only rewrite can reuse
runtime results when the corresponding source files are identical.

## Pull requests

A has a shared-support PR. B uses #1907, C uses #2016, and D uses #1626.
F has an MSHV GDB PR. E is a cherry-pick, not a second shared-support PR.

The branches live in `cshung/hyperlight`. Native GitHub stacks require head
branches in the upstream repository. These fork PRs target upstream `main` and
link their prerequisites and backend-only comparisons in their descriptions.
Their full PR diffs include unmerged prerequisites.
