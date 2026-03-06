# AArch64 Architecture Plan

This document outlines the plan for adding aarch64 cross-compilation support to Hyperlight.

## Goal

Make the entire workspace compile successfully for `aarch64-unknown-linux-gnu` while maintaining
identical behavior on x86_64. No aarch64 implementation is added — only stubs and conditional
compilation gates so the build succeeds. This is the **first PR** toward full aarch64 support.

## Current State: Cross-Compilation Errors

Running `cargo build --target aarch64-unknown-linux-gnu` currently fails. The first errors come from
`hyperlight-common`, which blocks all downstream crates. Fixing each crate in dependency order
will reveal errors in subsequent crates.

### Error inventory by crate (dependency order)

#### 1. `hyperlight-common`
| File | Error | Cause |
|------|-------|-------|
| `src/layout.rs:19` | `file not found for module arch` | `cfg_attr` has paths for `x86_64` and `x86` but not `aarch64` |
| `src/vmem.rs:19` | `file not found for module arch` | Same — no `aarch64` path mapping |

The `arch/aarch64/` directory exists but is **empty**.

#### 2. `hyperlight-host` (blocked by #1)
| File | Error | Cause |
|------|-------|-------|
| `src/hypervisor/regs/standard_regs.rs` | `CommonRegisters` has x86 fields (rax, rbx, rip...) | No arch gate, no aarch64 equivalent |
| `src/hypervisor/regs/special_regs.rs` | `CommonSpecialRegisters` has x86 fields (cr0, efer, gdt...) | Same |
| `src/hypervisor/regs/fpu.rs` | `CommonFpu` has x86 fields (fpr, xmm, mxcsr) | Same |
| `src/hypervisor/regs/debug_regs.rs` | `CommonDebugRegs` has x86 fields (dr0-dr7) | Same |
| `src/hypervisor/hyperlight_vm.rs` | Uses x86 register names (`rip`, `rsp`, `rdi`, `rsi`, `rdx`, `rcx`, `rflags`, `rax`, `cr3`) throughout; uses `std::arch::x86_64::__cpuid_count` | 3000-line file deeply coupled to x86 |
| `src/hypervisor/virtual_machine/kvm.rs` | CPUID manipulation, `kvm_regs`/`kvm_sregs`/`kvm_fpu` types | KVM x86 API types |
| `src/hypervisor/virtual_machine/mshv.rs` | `hv_message_type_HVMSG_X64_*`, `HV_X64_REGISTER_*` | MSHV x86 API types |
| `src/hypervisor/virtual_machine/mod.rs:115` | `compile_error!` if no hypervisor type available | Will fire if kvm/mshv features disabled |
| `src/hypervisor/gdb/arch.rs` | x86 exception IDs, INT3 opcode, DR6 flags | No arch gate |
| `src/hypervisor/gdb/x86_64_target.rs` | `GdbTargetArch = X86_64_SSE` | No arch gate |
| `src/hypervisor/crashdump.rs` | `NT_X86_XSTATE`, x86-64 register layout | No arch gate |
| `src/mem/mgr.rs:751` | `init-paging` code gated on `target_arch = "x86_64"` | Already gated — OK |
| `src/mem/elf.rs` | ELF relocations | Already has both x86_64 and aarch64 paths — OK |

## Patterns Researched from the Rust Ecosystem

The following crates were studied for how they cleanly separate architecture-specific code:

### Crates Researched

| Crate | Pattern Used | Notes |
|-------|-------------|-------|
| **`kvm-bindings`** (rust-vmm) | Flat arch modules + wildcard re-export | `mod x86_64; pub use self::x86_64::*;` / `mod arm64; pub use self::arm64::*;` gated by `cfg(target_arch)`. Simple, no traits. |
| **Cloud Hypervisor** (`hypervisor` crate) | Backend-owns-intersection + `cfg` on trait methods | `arch/x86/` and `arch/aarch64/` for types. Trait methods gated: `#[cfg(target_arch = "x86_64")] fn get_sregs()`. Backend dirs contain `kvm/x86_64/`, `kvm/aarch64/`. |
| **Firecracker** (`vmm` crate) | Arch-owns-everything + re-export at `arch/mod.rs` | `arch/x86_64/` and `arch/aarch64/` each contain full `kvm/`, `vcpu/`, `vm/` modules. `arch/mod.rs` re-exports with `pub use x86_64::*`. Clean — callers never write `x86_64::`. |
| **`libc`** (rust-lang) | Deep platform tree | `unix/linux/arch/` hierarchy. Only the matching arch module compiles. |
| **`stdarch`** / `core::arch` (rust-lang) | Separate arch crate modules | `x86_64/`, `aarch64/` directories. Each arch is self-contained. |
| **`rustix`** (bytecodealliance) | Backend abstraction layer | `backend/` directory with `linux_raw/`, `libc/` backends, each internally split by arch. |

### Recommended Pattern for Hyperlight

Hyperlight should use a combination of **Firecracker's re-export pattern** and **Cloud Hypervisor's backend structure**:

1. **`cfg_attr` path switching** for arch-specific module files (already used in `hyperlight-common` and `hyperlight-guest`). Extend to aarch64.
2. **`cfg(target_arch)` module gating with wildcard re-exports** for register types in `hyperlight-host` (like `kvm-bindings`).
3. **`cfg(target_arch)` on entire impl blocks and functions** rather than on individual struct fields — avoids `#[cfg]` spaghetti inside struct definitions.
4. **Stub modules for unimplemented architectures** — compile but `unimplemented!()` at runtime.

Key principle: **each arch-specific module should be self-contained**. Callers should never write `x86_64::CommonRegisters` — they write `CommonRegisters` and the right type is selected at compile time.

## Scope: Phase 1 — Compile for aarch64 (No Behavior Change)

The goal is: `cargo build --target aarch64-unknown-linux-gnu -p hyperlight-host` succeeds with **zero aarch64 implementation**. All aarch64 paths are stubs. All x86_64 behavior is identical.

Guest crates (`hyperlight-guest`, `hyperlight-guest-bin`, `hyperlight-guest-capi`, test guests) are **out of scope** for this PR — they will be addressed in a separate guest-support PR.

### Strategy

For `hyperlight-common` (shared dependency) and `hyperlight-host`, add the minimum conditional compilation needed:

1. **Add `cfg_attr` / `cfg` gates** — never delete x86 code, only wrap it
2. **Create stub files** — aarch64 modules that export the same symbols but with placeholder types or `todo!()` bodies
3. **Avoid trait-level abstraction changes** — the `VirtualMachine` trait keeps its current shape; the register types it uses become arch-specific via re-exports

### Changes by Crate

#### 1. `hyperlight-common`

**Files to modify:**
- `src/layout.rs` — add `#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/layout.rs")]`
- `src/vmem.rs` — add `#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/vmem.rs")]`

**Files to create:**
- `src/arch/aarch64/layout.rs` — stub with same public API as `arch/amd64/layout.rs` (constants can differ, functions can `todo!()`)
- `src/arch/aarch64/vmem.rs` — stub with same public API as `arch/amd64/vmem.rs`

#### 2. `hyperlight-host`

This is the largest change. The approach: **gate entire modules and files** rather than inserting `cfg` attributes inside functions.

**Register types (`src/hypervisor/regs/`):**

The current `CommonRegisters`, `CommonSpecialRegisters`, `CommonFpu`, `CommonDebugRegs` types are x86-only. Two options:

- **Option A (minimal, recommended for Phase 1):** Gate the entire `regs/` module and all four files behind `#[cfg(target_arch = "x86_64")]`, then create parallel aarch64 stub files that define the same type names with aarch64-appropriate (or placeholder) fields. Use `cfg_attr` path switching or conditional `mod` + `pub use` in `regs.rs`.

- **Option B (premature):** Introduce a `Registers` trait. This is too much refactoring for Phase 1.

Recommended: **Option A using `kvm-bindings` style**:

```rust
// regs.rs (new version)
#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::*;
```

Where `x86_64/` contains the current four files renamed, and `aarch64/` contains stubs exporting the same names (`CommonRegisters`, `CommonSpecialRegisters`, `CommonFpu`, `CommonDebugRegs`) but with aarch64-appropriate fields (can be empty structs initially or placeholder fields).

**`hyperlight_vm.rs` (3010 lines):**

This file is deeply x86-specific. Most of it uses x86 register field names directly. For Phase 1, the cleanest approach is to gate the entire `HyperlightVM` implementation behind `#[cfg(target_arch = "x86_64")]` and provide a stub aarch64 version that compiles but is not functional.

Approach:
- Wrap the entire `impl HyperlightVM` block (or the struct + impl together) with `#[cfg(target_arch = "x86_64")]`
- Create a minimal `hyperlight_vm_aarch64.rs` stub that defines the same struct and implements the same interface with `todo!()` bodies
- Use `cfg_attr` path switching or conditional includes

**Virtual machine backends (`src/hypervisor/virtual_machine/`):**
- `kvm.rs` — gate behind `#[cfg(target_arch = "x86_64")]` (KVM x86 CPUID code, x86 register types). Create `kvm_aarch64.rs` stub or split `kvm.rs` into `kvm/mod.rs` + `kvm/x86_64.rs` + `kvm/aarch64.rs`
- `mshv.rs` — gate behind `#[cfg(target_arch = "x86_64")]` (MSHV x64 types). Stub for aarch64.
- `mod.rs` — remove the `compile_error!` for no hypervisor, or adjust it to be aware that aarch64+linux with kvm feature is valid

**GDB (`src/hypervisor/gdb/`):**
- Gate `arch.rs` and `x86_64_target.rs` behind `#[cfg(target_arch = "x86_64")]`
- The `gdb` module is already behind `#[cfg(gdb)]` so this is low priority

**Crashdump (`src/hypervisor/crashdump.rs`):**
- Gate behind `#[cfg(target_arch = "x86_64")]` (already behind `#[cfg(crashdump)]`)

**Memory management (`src/mem/`):**
- `mgr.rs:751` — already gated on `target_arch = "x86_64"` — OK
- `elf.rs` — already has both x86_64 and aarch64 paths — OK

### File Change Summary

| Action | Path | Description |
|--------|------|-------------|
| **modify** | `hyperlight-common/src/layout.rs` | Add aarch64 cfg_attr |
| **modify** | `hyperlight-common/src/vmem.rs` | Add aarch64 cfg_attr |
| **create** | `hyperlight-common/src/arch/aarch64/layout.rs` | Stub |
| **create** | `hyperlight-common/src/arch/aarch64/vmem.rs` | Stub |
| **modify** | `hyperlight-host/src/hypervisor/regs.rs` | Restructure with cfg(target_arch) re-exports |
| **move** | `hyperlight-host/src/hypervisor/regs/*.rs` | → `regs/x86_64/` subdirectory |
| **create** | `hyperlight-host/src/hypervisor/regs/aarch64/*.rs` | Stub register types |
| **modify** | `hyperlight-host/src/hypervisor/hyperlight_vm.rs` | Gate x86 code, add aarch64 stub |
| **modify** | `hyperlight-host/src/hypervisor/virtual_machine/kvm.rs` | Gate x86-specific parts |
| **modify** | `hyperlight-host/src/hypervisor/virtual_machine/mshv.rs` | Gate x86-specific parts |
| **modify** | `hyperlight-host/src/hypervisor/virtual_machine/mod.rs` | Adjust compile_error for aarch64 |
| **modify** | `hyperlight-host/src/hypervisor/gdb/arch.rs` | Gate behind target_arch = "x86_64" |
| **modify** | `hyperlight-host/src/hypervisor/gdb/x86_64_target.rs` | Gate behind target_arch = "x86_64" |
| **modify** | `hyperlight-host/src/hypervisor/crashdump.rs` | Gate behind target_arch = "x86_64" |

### Verification Criteria

1. `cargo build` on x86_64 Linux — must produce identical binary (no behavior change)
2. `cargo build --target aarch64-unknown-linux-gnu -p hyperlight-host` — must succeed (cross-compile)
3. `cargo test` on x86_64 Linux — all existing tests pass
4. `cargo clippy --target aarch64-unknown-linux-gnu -p hyperlight-host` — no warnings
5. `just test-like-ci` — passes

### Principles

- **No new crates or dependencies** added
- **No trait redesign** — the `VirtualMachine` trait keeps its current shape
- **No new abstractions** — just conditional compilation (`cfg`) and stub modules
- **Minimal diff** — prefer wrapping existing code with `cfg` over moving/rewriting it
- **Stubs use `todo!()`** not `unimplemented!()` — clearer intent that implementation is planned

## Future Work (Separate PRs)

These are **out of scope** for the first PR but documented for planning:

### Phase 2: Guest crate aarch64 cross-compilation

Known errors to fix:

| Crate | File | Error | Cause |
|-------|------|-------|-------|
| `hyperlight-guest` | `src/layout.rs:17-18` | Missing `aarch64` cfg_attr path | Same pattern as hyperlight-common |
| `hyperlight-guest` | `src/prim_alloc.rs:17-18` | Missing `aarch64` cfg_attr path | Same pattern |
| `hyperlight-guest` | `src/exit.rs` | `asm!("out dx, eax")` with no arch gate | x86 I/O port assembly used unconditionally |
| `hyperlight-guest` | `src/lib.rs:18` | `compile_error!` for trace_guest on non-x86_64 | Only blocks trace_guest feature, not main build |
| `hyperlight-guest-bin` | `src/lib.rs:36-37` | `cfg_attr` only maps `x86_64` → `arch/amd64/mod.rs` | No aarch64 path for the `arch` module |
| `hyperlight-guest-bin` | `src/paging.rs` | x86 `asm!` (mov cr3, mov cr0) with no arch gate | Inline assembly is purely x86 |
| `hyperlight-guest-bin` | `src/lib.rs` `mem_profile` | `asm!("out dx, al")` with no arch gate | x86 assembly in allocator tracing |
| `hyperlight-guest-tracing` | — | Already gated | `cfg(target_arch = "x86_64")` in Cargo.toml — OK |
| test guests | `simpleguest/src/main.rs` | x86 asm: `hlt`, `int3`, `ud2`, etc. | No arch gate on test code |
| test guests | `dummyguest/src/main.rs` | x86 asm: `hlt`, `mov al, [0x8000]` | No arch gate on test code |

Changes needed:
- `hyperlight-guest`: add `cfg_attr` for aarch64 paths in `layout.rs`, `prim_alloc.rs`; gate x86 asm in `exit.rs`
- `hyperlight-guest-bin`: add aarch64 arch module stub; gate x86 asm in `paging.rs` and `lib.rs`
- Test guests: gate x86-specific test code or exclude from aarch64 builds
- Create stub files: `hyperlight-guest/src/arch/aarch64/{layout,prim_alloc}.rs`, `hyperlight-guest-bin/src/arch/aarch64/mod.rs`

### Phase 3: Implement aarch64 register types
- Replace stub register types with real AArch64 register structs
- Implement conversions to/from KVM aarch64 register types

### Phase 4: Restructure backends
- Split `kvm.rs` → `kvm/mod.rs` + `kvm/x86_64.rs` + `kvm/aarch64.rs`
- Same for `mshv.rs`
- Implement `VirtualMachine` trait for KVM on aarch64

### Phase 5: Implement guest-side aarch64
- Real `exit.rs` using MMIO or HVC for guest→host communication
- Real `paging.rs` with AArch64 page table manipulation
- Exception handling, context save/restore for AArch64

### Phase 6: Add HVF backend (macOS)
- New `hvf/` backend module for Apple Hypervisor.framework

## The Problem: Two Dimensions

Hyperlight needs to support multiple architectures AND multiple hypervisor backends:

| Backend | x86_64 | aarch64 |
|---------|--------|---------|
| KVM     | ✓      | ✓       |
| MSHV    | ✓      | ✓       |
| WHP     | ✓      | ✓ (Windows on ARM) |
| HVF     | ✗      | ✓ (macOS only)     |

Note: HVF is the only single-architecture backend — Apple dropped x86 HVF when transitioning to Apple Silicon.

Code falls into three categories:
1. **Pure architecture** — page tables, registers, memory layout (same across backends)
2. **Pure hypervisor** — API calls, VM creation, memory mapping (similar across arches)
3. **Intersection** — vCPU setup using a specific backend's API for a specific arch

## Reference Projects

These projects solve the same arch × backend problem and were studied for this plan:

| Project | Pattern | How it separates arch code |
|---------|---------|---------------------------|
| **kvm-bindings** (rust-vmm) | Flat arch module + wildcard re-export | `mod x86_64; pub use self::x86_64::*;` gated by `cfg(target_arch)` — callers see one flat namespace |
| **Cloud Hypervisor** | Backend-owns-intersection + cfg on trait methods | `arch/x86/` and `arch/aarch64/` for types; `kvm/x86_64/` and `kvm/aarch64/` for backend code; trait methods gated with `#[cfg(target_arch)]` |
| **Firecracker** | Arch-owns-everything + re-export | `arch/x86_64/` and `arch/aarch64/` each contain full `kvm/`, `vcpu/`, `vm/` trees; `arch/mod.rs` re-exports the right one |
| **libc** (rust-lang) | Deep platform tree | `unix/linux/arch/` hierarchy, only matching arch compiles |
| **stdarch** / `core::arch` (rust-lang) | Separate arch module trees | `x86_64/`, `aarch64/` directories, each self-contained |
| **rustix** (bytecodealliance) | Backend abstraction layer | `backend/` dir with `linux_raw/`, `libc/`, each internally split by arch |
