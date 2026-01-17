# AArch64 Architecture Plan

This document outlines the intended file structure and trait design for adding aarch64 support to Hyperlight.

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

## Proposed Directory Structure

```
src/hyperlight_host/src/hypervisor/
├── mod.rs                    # Top-level exports, InterruptHandle trait
├── hyperlight_vm.rs          # Main orchestration (arch-agnostic interface)
├── vm_exit.rs                # VmExit enum (shared, arch-agnostic parts)
├── virtual_machine.rs        # VirtualMachine trait (arch-generic version)
│
├── arch/                     # Pure architecture knowledge
│   ├── mod.rs                # Re-exports current arch types
│   ├── x86_64/
│   │   ├── mod.rs
│   │   ├── regs.rs           # X64Registers (rax, rip, rflags...)
│   │   ├── sregs.rs          # X64SpecialRegs (GDT, CR0, EFER...)
│   │   ├── fpu.rs            # X64Fpu (xmm, mxcsr...)
│   │   └── debug.rs          # DR6, debug registers
│   └── aarch64/
│       ├── mod.rs
│       ├── regs.rs           # Aarch64Registers (x0-x30, pc, sp, pstate)
│       ├── sregs.rs          # Aarch64SystemRegs (SCTLR, TCR, TTBR, ESR...)
│       └── fpu.rs            # Aarch64Fpu (v0-v31, fpcr, fpsr)
│
├── backends/                 # Hypervisor backends
│   ├── mod.rs                # HypervisorBackend trait, detection
│   │
│   ├── kvm/
│   │   ├── mod.rs            # KvmVm shared code, is_hypervisor_present()
│   │   ├── x86_64.rs         # KvmVm impl for x86_64
│   │   └── aarch64.rs        # KvmVm impl for aarch64
│   │
│   ├── mshv/
│   │   ├── mod.rs            # MshvVm shared code
│   │   ├── x86_64.rs         # MshvVm impl for x86_64
│   │   └── aarch64.rs        # MshvVm impl for aarch64 (future)
│   │
│   ├── whp/
│   │   ├── mod.rs            # WhpVm shared code
│   │   ├── x86_64.rs         # WhpVm impl for x86_64
│   │   └── aarch64.rs        # WhpVm impl for Windows on ARM
│   │
│   └── hvf/
│       ├── mod.rs            # HvfVm shared code
│       └── aarch64.rs        # HvfVm impl for aarch64 only (macOS)
│
├── interrupt/                # InterruptHandle implementations
│   ├── mod.rs                # InterruptHandle, InterruptHandleImpl traits
│   ├── linux.rs              # LinuxInterruptHandle (for KVM/MSHV)
│   ├── windows.rs            # WindowsInterruptHandle (for WHP)
│   └── macos.rs              # HvfInterruptHandle (for HVF)
│
├── gdb/                      # GDB debugging (needs arch split)
│   ├── mod.rs
│   ├── x86_64.rs
│   └── aarch64.rs            # Future
│
└── crashdump/                # Crash dumps (needs arch split)
    ├── mod.rs
    └── x86_64.rs
```

## Register Type Differences

ARM and x86 have fundamentally different register architectures:

### x86_64 Registers

```rust
pub struct X64Registers {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rsp: u64, pub rbp: u64,
    pub r8: u64,  pub r9: u64,  pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

pub struct X64SpecialRegisters {
    pub cs: SegmentRegister,
    pub ds: SegmentRegister,
    pub es: SegmentRegister,
    pub fs: SegmentRegister,
    pub gs: SegmentRegister,
    pub ss: SegmentRegister,
    pub tr: SegmentRegister,
    pub ldt: SegmentRegister,
    pub gdt: TableRegister,
    pub idt: TableRegister,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

pub struct X64Fpu {
    pub fpr: [[u8; 16]; 8],   // x87 FPU registers
    pub xmm: [[u8; 16]; 16],  // SSE registers
    pub mxcsr: u32,
    // ...
}
```

### AArch64 Registers

```rust
pub struct Aarch64Registers {
    pub x: [u64; 31],      // x0-x30 (x30 = link register)
    pub sp: u64,           // stack pointer (separate from x regs)
    pub pc: u64,           // program counter
    pub pstate: u64,       // processor state (NZCV flags, EL, etc.)
}

pub struct Aarch64SystemRegisters {
    pub sctlr_el1: u64,    // system control
    pub ttbr0_el1: u64,    // page table base (user)
    pub ttbr1_el1: u64,    // page table base (kernel)  
    pub tcr_el1: u64,      // translation control
    pub mair_el1: u64,     // memory attributes
    pub vbar_el1: u64,     // exception vector base
    pub elr_el1: u64,      // exception return address
    pub spsr_el1: u64,     // saved processor state
    pub esr_el1: u64,      // exception syndrome
    pub far_el1: u64,      // fault address
    // No segments, no GDT/IDT, no EFER
}

pub struct Aarch64Fpu {
    pub v: [[u8; 16]; 32], // v0-v31 NEON/SIMD registers (128-bit each)
    pub fpcr: u32,         // FP control register
    pub fpsr: u32,         // FP status register
}
```

## Trait Design

### Approach: Module Re-exports (Recommended)

Use conditional compilation to re-export arch-specific types at a common path:

```rust
// hypervisor/arch/mod.rs
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// Re-export current arch's types at this level
#[cfg(target_arch = "x86_64")]
pub use x86_64::{Registers, SpecialRegisters, Fpu};

#[cfg(target_arch = "aarch64")]
pub use aarch64::{Registers, SpecialRegisters, Fpu};
```

Then callers just write:
```rust
use crate::hypervisor::arch::{Registers, SpecialRegisters, Fpu};
```

### VirtualMachine Trait

```rust
// hypervisor/virtual_machine.rs
use crate::hypervisor::arch::{Registers, SpecialRegisters, Fpu};

pub(crate) trait VirtualMachine: Debug + Send {
    /// Map memory region into this VM
    unsafe fn map_memory(&mut self, region: (u32, &MemoryRegion)) -> Result<()>;
    
    /// Unmap memory region from this VM
    fn unmap_memory(&mut self, region: (u32, &MemoryRegion)) -> Result<()>;
    
    /// Runs the vCPU until it exits
    fn run_vcpu(&mut self) -> Result<VmExit>;
    
    /// Get general-purpose registers
    fn regs(&self) -> Result<Registers>;
    
    /// Set general-purpose registers
    fn set_regs(&self, regs: &Registers) -> Result<()>;
    
    /// Get special/system registers
    fn sregs(&self) -> Result<SpecialRegisters>;
    
    /// Set special/system registers
    fn set_sregs(&self, sregs: &SpecialRegisters) -> Result<()>;
    
    /// Get FPU/SIMD registers
    fn fpu(&self) -> Result<Fpu>;
    
    /// Set FPU/SIMD registers
    fn set_fpu(&self, fpu: &Fpu) -> Result<()>;
    
    /// Get xsave area (crashdump)
    #[cfg(crashdump)]
    fn xsave(&self) -> Result<Vec<u8>>;
    
    /// Windows-specific partition handle
    #[cfg(target_os = "windows")]
    fn partition_handle(&self) -> WHV_PARTITION_HANDLE;
    
    /// Windows-specific memory setup completion
    #[cfg(target_os = "windows")]
    fn complete_initial_memory_setup(&mut self);
}
```

### VmExit Enum

Mostly architecture-agnostic, with arch-specific debug info:

```rust
pub(crate) enum VmExit {
    /// The vCPU has halted
    Halt(),
    
    /// The vCPU has issued a write to the given port with the given value
    IoOut(u16, Vec<u8>),
    
    /// The vCPU tried to read from the given (unmapped) addr
    MmioRead(u64),
    
    /// The vCPU tried to write to the given (unmapped) addr
    MmioWrite(u64),
    
    /// The vCPU execution has been cancelled
    Cancelled(),
    
    /// The vCPU has exited for a reason that is not handled
    Unknown(String),
    
    /// The operation should be retried (Linux EAGAIN)
    Retry(),
    
    /// Debug exit (architecture-specific payload)
    #[cfg(gdb)]
    Debug(DebugExit),
}

#[cfg(gdb)]
pub(crate) enum DebugExit {
    #[cfg(target_arch = "x86_64")]
    X86 { dr6: u64, exception: u32 },
    
    #[cfg(target_arch = "aarch64")]
    Aarch64 { esr: u64, far: u64 },
}
```

### InterruptHandle Traits

```rust
// hypervisor/interrupt/mod.rs

/// Public trait for interrupt handling (used by sandbox)
pub trait InterruptHandle: Send + Sync {
    fn kill(&self);
    fn killed(&self) -> bool;
    fn state(&self) -> u8;
}

/// Internal trait with platform-specific details
pub(crate) trait InterruptHandleImpl: InterruptHandle {
    /// Set the thread ID for the vcpu thread (Linux only)
    #[cfg(any(kvm, mshv3))]
    fn set_tid(&self);
    
    /// Set the running state
    fn set_running(&self);
    
    /// Clear the running state
    fn clear_running(&self);
    
    /// Wait for the running state to be set
    fn wait_for_running(&self);
}
```

## Migration Phases

### Phase 1: Extract arch module (no behavior change)
1. Create `arch/mod.rs`, `arch/x86_64/mod.rs`
2. Move `regs/` contents → `arch/x86_64/` with renames
3. Re-export from old locations for compatibility
4. Verify: `cargo check` on x86_64 Linux

### Phase 2: Add aarch64 arch types
1. Create `arch/aarch64/regs.rs`, `sregs.rs`, `fpu.rs` with proper ARM types
2. Update `arch/mod.rs` with conditional re-exports
3. Verify: `cargo check` on aarch64 macOS

### Phase 3: Restructure backends
1. Create `backends/` directory
2. Move `virtual_machine/kvm.rs` → `backends/kvm/mod.rs` + `backends/kvm/x86_64.rs`
3. Same for mshv, whp, hvf
4. Keep `VirtualMachine` trait generic
5. Verify: `cargo check` on all platforms

### Phase 4: Wire up KVM aarch64
1. Add `backends/kvm/aarch64.rs` with real implementation
2. Verify on aarch64 Linux (Parallels/UTM VM on Mac)

### Phase 5: Wire up HVF aarch64
1. Replace HVF stub with real implementation in `backends/hvf/aarch64.rs`
2. Verify on macOS aarch64 bare metal

## Reference Projects

These projects solve the same arch × backend problem:

| Project | Pattern | Link |
|---------|---------|------|
| Cloud Hypervisor | Backend-owns-intersection | `hypervisor/kvm/x86_64/` |
| crosvm | Flat files in backend | `hypervisor/kvm/x86_64.rs` |
| Firecracker | KVM-only, just arch split | `arch/x86_64/` |
| QEMU | Arch-owns-intersection | `target/arm/kvm/` |

Cloud Hypervisor's pattern is recommended for Hyperlight due to similar crate structure and Rust conventions.
