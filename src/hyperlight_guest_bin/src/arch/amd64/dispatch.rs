/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

//! This module contains the architecture-specific dispatch function
//! entry sequence

// The extern "C" here is a lie until #![feature(abi_custom)] is stabilised
unsafe extern "C" {
    /// There are two reasons that we need an architecture-specific
    /// assembly stub currently: (1) to ensure that the fact that the
    /// dispatch function never returns but can be executed again is
    /// OK (i.e. we must ensure that there is no stack frame
    /// teardown); (2) at least presently, to ensure that the TLB is
    /// flushed in certain cases.
    ///
    /// # TLB flushing
    ///
    /// The hyperlight host likes to use one partition and reset it in
    /// various ways; if that has happened, there might stale TLB
    /// entries hanging around from the former user of the
    /// partition. Flushing the TLB here is not quite the right thing
    /// to do, since incorrectly cached entries could make even this
    /// code not exist, but regrettably there is not a simple way for
    /// the host to trigger flushing when it ought to happen, so for
    /// now this works in practice, since the text segment is always
    /// part of the big identity-mapped region at the base of the
    /// guest.  The stack, however, is not part of the snapshot region
    /// which is (in practice) idmapped for the relevant area, so this
    /// cannot touch the stack until the flush is done.
    ///
    /// Currently this just always flips CR4.PGE back and forth to
    /// trigger a tlb flush. We should use a faster approach where
    /// available
    ///
    /// # ABI
    ///
    /// The ZF should be set if a TLB flush is required on this call
    /// (e.g. the first call after a snapshot restore)
    ///
    /// The stack pointer should, unusually for amd64, by 16-byte
    /// aligned at the beginning of the function---no return address
    /// should be pushed.
    pub(crate) unsafe fn dispatch_function(must_flush_tlb: u64);
}
core::arch::global_asm!("
    .global dispatch_function
    dispatch_function:
    jnz flush_done
    mov rdi, cr4
    xor rdi, 0x80
    mov cr4, rdi
    xor rdi, 0x80
    mov cr4, rdi
    flush_done:
    call {internal_dispatch_function}\n
    hlt\n
", internal_dispatch_function = sym crate::guest_function::call::internal_dispatch_function);
