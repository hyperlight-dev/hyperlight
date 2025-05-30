/*
Copyright 2024 The Hyperlight Authors.

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

pub const PAGE_SHIFT: u64 = 12;
pub const PAGE_SIZE: u64 = 1 << 12;
pub const PAGE_SIZE_USIZE: usize = 1 << 12;

/// A memory region in the guest address space
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GuestMemoryRegion {
    /// The size of the memory region
    pub size: u64,
    /// The address of the memory region
    pub ptr: u64,
}

/// A memory region in the guest address space that is used for the stack
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GuestStack {
    /// The top of the user stack
    pub min_user_stack_address: u64,
    /// The user stack pointer
    pub user_stack_address: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct HyperlightPEB {
    pub security_cookie_seed: u64,
    pub guest_function_dispatch_ptr: u64,
    pub code_ptr: u64,
    pub input_stack: GuestMemoryRegion,
    pub output_stack: GuestMemoryRegion,
    pub guest_heap: GuestMemoryRegion,
    pub guest_stack: GuestStack,
}
