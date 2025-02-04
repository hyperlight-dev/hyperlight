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
use std::fmt::Debug;
use std::mem::{offset_of, size_of};

use hyperlight_common::mem::{GuestStackData, HyperlightPEB, RunMode, PAGE_SIZE_USIZE};
use paste::paste;
use rand::{rng, RngCore};
use tracing::{instrument, Span};

use super::memory_region::MemoryRegionType::{
    BootStack, Code, GuardPage, GuestErrorData, Heap, HostExceptionData, HostFunctionDefinitions,
    InputData, KernelStack, OutputData, PageTables, PanicContext, Peb, Stack,
};
use super::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionVecBuilder};
use super::mgr::AMOUNT_OF_MEMORY_PER_PT;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, SharedMemory};
use crate::error::HyperlightError::{GuestOffsetIsInvalid, MemoryRequestTooBig};
use crate::sandbox::SandboxConfiguration;
use crate::{log_then_return, new_error, Result};

// +-------------------------------------------+
// |             Boot Stack (4KiB)             |
// +-------------------------------------------+
// |       Kernel Stack Guard Page (4KiB)      |
// +-------------------------------------------+
// |             Kernel Stack                  |
// +-------------------------------------------+
// |        Guest Stack Guard Page (4KiB)      |
// +-------------------------------------------+
// |             Guest (User) Stack            |
// +-------------------------------------------+
// |             Guard Page (4KiB)             |
// +-------------------------------------------+
// |             Guest Heap                    |
// +-------------------------------------------+
// |         Guest Panic Context               |
// +-------------------------------------------+
// |             Output Data                   |
// +-------------------------------------------+
// |              Input Data                   |
// +-------------------------------------------+
// |           Guest Error Log                 |
// +-------------------------------------------+
// |        Host Exception Handlers            |
// +-------------------------------------------+
// |        Host Function Definitions          |
// +-------------------------------------------+
// |                PEB Struct (0x98)          |
// +-------------------------------------------+
// |               Guest Code                  |
// +-------------------------------------------+
// |                    PT                     |
// +-------------------------------------------+ 0x203_000
// |                    PD                     |
// +-------------------------------------------+ 0x202_000
// |                   PDPT                    |
// +-------------------------------------------+ 0x201_000
// |                   PML4                    |
// +-------------------------------------------+ 0x200_000
// |                    ⋮                      |
// |                 Unmapped                  |
// |                    ⋮                      |
// +-------------------------------------------+ 0x0

///
/// - `HostDefinitions` - the length of this is the `HostFunctionDefinitionSize`
///   field from `SandboxConfiguration`
///
/// - `HostExceptionData` - memory that contains details of any Host Exception that
///   occurred in outb function. it contains a 32 bit length following by a json
///   serialisation of any error that occurred. the length of this field is
///   `HostExceptionSize` from` `SandboxConfiguration`
///
/// - `GuestError` - contains a buffer for any guest error that occurred.
///   the length of this field is `GuestErrorBufferSize` from `SandboxConfiguration`
///
/// - `InputData` -  this is a buffer that is used for input data to the host program.
///   the length of this field is `InputDataSize` from `SandboxConfiguration`
///
/// - `OutputData` - this is a buffer that is used for output data from host program.
///   the length of this field is `OutputDataSize` from `SandboxConfiguration`
///
/// - `GuestHeap` - this is a buffer that is used for heap data in the guest. the length
///   of this field is returned by the `heap_size()` method of this struct
///
/// - `GuestStack` - this is a buffer that is used for stack data in the guest. the length
///   of this field is returned by the `stack_size()` method of this struct. in reality,
///   the stack might be slightly bigger or smaller than this value since total memory
///   size is rounded up to the nearest 4K, and there is a 16-byte stack guard written
///   to the top of the stack. (see below for more details)
///
/// - `GuestPanicContext` - contains a buffer for context associated with any guest
///   panic that occurred.
///   the length of this field is returned by the `guest_panic_context_size()` fn of this struct.
///
/// Boot Stack - this is the stack that is used before the TSS is set up. It is fixed to 4K
/// Kernel Stack Guard Page is to Guard against boot stack overflow so we dont corrupt the kernel stack
/// Kernel Stack - this is the stack that is used for kernel mode operations we switch to this early in the initialization function
/// Guest Stack Guard Page is to Guard against kernel stack overflow so we dont corrupt the user stack

#[derive(Copy, Clone)]
pub(crate) struct SandboxMemoryLayout {
    pub(super) sandbox_memory_config: SandboxConfiguration,
    /// The total stack size of this sandbox.
    pub(super) stack_size: usize,
    /// The heap size of this sandbox.
    pub(super) heap_size: usize,

    /// The following fields are offsets to the actual PEB struct fields.
    /// They are used when writing the PEB struct itself
    peb_offset: usize,
    peb_security_cookie_seed_offset: usize,
    peb_guest_dispatch_function_ptr_offset: usize, // set by guest in guest entrypoint
    pub(super) peb_host_function_definitions_offset: usize,
    pub(crate) peb_host_exception_offset: usize,
    peb_guest_error_offset: usize,
    peb_code_and_outb_pointer_offset: usize,
    peb_runmode_offset: usize,
    peb_input_data_offset: usize,
    peb_output_data_offset: usize,
    peb_guest_panic_context_offset: usize,
    peb_heap_data_offset: usize,
    peb_guest_stack_data_offset: usize,

    // The following are the actual values
    // that are written to the PEB struct
    pub(crate) host_function_definitions_buffer_offset: usize,
    pub(crate) host_exception_buffer_offset: usize,
    pub(super) guest_error_buffer_offset: usize,
    pub(super) input_data_buffer_offset: usize,
    pub(super) output_data_buffer_offset: usize,
    guest_panic_context_buffer_offset: usize,
    guest_heap_buffer_offset: usize,
    guard_page_offset: usize,
    guest_user_stack_buffer_offset: usize, // the lowest address of the user stack
    user_stack_guard_page_offset: usize,
    kernel_stack_buffer_offset: usize,
    kernel_stack_guard_page_offset: usize,
    #[allow(dead_code)]
    pub(super) kernel_stack_size_rounded: usize,
    boot_stack_buffer_offset: usize,

    // other
    pub(crate) peb_address: usize,
    code_size: usize,
    // The total size of the page tables
    total_page_table_size: usize,
    // The offset in the sandbox memory where the code starts
    guest_code_offset: usize,
}

impl Debug for SandboxMemoryLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxMemoryLayout")
            .field(
                "Total Memory Size",
                &format_args!("{:#x}", self.get_memory_size().unwrap_or(0)),
            )
            .field("Stack Size", &format_args!("{:#x}", self.stack_size))
            .field("Heap Size", &format_args!("{:#x}", self.heap_size))
            .field("PEB Address", &format_args!("{:#x}", self.peb_address))
            .field("PEB Offset", &format_args!("{:#x}", self.peb_offset))
            .field("Code Size", &format_args!("{:#x}", self.code_size))
            .field(
                "Security Cookie Seed Offset",
                &format_args!("{:#x}", self.peb_security_cookie_seed_offset),
            )
            .field(
                "Guest Dispatch Function Pointer Offset",
                &format_args!("{:#x}", self.peb_guest_dispatch_function_ptr_offset),
            )
            .field(
                "Host Function Definitions Offset",
                &format_args!("{:#x}", self.peb_host_function_definitions_offset),
            )
            .field(
                "Host Exception Offset",
                &format_args!("{:#x}", self.peb_host_exception_offset),
            )
            .field(
                "Guest Error Offset",
                &format_args!("{:#x}", self.peb_guest_error_offset),
            )
            .field(
                "Code and OutB Pointer Offset",
                &format_args!("{:#x}", self.peb_code_and_outb_pointer_offset),
            )
            .field(
                "Input Data Offset",
                &format_args!("{:#x}", self.peb_input_data_offset),
            )
            .field(
                "Output Data Offset",
                &format_args!("{:#x}", self.peb_output_data_offset),
            )
            .field(
                "Guest Panic Context Offset",
                &format_args!("{:#x}", self.peb_guest_panic_context_offset),
            )
            .field(
                "Guest Heap Offset",
                &format_args!("{:#x}", self.peb_heap_data_offset),
            )
            .field(
                "Guest Stack Offset",
                &format_args!("{:#x}", self.peb_guest_stack_data_offset),
            )
            .field(
                "Host Function Definitions Buffer Offset",
                &format_args!("{:#x}", self.host_function_definitions_buffer_offset),
            )
            .field(
                "Host Exception Buffer Offset",
                &format_args!("{:#x}", self.host_exception_buffer_offset),
            )
            .field(
                "Guest Error Buffer Offset",
                &format_args!("{:#x}", self.guest_error_buffer_offset),
            )
            .field(
                "Input Data Buffer Offset",
                &format_args!("{:#x}", self.input_data_buffer_offset),
            )
            .field(
                "Output Data Buffer Offset",
                &format_args!("{:#x}", self.output_data_buffer_offset),
            )
            .field(
                "Guest Panic Context Buffer Offset",
                &format_args!("{:#x}", self.guest_panic_context_buffer_offset),
            )
            .field(
                "Guest Heap Buffer Offset",
                &format_args!("{:#x}", self.guest_heap_buffer_offset),
            )
            .field(
                "Guard Page Offset",
                &format_args!("{:#x}", self.guard_page_offset),
            )
            .field(
                "Guest User Stack Buffer Offset",
                &format_args!("{:#x}", self.guest_user_stack_buffer_offset),
            )
            .field(
                "Page Table Size",
                &format_args!("{:#x}", self.total_page_table_size),
            )
            .field(
                "Guest Code Offset",
                &format_args!("{:#x}", self.guest_code_offset),
            )
            .field(
                "User Stack Guard Page Offset",
                &format_args!("{:#x}", self.user_stack_guard_page_offset),
            )
            .field(
                "Kernel Stack Buffer Offset",
                &format_args!("{:#x}", self.kernel_stack_buffer_offset),
            )
            .field(
                "Kernel Stack Guard Page Offset",
                &format_args!("{:#x}", self.kernel_stack_guard_page_offset),
            )
            .field(
                "Boot Stack Buffer Offset",
                &format_args!("{:#x}", self.boot_stack_buffer_offset),
            )
            .finish()
    }
}

impl SandboxMemoryLayout {
    /// The offset into the sandbox's memory where the PML4 Table is located.
    /// See https://www.pagetable.com/?p=14 for more information.
    pub(crate) const PML4_OFFSET: usize = 0x0000;
    /// The offset into the sandbox's memory where the Page Directory Pointer
    /// Table starts.
    pub(super) const PDPT_OFFSET: usize = 0x1000;
    /// The offset into the sandbox's memory where the Page Directory starts.
    pub(super) const PD_OFFSET: usize = 0x2000;
    /// The offset into the sandbox's memory where the Page Tables start.
    pub(super) const PT_OFFSET: usize = 0x3000;
    /// The address (not the offset) to the start of the page directory
    pub(super) const PD_GUEST_ADDRESS: usize = Self::BASE_ADDRESS + Self::PD_OFFSET;
    /// The address (not the offset) into sandbox memory where the Page
    /// Directory Pointer Table starts
    pub(super) const PDPT_GUEST_ADDRESS: usize = Self::BASE_ADDRESS + Self::PDPT_OFFSET;
    /// The address (not the offset) into sandbox memory where the Page
    /// Tables start
    pub(super) const PT_GUEST_ADDRESS: usize = Self::BASE_ADDRESS + Self::PT_OFFSET;
    /// The maximum amount of memory a single sandbox will be allowed.
    /// The addressable virtual memory with current paging setup is virtual address 0x0 - 0x40000000 (excl.),
    /// However, the memory up to Self::BASE_ADDRESS is not used.
    const MAX_MEMORY_SIZE: usize = 0x40000000 - Self::BASE_ADDRESS;

    /// The base address of the sandbox's memory.
    pub(crate) const BASE_ADDRESS: usize = 0x0200000;

    // the offset into a sandbox's input/output buffer where the stack starts
    const STACK_POINTER_SIZE_BYTES: u64 = 8;

    /// Create a new `SandboxMemoryLayout` with the given
    /// `SandboxConfiguration`, code size and stack/heap size.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new(
        cfg: SandboxConfiguration,
        code_size: usize,
        stack_size: usize,
        heap_size: usize,
    ) -> Result<Self> {
        let total_page_table_size =
            Self::get_total_page_table_size(cfg, code_size, stack_size, heap_size);
        let guest_code_offset = total_page_table_size;
        // The following offsets are to the fields of the PEB struct itself!
        let peb_offset = total_page_table_size + round_up_to(code_size, PAGE_SIZE_USIZE);
        let peb_security_cookie_seed_offset =
            peb_offset + offset_of!(HyperlightPEB, security_cookie_seed);
        let peb_guest_dispatch_function_ptr_offset =
            peb_offset + offset_of!(HyperlightPEB, guest_function_dispatch_ptr);
        let peb_host_function_definitions_offset =
            peb_offset + offset_of!(HyperlightPEB, hostFunctionDefinitions);
        let peb_host_exception_offset = peb_offset + offset_of!(HyperlightPEB, hostException);
        let peb_guest_error_offset = peb_offset + offset_of!(HyperlightPEB, guestErrorData);
        let peb_code_and_outb_pointer_offset = peb_offset + offset_of!(HyperlightPEB, pCode);
        let peb_runmode_offset = peb_offset + offset_of!(HyperlightPEB, runMode);
        let peb_input_data_offset = peb_offset + offset_of!(HyperlightPEB, inputdata);
        let peb_output_data_offset = peb_offset + offset_of!(HyperlightPEB, outputdata);
        let peb_guest_panic_context_offset =
            peb_offset + offset_of!(HyperlightPEB, guestPanicContextData);
        let peb_heap_data_offset = peb_offset + offset_of!(HyperlightPEB, guestheapData);
        let peb_guest_stack_data_offset = peb_offset + offset_of!(HyperlightPEB, gueststackData);

        // The following offsets are the actual values that relate to memory layout,
        // which are written to PEB struct
        let peb_address = Self::BASE_ADDRESS + peb_offset;
        // make sure host function definitions buffer starts at 4K boundary
        let host_function_definitions_buffer_offset = round_up_to(
            peb_guest_stack_data_offset + size_of::<GuestStackData>(),
            PAGE_SIZE_USIZE,
        );
        // make sure host exception buffer starts at 4K boundary
        let host_exception_buffer_offset = round_up_to(
            host_function_definitions_buffer_offset + cfg.get_host_function_definition_size(),
            PAGE_SIZE_USIZE,
        );
        let guest_error_buffer_offset = round_up_to(
            host_exception_buffer_offset + cfg.get_host_exception_size(),
            PAGE_SIZE_USIZE,
        );
        let input_data_buffer_offset = round_up_to(
            guest_error_buffer_offset + cfg.get_guest_error_buffer_size(),
            PAGE_SIZE_USIZE,
        );
        let output_data_buffer_offset = round_up_to(
            input_data_buffer_offset + cfg.get_input_data_size(),
            PAGE_SIZE_USIZE,
        );
        let guest_panic_context_buffer_offset = round_up_to(
            output_data_buffer_offset + cfg.get_output_data_size(),
            PAGE_SIZE_USIZE,
        );
        // make sure heap buffer starts at 4K boundary
        let guest_heap_buffer_offset = round_up_to(
            guest_panic_context_buffer_offset + cfg.get_guest_panic_context_buffer_size(),
            PAGE_SIZE_USIZE,
        );
        // make sure guard page starts at 4K boundary
        let guard_page_offset = round_up_to(guest_heap_buffer_offset + heap_size, PAGE_SIZE_USIZE);
        let guest_user_stack_buffer_offset = guard_page_offset + PAGE_SIZE_USIZE;
        // round up stack size to page size. This is needed for MemoryRegion
        let stack_size_rounded = round_up_to(stack_size, PAGE_SIZE_USIZE);

        let user_stack_guard_page_offset = guest_user_stack_buffer_offset + stack_size_rounded;
        let kernel_stack_buffer_offset = user_stack_guard_page_offset + PAGE_SIZE_USIZE;
        let kernel_stack_size_rounded = round_up_to(cfg.get_kernel_stack_size(), PAGE_SIZE_USIZE);
        let kernel_stack_guard_page_offset = kernel_stack_buffer_offset + kernel_stack_size_rounded;
        let boot_stack_buffer_offset = kernel_stack_guard_page_offset + PAGE_SIZE_USIZE;

        Ok(Self {
            peb_offset,
            stack_size: stack_size_rounded,
            heap_size,
            peb_security_cookie_seed_offset,
            peb_guest_dispatch_function_ptr_offset,
            peb_host_function_definitions_offset,
            peb_host_exception_offset,
            peb_guest_error_offset,
            peb_code_and_outb_pointer_offset,
            peb_runmode_offset,
            peb_input_data_offset,
            peb_output_data_offset,
            peb_guest_panic_context_offset,
            peb_heap_data_offset,
            peb_guest_stack_data_offset,
            guest_error_buffer_offset,
            sandbox_memory_config: cfg,
            code_size,
            host_function_definitions_buffer_offset,
            host_exception_buffer_offset,
            input_data_buffer_offset,
            output_data_buffer_offset,
            guest_heap_buffer_offset,
            guest_user_stack_buffer_offset,
            peb_address,
            guest_panic_context_buffer_offset,
            guard_page_offset,
            total_page_table_size,
            guest_code_offset,
            user_stack_guard_page_offset,
            kernel_stack_buffer_offset,
            kernel_stack_guard_page_offset,
            kernel_stack_size_rounded,
            boot_stack_buffer_offset,
        })
    }

    /// Gets the offset in guest memory to the RunMode field in the PEB struct.
    pub fn get_run_mode_offset(&self) -> usize {
        self.peb_runmode_offset
    }

    /// Get the offset in guest memory to the size field in the
    /// `HostExceptionData` structure.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_host_exception_size_offset(&self) -> usize {
        // The size field is the first field in the `HostExceptionData` struct
        self.peb_host_exception_offset
    }

    /// Get the offset in guest memory to the max size of the guest error buffer
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_guest_error_buffer_size_offset(&self) -> usize {
        self.peb_guest_error_offset
    }

    /// Get the offset in guest memory to the error message buffer pointer
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_guest_error_buffer_pointer_offset(&self) -> usize {
        self.peb_guest_error_offset + size_of::<u64>()
    }

    /// Get the offset in guest memory to the output data size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_output_data_size_offset(&self) -> usize {
        // The size field is the first field in the `OutputData` struct
        self.peb_output_data_offset
    }

    /// Get the offset in guest memory to the host function definitions
    /// size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_host_function_definitions_size_offset(&self) -> usize {
        // The size field is the first field in the `HostFunctions` struct
        self.peb_host_function_definitions_offset
    }

    /// Get the offset in guest memory to the host function definitions
    /// pointer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_host_function_definitions_pointer_offset(&self) -> usize {
        // The size field is the field after the size field in the `HostFunctions` struct which is a u64
        self.peb_host_function_definitions_offset + size_of::<u64>()
    }

    /// Get the offset in guest memory to the minimum guest stack address.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_min_guest_stack_address_offset(&self) -> usize {
        // The minimum guest user stack address is the start of the guest stack
        self.peb_guest_stack_data_offset
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_guest_stack_size(&self) -> usize {
        self.stack_size
    }

    /// Get the offset in guest memory to the start of host errors
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_host_exception_offset(&self) -> usize {
        self.host_exception_buffer_offset
    }

    /// Get the offset in guest memory to the OutB pointer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_outb_pointer_offset(&self) -> usize {
        // The outb pointer is immediately after the code pointer
        // in the `CodeAndOutBPointers` struct which is a u64
        self.peb_code_and_outb_pointer_offset + size_of::<u64>()
    }

    /// Get the offset in guest memory to the OutB context.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_outb_context_offset(&self) -> usize {
        // The outb context is immediately after the outb pointer
        // in the `CodeAndOutBPointers` struct which is a u64
        self.get_outb_pointer_offset() + size_of::<u64>()
    }

    /// Get the offset in guest memory to the output data pointer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_output_data_pointer_offset(&self) -> usize {
        // This field is immediately after the output data size field,
        // which is a `u64`.
        self.get_output_data_size_offset() + size_of::<u64>()
    }

    /// Get the offset in guest memory to the start of output data.
    ///
    /// This function exists to accommodate the macro that generates C API
    /// compatible functions.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_output_data_offset(&self) -> usize {
        self.output_data_buffer_offset
    }

    /// Get the offset in guest memory to the input data size.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_input_data_size_offset(&self) -> usize {
        // The input data size is the first field in the `InputData` struct
        self.peb_input_data_offset
    }

    /// Get the offset in guest memory to the input data pointer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_input_data_pointer_offset(&self) -> usize {
        // The input data pointer is immediately after the input
        // data size field in the `InputData` struct which is a `u64`.
        self.get_input_data_size_offset() + size_of::<u64>()
    }

    /// Get the offset in guest memory to the code pointer
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_code_pointer_offset(&self) -> usize {
        // The code pointer is the first field
        // in the `CodeAndOutBPointers` struct which is a u64
        self.peb_code_and_outb_pointer_offset
    }

    /// Get the offset in guest memory to where the guest dispatch function
    /// pointer is written
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_dispatch_function_pointer_offset(&self) -> usize {
        self.peb_guest_dispatch_function_ptr_offset
    }

    /// Get the offset in guest memory to the PEB address
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_in_process_peb_offset(&self) -> usize {
        self.peb_offset
    }

    /// Get the offset in guest memory to the heap size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_heap_size_offset(&self) -> usize {
        self.peb_heap_data_offset
    }

    /// Get the offset of the heap pointer in guest memory,
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_heap_pointer_offset(&self) -> usize {
        // The heap pointer is immediately after the
        // heap size field in the `GuestHeap` struct which is a `u64`.
        self.get_heap_size_offset() + size_of::<u64>()
    }

    /// Get the offset to the top of the stack in guest memory
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_top_of_user_stack_offset(&self) -> usize {
        self.guest_user_stack_buffer_offset
    }

    /// Get the offset of the user stack pointer in guest memory,
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_user_stack_pointer_offset(&self) -> usize {
        // The userStackAddress is immediately after the
        // minUserStackAddress (top of user stack) field in the `GuestStackData` struct which is a `u64`.
        self.get_min_guest_stack_address_offset() + size_of::<u64>()
    }

    /// Get the offset of the kernel stack pointer in guest memory,
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_kernel_stack_pointer_offset(&self) -> usize {
        // The kernelStackAddress is immediately after the
        // userStackAddress in the `GuestStackData` struct which is a `u64`.
        self.get_user_stack_pointer_offset() + size_of::<u64>()
    }

    /// Get the offset of the boot stack pointer in guest memory,
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_boot_stack_pointer_offset(&self) -> usize {
        // The bootStackAddress is immediately after the
        // kernelStackAddress in the `GuestStackData` struct which is a `u64`.
        self.get_kernel_stack_pointer_offset() + size_of::<u64>()
    }

    // Get the offset in guest memory to the start of the guest panic context data
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_panic_context_offset(&self) -> usize {
        self.peb_guest_panic_context_offset
    }

    // Get the offset to the guest panic context buffer size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_panic_context_size_offset(&self) -> usize {
        // The size field is the first field in the `GuestPanicContext` data
        self.peb_guest_panic_context_offset
    }

    /// Get the offset to the guest panic context buffer pointer
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_panic_context_buffer_pointer_offset(&self) -> usize {
        // The guest panic data pointer is immediately after the guest
        // panic data size field in the `GuestPanicContext` data which is a `u64`
        self.get_guest_panic_context_size_offset() + size_of::<u64>()
    }

    /// Get the offset to the guest panic context buffer pointer
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_panic_context_buffer_offset(&self) -> usize {
        self.guest_panic_context_buffer_offset
    }

    /// Get the offset to the guest guard page
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_guard_page_offset(&self) -> usize {
        self.guard_page_offset
    }

    /// Get the total size of guest memory in `self`'s memory
    /// layout.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_unaligned_memory_size(&self) -> usize {
        self.get_boot_stack_buffer_offset() + PAGE_SIZE_USIZE
    }

    /// get the code offset
    /// This is the offset in the sandbox memory where the code starts
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_guest_code_offset(&self) -> usize {
        self.guest_code_offset
    }

    /// Get the guest address of the code section in the sandbox
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_code_address(&self) -> usize {
        Self::BASE_ADDRESS + self.guest_code_offset
    }

    /// Get the offset in guest memory to the user stack guard page
    /// This is the offset in the sandbox memory where the user stack guard page starts
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_user_stack_guard_page_offset(&self) -> usize {
        self.user_stack_guard_page_offset
    }

    /// Get the offset in guest memory to the kernel stack buffer
    /// This is the offset in the sandbox memory where the kernel stack starts
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_kernel_stack_buffer_offset(&self) -> usize {
        self.kernel_stack_buffer_offset
    }

    /// Get the offset in guest memory to the kernel stack guard page
    /// This is the offset in the sandbox memory where the kernel stack guard page starts
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_kernel_stack_guard_page_offset(&self) -> usize {
        self.kernel_stack_guard_page_offset
    }

    /// Get the offset in guest memory to the boot stack buffer
    /// This is the offset in the sandbox memory where the boot stack starts
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_boot_stack_buffer_offset(&self) -> usize {
        self.boot_stack_buffer_offset
    }

    #[cfg(test)]
    /// Get the page table size
    fn get_page_table_size(&self) -> usize {
        self.total_page_table_size
    }

    // This function calculates the page table size for the sandbox
    // We need enough memory to store the PML4, PDPT, PD and PTs
    // The size of a single table is 4K, we can map up to 1GB total memory which requires 1 PML4, 1 PDPT, 1 PD and 512 PTs
    // but we only need enough PTs to map the memory we are using. (In other words we only need 512 PTs to map the memory if the memory size is 1GB)
    //
    // Because we always start the physical address space at 0x200_000
    // we can calculate the amount of memory needed for the PTs by calculating how much memory is needed for the sandbox configuration in total,
    // then add 0x200_000 to that (as we start at 0x200_000),
    // and then add 3 * 4K (for the PML4, PDPT and PD)  to that,
    // then add 2MB to that (the maximum size of memory required for the PTs themselves is 2MB when we map 1GB of memory in 4K pages),
    // then divide that by 0x200_000 (as we can map 2MB in each PT) and then round the result up by 1 .
    // This will give us the total size of the PTs required for the sandbox to which we can add the size of the PML4, PDPT and PD.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_total_page_table_size(
        cfg: SandboxConfiguration,
        code_size: usize,
        stack_size: usize,
        heap_size: usize,
    ) -> usize {
        // Get the configured memory size (assume each section is 4K aligned)

        let mut total_mapped_memory_size: usize = round_up_to(code_size, PAGE_SIZE_USIZE);
        total_mapped_memory_size += round_up_to(stack_size, PAGE_SIZE_USIZE);
        total_mapped_memory_size += round_up_to(heap_size, PAGE_SIZE_USIZE);
        total_mapped_memory_size += round_up_to(cfg.get_host_exception_size(), PAGE_SIZE_USIZE);
        total_mapped_memory_size +=
            round_up_to(cfg.get_host_function_definition_size(), PAGE_SIZE_USIZE);
        total_mapped_memory_size += round_up_to(cfg.get_guest_error_buffer_size(), PAGE_SIZE_USIZE);
        total_mapped_memory_size += round_up_to(cfg.get_input_data_size(), PAGE_SIZE_USIZE);
        total_mapped_memory_size += round_up_to(cfg.get_output_data_size(), PAGE_SIZE_USIZE);
        total_mapped_memory_size +=
            round_up_to(cfg.get_guest_panic_context_buffer_size(), PAGE_SIZE_USIZE);
        total_mapped_memory_size += round_up_to(size_of::<HyperlightPEB>(), PAGE_SIZE_USIZE);

        // Add the base address of the sandbox
        total_mapped_memory_size += Self::BASE_ADDRESS;

        // Add the size of  the PML4, PDPT and PD
        total_mapped_memory_size += 3 * PAGE_SIZE_USIZE;

        // Add the maximum possible size of the PTs
        total_mapped_memory_size += 512 * PAGE_SIZE_USIZE;

        // Get the number of pages needed for the PTs

        let num_pages: usize = ((total_mapped_memory_size + AMOUNT_OF_MEMORY_PER_PT - 1)
            / AMOUNT_OF_MEMORY_PER_PT)
            + 1 // Round up
            + 3; // PML4, PDPT, PD

        num_pages * PAGE_SIZE_USIZE
    }

    /// Get the total size of guest memory in `self`'s memory
    /// layout aligned to page size boundaries.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_memory_size(&self) -> Result<usize> {
        let total_memory = self.get_unaligned_memory_size();

        // Size should be a multiple of page size.
        let remainder = total_memory % PAGE_SIZE_USIZE;
        let multiples = total_memory / PAGE_SIZE_USIZE;
        let size = match remainder {
            0 => total_memory,
            _ => (multiples + 1) * PAGE_SIZE_USIZE,
        };

        if size > Self::MAX_MEMORY_SIZE {
            Err(MemoryRequestTooBig(size, Self::MAX_MEMORY_SIZE))
        } else {
            Ok(size)
        }
    }

    /// Returns the memory regions associated with this memory layout,
    /// suitable for passing to a hypervisor for mapping into memory
    pub fn get_memory_regions(&self, shared_mem: &GuestSharedMemory) -> Result<Vec<MemoryRegion>> {
        let mut builder = MemoryRegionVecBuilder::new(Self::BASE_ADDRESS, shared_mem.base_addr());

        // PML4, PDPT, PD
        let code_offset = builder.push_page_aligned(
            self.total_page_table_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            PageTables,
        );

        if code_offset != self.guest_code_offset {
            return Err(new_error!(
                "Code offset does not match expected code offset expected:  {}, actual:  {}",
                self.guest_code_offset,
                code_offset
            ));
        }

        // code
        let peb_offset = builder.push_page_aligned(
            self.code_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            Code,
        );

        let expected_peb_offset = TryInto::<usize>::try_into(self.peb_offset)?;

        if peb_offset != expected_peb_offset {
            return Err(new_error!(
                "PEB offset does not match expected PEB offset expected:  {}, actual:  {}",
                expected_peb_offset,
                peb_offset
            ));
        }

        // PEB
        let host_functions_definitions_offset = builder.push_page_aligned(
            size_of::<HyperlightPEB>(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            Peb,
        );

        let expected_host_functions_definitions_offset =
            TryInto::<usize>::try_into(self.host_function_definitions_buffer_offset)?;

        if host_functions_definitions_offset != expected_host_functions_definitions_offset {
            return Err(new_error!(
                "Host Function Definitions offset does not match expected Host Function Definitions offset expected:  {}, actual:  {}",
                expected_host_functions_definitions_offset,
                host_functions_definitions_offset
            ));
        }

        // host function definitions
        let host_exception_offset = builder.push_page_aligned(
            self.sandbox_memory_config
                .get_host_function_definition_size(),
            MemoryRegionFlags::READ,
            HostFunctionDefinitions,
        );

        let expected_host_exception_offset =
            TryInto::<usize>::try_into(self.host_exception_buffer_offset)?;

        if host_exception_offset != expected_host_exception_offset {
            return Err(new_error!(
                "Host Exception offset does not match expected Host Exception offset expected:  {}, actual:  {}",
                expected_host_exception_offset,
                host_exception_offset
            ));
        }

        // host exception
        let guest_error_offset = builder.push_page_aligned(
            self.sandbox_memory_config.get_host_exception_size(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            HostExceptionData,
        );

        let expected_guest_error_offset =
            TryInto::<usize>::try_into(self.guest_error_buffer_offset)?;

        if guest_error_offset != expected_guest_error_offset {
            return Err(new_error!(
                "Guest Error offset does not match expected Guest Error offset expected:  {}, actual:  {}",
                expected_guest_error_offset,
                guest_error_offset
            ));
        }

        // guest error
        let input_data_offset = builder.push_page_aligned(
            self.sandbox_memory_config.get_guest_error_buffer_size(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            GuestErrorData,
        );

        let expected_input_data_offset = TryInto::<usize>::try_into(self.input_data_buffer_offset)?;

        if input_data_offset != expected_input_data_offset {
            return Err(new_error!(
                "Input Data offset does not match expected Input Data offset expected:  {}, actual:  {}",
                expected_input_data_offset,
                input_data_offset
            ));
        }

        // guest input data
        let output_data_offset = builder.push_page_aligned(
            self.sandbox_memory_config.get_input_data_size(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            InputData,
        );

        let expected_output_data_offset =
            TryInto::<usize>::try_into(self.output_data_buffer_offset)?;

        if output_data_offset != expected_output_data_offset {
            return Err(new_error!(
                "Output Data offset does not match expected Output Data offset expected:  {}, actual:  {}",
                expected_output_data_offset,
                output_data_offset
            ));
        }

        // guest output data
        let guest_panic_context_offset = builder.push_page_aligned(
            self.sandbox_memory_config.get_output_data_size(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            OutputData,
        );

        let expected_guest_panic_context_offset =
            TryInto::<usize>::try_into(self.guest_panic_context_buffer_offset)?;

        if guest_panic_context_offset != expected_guest_panic_context_offset {
            return Err(new_error!(
                "Guest Panic Context offset does not match expected Guest Panic Context offset expected:  {}, actual:  {}",
                expected_guest_panic_context_offset,
                guest_panic_context_offset
            ));
        }

        // guest panic context
        let heap_offset = builder.push_page_aligned(
            self.sandbox_memory_config
                .get_guest_panic_context_buffer_size(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            PanicContext,
        );

        let expected_heap_offset = TryInto::<usize>::try_into(self.guest_heap_buffer_offset)?;

        if heap_offset != expected_heap_offset {
            return Err(new_error!(
                "Guest Heap offset does not match expected Guest Heap offset expected:  {}, actual:  {}",
                expected_heap_offset,
                heap_offset
            ));
        }

        // heap
        #[cfg(feature = "executable_heap")]
        let guard_page_offset = builder.push_page_aligned(
            self.heap_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            Heap,
        );
        #[cfg(not(feature = "executable_heap"))]
        let guard_page_offset = builder.push_page_aligned(
            self.heap_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            Heap,
        );

        let expected_guard_page_offset = TryInto::<usize>::try_into(self.guard_page_offset)?;

        if guard_page_offset != expected_guard_page_offset {
            return Err(new_error!(
                "Guard Page offset does not match expected Guard Page offset expected:  {}, actual:  {}",
                expected_guard_page_offset,
                guard_page_offset
            ));
        }

        // guard page
        let stack_offset = builder.push_page_aligned(
            PAGE_SIZE_USIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::STACK_GUARD,
            GuardPage,
        );

        let expected_stack_offset =
            TryInto::<usize>::try_into(self.guest_user_stack_buffer_offset)?;

        if stack_offset != expected_stack_offset {
            return Err(new_error!(
                "Stack offset does not match expected Stack offset expected:  {}, actual:  {}",
                expected_stack_offset,
                stack_offset
            ));
        }

        // stack
        let user_stack_guard_page_offset = builder.push_page_aligned(
            self.get_guest_stack_size(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            Stack,
        );

        let expected_user_stack_guard_page_offset =
            TryInto::<usize>::try_into(self.get_top_of_user_stack_offset())?
                + self.get_guest_stack_size();

        if user_stack_guard_page_offset != expected_user_stack_guard_page_offset {
            return Err(new_error!(
                "User Guard Page offset does not match expected User Guard Page offset expected:  {}, actual:  {}",
                expected_user_stack_guard_page_offset,
                user_stack_guard_page_offset
            ));
        }

        let kernel_stack_offset = builder.push_page_aligned(
            PAGE_SIZE_USIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::STACK_GUARD,
            GuardPage,
        );

        let expected_kernel_stack_offset =
            TryInto::<usize>::try_into(self.kernel_stack_buffer_offset)?;

        if kernel_stack_offset != expected_kernel_stack_offset {
            return Err(new_error!(
                "Kernel Stack offset does not match expected Kernel Stack offset expected:  {}, actual:  {}",
                expected_kernel_stack_offset,
                kernel_stack_offset
            ));
        }

        let kernel_stack_guard_page_offset = builder.push_page_aligned(
            self.kernel_stack_size_rounded,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            KernelStack,
        );

        let expected_kernel_stack_guard_page_offset =
            TryInto::<usize>::try_into(self.kernel_stack_guard_page_offset)?;

        if kernel_stack_guard_page_offset != expected_kernel_stack_guard_page_offset {
            return Err(new_error!(
                "Kernel Guard Page offset does not match expected Kernel Guard Page offset expected:  {}, actual:  {}",
                expected_kernel_stack_guard_page_offset,
                kernel_stack_guard_page_offset
            ));
        }

        let boot_stack_offset = builder.push_page_aligned(
            PAGE_SIZE_USIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::STACK_GUARD,
            GuardPage,
        );

        let expected_boot_stack_offset = TryInto::<usize>::try_into(self.boot_stack_buffer_offset)?;

        if boot_stack_offset != expected_boot_stack_offset {
            return Err(new_error!(
                "Boot Stack offset does not match expected Boot Stack offset expected:  {}, actual:  {}",
                expected_boot_stack_offset,
                boot_stack_offset
            ));
        }

        let final_offset = builder.push_page_aligned(
            PAGE_SIZE_USIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            BootStack,
        );

        let expected_final_offset = TryInto::<usize>::try_into(self.get_memory_size()?)?;

        if final_offset != expected_final_offset {
            return Err(new_error!(
                "Final offset does not match expected Final offset expected:  {}, actual:  {}",
                expected_final_offset,
                final_offset
            ));
        }

        Ok(builder.build())
    }

    /// Write the finished memory layout to `shared_mem` and return
    /// `Ok` if successful.
    ///
    /// Note: `shared_mem` may have been modified, even if `Err` was returned
    /// from this function.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write(
        &self,
        shared_mem: &mut ExclusiveSharedMemory,
        guest_offset: usize,
        size: usize,
        run_inprocess: bool,
    ) -> Result<()> {
        macro_rules! get_address {
            ($something:ident) => {
                paste! {
                    if guest_offset == 0 {
                        let offset = self.[<$something _offset>];
                        let calculated_addr = shared_mem.calculate_address(offset)?;
                        u64::try_from(calculated_addr)?
                    } else {
                        u64::try_from(guest_offset +  self.[<$something _offset>])?
                    }
                }
            };
        }

        if guest_offset != SandboxMemoryLayout::BASE_ADDRESS
            && guest_offset != shared_mem.base_addr()
        {
            return Err(GuestOffsetIsInvalid(guest_offset));
        }

        // Start of setting up the PEB. The following are in the order of the PEB fields

        // Set up the security cookie seed
        let mut security_cookie_seed = [0u8; 8];
        rng().fill_bytes(&mut security_cookie_seed);
        shared_mem.copy_from_slice(&security_cookie_seed, self.peb_security_cookie_seed_offset)?;

        // Skip guest_dispatch_function_ptr_offset because it is set by the guest

        // Set up Host Function Definition
        shared_mem.write_u64(
            self.get_host_function_definitions_size_offset(),
            self.sandbox_memory_config
                .get_host_function_definition_size()
                .try_into()?,
        )?;
        let addr = get_address!(host_function_definitions_buffer);
        shared_mem.write_u64(self.get_host_function_definitions_pointer_offset(), addr)?;

        // Set up Host Exception Header
        // The peb only needs to include the size, not the actual buffer
        // since the the guest wouldn't want to read the buffer anyway
        shared_mem.write_u64(
            self.get_host_exception_size_offset(),
            self.sandbox_memory_config
                .get_host_exception_size()
                .try_into()?,
        )?;

        // Set up Guest Error Fields
        let addr = get_address!(guest_error_buffer);
        shared_mem.write_u64(self.get_guest_error_buffer_pointer_offset(), addr)?;
        shared_mem.write_u64(
            self.get_guest_error_buffer_size_offset(),
            u64::try_from(self.sandbox_memory_config.get_guest_error_buffer_size())?,
        )?;

        // Skip code, is set when loading binary
        // skip outb and outb context, is set when running in_proc

        // Set RunMode in PEB
        shared_mem.write_u64(
            self.get_run_mode_offset(),
            match (
                run_inprocess,
                cfg!(target_os = "windows"),
                cfg!(target_os = "linux"),
            ) {
                (false, _, _) => RunMode::Hypervisor as u64,
                (true, true, _) => RunMode::InProcessWindows as u64,
                (true, _, true) => RunMode::InProcessLinux as u64,
                (true, _, _) => log_then_return!("Unsupported OS for in-process mode"),
            },
        )?;

        // Set up input buffer pointer
        shared_mem.write_u64(
            self.get_input_data_size_offset(),
            self.sandbox_memory_config
                .get_input_data_size()
                .try_into()?,
        )?;
        let addr = get_address!(input_data_buffer);
        shared_mem.write_u64(self.get_input_data_pointer_offset(), addr)?;

        // Set up output buffer pointer
        shared_mem.write_u64(
            self.get_output_data_size_offset(),
            self.sandbox_memory_config
                .get_output_data_size()
                .try_into()?,
        )?;
        let addr = get_address!(output_data_buffer);
        shared_mem.write_u64(self.get_output_data_pointer_offset(), addr)?;

        // Set up the guest panic context buffer
        let addr = get_address!(guest_panic_context_buffer);
        shared_mem.write_u64(
            self.get_guest_panic_context_size_offset(),
            self.sandbox_memory_config
                .get_guest_panic_context_buffer_size()
                .try_into()?,
        )?;
        shared_mem.write_u64(self.get_guest_panic_context_buffer_pointer_offset(), addr)?;

        // Set up heap buffer pointer
        let addr = get_address!(guest_heap_buffer);
        shared_mem.write_u64(self.get_heap_size_offset(), self.heap_size.try_into()?)?;
        shared_mem.write_u64(self.get_heap_pointer_offset(), addr)?;

        // Set up user stack pointers

        // Set up Min Guest User Stack Address

        // The top of the user stack is calculated as the size of the guest memory + the guest offset which gives us the
        // address at the bottom of the guest memory.
        // we then subtract the size of the stack, the size of the kernel stack,
        // the size of the boot stack, the size of the user stack guard page and the size of the kernel stack guard page
        // which are all 4K

        let bottom = guest_offset + size;
        let min_user_stack_address = bottom
            - self.stack_size
            - self.kernel_stack_size_rounded
            - PAGE_SIZE_USIZE
            - PAGE_SIZE_USIZE
            - PAGE_SIZE_USIZE;

        // Top of user stack

        shared_mem.write_u64(
            self.get_min_guest_stack_address_offset(),
            min_user_stack_address.try_into()?,
        )?;

        // Start of user stack

        let start_of_user_stack: u64 = (min_user_stack_address + self.stack_size).try_into()?;

        shared_mem.write_u64(self.get_user_stack_pointer_offset(), start_of_user_stack)?;

        // Start of kernel stack

        // There is a guard page between the user stack and the kernel stack and then we need to add the size of the kernel stack

        let start_of_kernel_stack: u64 =
            start_of_user_stack + (PAGE_SIZE_USIZE + self.kernel_stack_size_rounded) as u64;

        shared_mem.write_u64(
            self.get_kernel_stack_pointer_offset(),
            start_of_kernel_stack,
        )?;

        // Start of boot stack

        // There is a guard page between the kernel stack and the boot stack and then we need to add the size of the boot stack

        let start_of_boot_stack: u64 = start_of_kernel_stack + (PAGE_SIZE_USIZE * 2) as u64;

        shared_mem.write_u64(self.get_boot_stack_pointer_offset(), start_of_boot_stack)?;

        // End of setting up the PEB

        // Initialize the stack pointers of input data and output data
        // to point to the ninth (index 8) byte, which is the first free address
        // of the each respective stack. The first 8 bytes are the stack pointer itself.
        shared_mem.write_u64(
            self.input_data_buffer_offset,
            Self::STACK_POINTER_SIZE_BYTES,
        )?;
        shared_mem.write_u64(
            self.output_data_buffer_offset,
            Self::STACK_POINTER_SIZE_BYTES,
        )?;

        Ok(())
    }
}

fn round_up_to(value: usize, multiple: usize) -> usize {
    (value + multiple - 1) & !(multiple - 1)
}

#[cfg(test)]
mod tests {
    use hyperlight_common::mem::PAGE_SIZE_USIZE;

    use super::*;

    #[test]
    fn test_round_up() {
        assert_eq!(0, round_up_to(0, 4));
        assert_eq!(4, round_up_to(1, 4));
        assert_eq!(4, round_up_to(2, 4));
        assert_eq!(4, round_up_to(3, 4));
        assert_eq!(4, round_up_to(4, 4));
        assert_eq!(8, round_up_to(5, 4));
        assert_eq!(8, round_up_to(6, 4));
        assert_eq!(8, round_up_to(7, 4));
        assert_eq!(8, round_up_to(8, 4));
        assert_eq!(PAGE_SIZE_USIZE, round_up_to(44, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE, round_up_to(4095, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE, round_up_to(4096, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE * 2, round_up_to(4097, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE * 2, round_up_to(8191, PAGE_SIZE_USIZE));
    }

    // helper func for testing
    fn get_expected_memory_size(layout: &SandboxMemoryLayout) -> usize {
        let cfg = layout.sandbox_memory_config;
        let mut expected_size = 0;
        // in order of layout
        expected_size += layout.get_page_table_size();
        expected_size += layout.code_size;

        expected_size += round_up_to(size_of::<HyperlightPEB>(), PAGE_SIZE_USIZE);

        expected_size += round_up_to(cfg.get_host_function_definition_size(), PAGE_SIZE_USIZE);

        expected_size += round_up_to(cfg.get_host_exception_size(), PAGE_SIZE_USIZE);

        expected_size += round_up_to(cfg.get_guest_error_buffer_size(), PAGE_SIZE_USIZE);

        expected_size += round_up_to(cfg.get_input_data_size(), PAGE_SIZE_USIZE);

        expected_size += round_up_to(cfg.get_output_data_size(), PAGE_SIZE_USIZE);

        expected_size += round_up_to(cfg.get_guest_panic_context_buffer_size(), PAGE_SIZE_USIZE);

        expected_size += round_up_to(layout.heap_size, PAGE_SIZE_USIZE);

        expected_size += PAGE_SIZE_USIZE; // guard page

        expected_size += round_up_to(layout.stack_size, PAGE_SIZE_USIZE);

        expected_size += PAGE_SIZE_USIZE; // user stack guard page

        expected_size += round_up_to(layout.kernel_stack_size_rounded, PAGE_SIZE_USIZE);

        expected_size += PAGE_SIZE_USIZE; // kernel stack guard page

        expected_size += PAGE_SIZE_USIZE; // boot stack

        expected_size
    }

    #[test]
    fn test_get_memory_size() {
        let sbox_cfg = SandboxConfiguration::default();
        let sbox_mem_layout = SandboxMemoryLayout::new(sbox_cfg, 4096, 2048, 4096).unwrap();
        assert_eq!(
            sbox_mem_layout.get_memory_size().unwrap(),
            get_expected_memory_size(&sbox_mem_layout)
        );
    }
}
