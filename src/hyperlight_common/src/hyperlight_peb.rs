use crate::PAGE_SIZE;

/// Hyperlight supports 2 primary modes:
/// 1. Hypervisor mode
/// 2. In-process mode
///
/// When running in process, there's no hypervisor isolation.
/// In-process mode is primarily used for debugging and testing.
#[repr(u64)]
#[derive(Clone, Debug, PartialEq, Default)]
pub enum RunMode {
    None = 0,
    #[default]
    Hypervisor = 1,
    InProcessWindows = 2,
    InProcessLinux = 3,
    Invalid = 4,
}

#[repr(C)]
#[derive(Clone, Default)]
pub struct HyperlightPEB {
    // - Host configured fields
    /// Hyperlight supports two primary modes:
    /// 1. Hypervisor mode
    /// 2. In-process mode
    ///
    /// When running in process, there's no hypervisor isolation.
    /// It's a mode primarily used for debugging and testing.
    pub run_mode: RunMode,

    /// On Windows, Hyperlight supports in-process execution.
    /// In-process execution means a guest is running in
    /// Hyperlight, but with no hypervisor isolation. When we
    /// run in-process, we can't rely on the usual mechanism for
    /// host function calls (i.e., `outb`). Instead, we call a
    /// function directly, which is represented by this pointer.
    pub outb_ptr: u64,

    /// The base address for the guest memory region.
    pub guest_memory_base_address: u64,

    /// The size of the guest memory region.
    pub guest_memory_size: u64,

    // - Guest configured fields
    /// The guest function dispatch pointer is what allows
    /// a host to call "guest functions". The host can
    /// directly set the instruction pointer register to this
    /// before re-entering the guest.
    pub guest_function_dispatch_ptr: u64,

    /// Guest error data can be used to pass guest error information
    /// between host and the guest.
    pub guest_error_data_ptr: u64,
    pub guest_error_data_size: u64,

    /// Host error data can be used to pass host error information
    /// between the host and the guest.
    pub host_error_data_ptr: u64,
    pub host_error_data_size: u64,

    /// The input data pointer is used to pass data from
    /// the host to the guest.
    pub input_data_ptr: u64,
    pub input_data_size: u64,

    /// The output data pointer is used to pass data from
    /// the guest to the host.
    pub output_data_ptr: u64,
    pub output_data_size: u64,

    /// The guest panic context pointer can be used to pass
    /// panic context data from the guest to the host.
    pub guest_panic_context_ptr: u64,
    pub guest_panic_context_size: u64,

    /// The guest heap data pointer points to a region of
    /// memory in the guest that is used for heap allocations.
    pub guest_heap_data_ptr: u64,
    pub guest_heap_data_size: u64,

    /// The guest stack data pointer points to a region of
    /// memory in the guest that is used for stack allocations.
    pub guest_stack_data_ptr: u64,
    pub guest_stack_data_size: u64,

    // Host function details may be used in the guest before
    // issuing a host function call to validate it before
    // ensuing a `VMEXIT`.
    pub host_function_details_ptr: u64,
    pub host_function_details_size: u64,
}

impl HyperlightPEB {
    pub fn set_default_memory_layout(&mut self) {
        // we set the guest stack at the start of the guest memory region to leverage
        // the stack guard page before it
        self.set_guest_stack_data_region(
            self.guest_memory_base_address, // start at base of custom guest memory region,
            None,                           // don't override the stack size
        );

        let guest_stack_size = self.get_guest_stack_data_size();

        self.set_guest_heap_data_region(
            guest_stack_size, // start at the end of the stack
            None,             // don't override the heap size
        );

        let guest_heap_size = self.get_guest_heap_data_size();

        self.set_guest_error_data_region(
            guest_stack_size + guest_heap_size as u64, // start at the end of the host function details
            PAGE_SIZE as u64,                          // 4KB
        );

        self.set_host_error_data_region(
            guest_stack_size + guest_heap_size + PAGE_SIZE as u64, // start at the end of the guest error data
            PAGE_SIZE as u64,                                      // 4KB
        );

        self.set_input_data_region(
            guest_stack_size + guest_heap_size + PAGE_SIZE as u64 * 2, // start at the end of the host error data
            PAGE_SIZE as u64 * 4,                                      // 16KB
        );

        self.set_output_data_region(
            guest_stack_size + guest_heap_size + PAGE_SIZE as u64 * 6, // start at the end of the input data
            PAGE_SIZE as u64 * 4,                                      // 16KB
        );

        self.set_guest_panic_context_region(
            guest_stack_size + guest_heap_size + PAGE_SIZE as u64 * 10, // start at the end of the output data
            PAGE_SIZE as u64,                                           // 4KB
        );

        self.set_host_function_details_region(
            guest_stack_size + guest_heap_size + PAGE_SIZE as u64 * 11, // start at the end of the guest panic context
            PAGE_SIZE as u64,                                           // 4KB
        );
    }

    // Sets the guest error data region, where the guest can write errors to.
    pub fn set_guest_error_data_region(&mut self, ptr: u64, size: u64) {
        self.guest_error_data_ptr = self.guest_memory_base_address + ptr;
        self.guest_error_data_size = size;
    }

    // Sets the host error data region, where the host can write errors to.
    pub fn set_host_error_data_region(&mut self, ptr: u64, size: u64) {
        self.host_error_data_ptr = self.guest_memory_base_address + ptr;
        self.host_error_data_size = size;
    }

    // Sets the input data region, where the host can write things like function calls to.
    pub fn set_input_data_region(&mut self, ptr: u64, size: u64) {
        self.input_data_ptr = self.guest_memory_base_address + ptr;
        self.input_data_size = size;
    }

    // Sets the output data region, where the guest can write things like function return values to.
    pub fn set_output_data_region(&mut self, ptr: u64, size: u64) {
        self.output_data_ptr = self.guest_memory_base_address + ptr;
        self.output_data_size = size;
    }

    // Sets the guest panic context region, where the guest can write panic context data to.
    pub fn set_guest_panic_context_region(&mut self, ptr: u64, size: u64) {
        self.guest_panic_context_ptr = self.guest_memory_base_address + ptr;
        self.guest_panic_context_size = size;
    }

    // Gets the guest heap size. If not set, this function panics—this is because the host is always
    // expected to set the size of the heap data region in accordance to info from the guest binary,
    // so, if this is not set, we have a critical error.
    pub fn get_guest_heap_data_size(&self) -> u64 {
        if self.guest_heap_data_size == 0 {
            panic!("Heap data size is not set");
        }

        self.guest_heap_data_size
    }

    // Sets the guest heap data region.
    pub fn set_guest_heap_data_region(&mut self, ptr: u64, size_override: Option<u64>) {
        self.guest_heap_data_ptr = self.guest_memory_base_address + ptr;
        // the Hyperlight host always sets the heap data size to a default value, the
        // guest has the option to override it.
        if let Some(size) = size_override {
            self.guest_heap_data_size = size;
        }

        // If by this point the size is still None, we have a critical error
        // and we should panic.
        if self.guest_heap_data_size == 0 {
            panic!("Heap data size is 0 after setting guest heap data region");
        }
    }

    // Gets the guest heap size. If not set, this function panics—this is because the host is always
    // expected to set the size of the heap data region in accordance to info from the guest binary,
    // so, if this is not set, we have a critical error.
    pub fn get_guest_stack_data_size(&self) -> u64 {
        if self.guest_stack_data_size == 0 {
            panic!("Stack data size is not set");
        }

        self.guest_stack_data_size
    }

    // Sets the guest stack data region.
    pub fn set_guest_stack_data_region(&mut self, ptr: u64, size_override: Option<u64>) {
        self.guest_stack_data_ptr = self.guest_memory_base_address + ptr;

        // the Hyperlight host always sets the stack data size to a default value, the
        // guest has the option to override it.
        if let Some(size) = size_override {
            self.guest_stack_data_size = size;
        }

        // If by this point the size is still None, we have a critical error
        // and we should panic.
        if self.guest_stack_data_size == 0 {
            panic!("Stack data size is 0 after setting guest stack data region");
        }
    }

    // Sets the host function details region, where the guest can write host function details to.
    pub fn set_host_function_details_region(&mut self, ptr: u64, size: u64) {
        self.host_function_details_ptr = self.guest_memory_base_address + ptr;
        self.host_function_details_size = size;
    }

    // Gets the input data region, where the host can write things like function calls to.
    pub fn get_input_data_region(&self) -> (u64, u64) {
        (self.input_data_ptr, self.input_data_size)
    }

    // Gets the output data region, where the guest can write things like function return values to.
    pub fn get_output_data_region(&self) -> (u64, u64) {
        (self.output_data_ptr, self.output_data_size)
    }
}
