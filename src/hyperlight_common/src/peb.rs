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

/// Represents a memory region with an offset and a size.
#[derive(Clone, Debug, Default)]
pub struct MemoryRegion {
    pub offset: Option<u64>,
    pub size: u64,
}

#[repr(C)]
#[derive(Clone, Default)]
pub struct HyperlightPEB {
    /// The minimum stack address is the lowest address of the stack.
    pub min_stack_address: u64,

    // - Host configured fields
    /// Hyperlight supports two primary modes:
    /// 1. Hypervisor mode
    /// 2. In-process mode
    ///
    /// When running in process, there's no hypervisor isolation.
    /// It's a mode primarily used for debugging and testing.
    run_mode: RunMode,

    /// On Windows, Hyperlight supports in-process execution.
    /// In-process execution means a guest is running in
    /// Hyperlight, but with no hypervisor isolation. When we
    /// run in-process, we can't rely on the usual mechanism for
    /// host function calls (i.e., `outb`). Instead, we call a
    /// function directly, which is represented by these pointers.
    outb_ptr: u64,
    outb_ptr_ctx: u64,

    /// The host base address for the custom guest memory region.
    guest_memory_host_base_address: u64,

    /// The base address for the guest memory region.
    guest_memory_base_address: u64,

    /// The size of the guest memory region.
    guest_memory_size: u64,

    // - Guest configured fields
    /// The guest function dispatch pointer is what allows
    /// a host to call "guest functions". The host can
    /// directly set the instruction pointer register to this
    /// before re-entering the guest.
    guest_function_dispatch_ptr: u64,

    /// The input data pointer is used to pass data from
    /// the host to the guest.
    input_data: Option<MemoryRegion>,

    /// The output data pointer is used to pass data from
    /// the guest to the host.
    output_data: Option<MemoryRegion>,

    /// The guest panic context pointer can be used to pass
    /// panic context data from the guest to the host.
    guest_panic_context: Option<MemoryRegion>,

    /// The guest heap data pointer points to a region of
    /// memory in the guest that is used for heap allocations.
    guest_heap_data: Option<MemoryRegion>,

    /// The guest stack data pointer points to a region of
    /// memory in the guest that is used for stack allocations.
    guest_stack_data: Option<MemoryRegion>,
}

impl HyperlightPEB {
    /// Creates a new HyperlightPEB with the basic configuration based on the provided guest memory
    /// layout and default guest heap/stack sizes. The guest can later fill additional fields.
    pub fn new(
        min_stack_address: u64,
        run_mode: RunMode,
        guest_heap_size: u64,
        guest_stack_size: u64,
        guest_memory_host_base_address: u64,
        guest_memory_base_address: u64,
        guest_memory_size: u64,
    ) -> Self {
        Self {
            min_stack_address,
            run_mode,
            outb_ptr: 0,
            outb_ptr_ctx: 0,
            guest_memory_host_base_address,
            guest_memory_base_address,
            guest_memory_size,
            guest_function_dispatch_ptr: 0,
            input_data: None,
            output_data: None,
            guest_panic_context: None,
            guest_heap_data: Some(MemoryRegion {
                offset: None,
                size: guest_heap_size,
            }),
            guest_stack_data: Some(MemoryRegion {
                offset: None,
                size: guest_stack_size,
            }),
        }
    }

    /// Convenience method that sets an arbitrary "default" memory layout for the guest. This layout
    /// is used by guests built w/ the `hyperlight_guest` library.
    /// - +--------------------------+
    /// - | Guest panic context data | 4KB
    /// - +--------------------------+
    /// - | Output data              | 16KB
    /// - +--------------------------+
    /// - | Input data               | 16KB
    /// - +--------------------------+
    /// - | Guest heap data          | (configurable size)
    /// - +--------------------------+
    /// - | Guest stack data         | (configurable size)
    /// - +--------------------------+
    pub fn set_default_memory_layout(&mut self) {
        // we set the guest stack at the start of the guest memory region to leverage
        // the stack guard page before it
        self.set_guest_stack_data_region(
            0x0,  // start at base of custom guest memory region,
            None, // don't override the stack size
        );

        let guest_stack_size = self.get_guest_stack_data_size();

        self.set_guest_heap_data_region(
            guest_stack_size, // start at the end of the stack
            None,             // don't override the heap size
        );

        let guest_heap_size = self.get_guest_heap_data_size();

        self.set_input_data_region(
            guest_stack_size + guest_heap_size, // start at the end of the heap
            PAGE_SIZE as u64 * 4,               // 16KB
        );

        self.set_output_data_region(
            guest_stack_size + guest_heap_size + PAGE_SIZE as u64 * 4, // start at the end of the input data
            PAGE_SIZE as u64 * 4,                                      // 16KB
        );

        self.set_guest_panic_context_region(
            guest_stack_size + guest_heap_size + PAGE_SIZE as u64 * 8, // start at the end of the output data
            PAGE_SIZE as u64,                                          // 4KB
        );
    }

    /// Sets the guest stack data region.
    /// - HyperlightPEB is always set with a default size for stack from the guest binary, there's an
    ///     option to override this size with the `size_override` parameter.

    pub fn set_guest_stack_data_region(&mut self, offset: u64, size_override: Option<u64>) {
        let size = size_override.unwrap_or_else(|| {
            self.guest_stack_data
                .as_ref()
                .expect("Guest stack region must be defined")
                .size
        });
        self.guest_stack_data = Some(MemoryRegion {
            offset: Some(offset),
            size,
        });

        if size == 0 {
            panic!("Stack data size is 0 after setting guest stack data region");
        }
    }

    /// Get guest stack data region (offset + size).
    pub fn get_guest_stack_data_region(&self) -> Option<MemoryRegion> {
        self.guest_stack_data.clone()
    }

    /// Gets the guest stack data region depending on the running mode (i.e., if `RunMode::Hypervisor` this
    /// returns the stack data guest address. If `RunMode::InProcessWindows` or `RunMode::InProcessLinux`, it
    /// returns the stack data host address).
    pub fn get_stack_data_address(&self) -> u64 {
        let region = self
            .guest_stack_data
            .as_ref()
            .expect("Stack data region not set");
        match self.run_mode {
            RunMode::Hypervisor => region.offset.unwrap() + self.guest_memory_base_address,
            RunMode::InProcessWindows | RunMode::InProcessLinux => {
                region.offset.unwrap() + self.guest_memory_host_base_address
            }
            _ => panic!("Invalid running mode"),
        }
    }

    /// Returns the size of the guest stack data region. Panics if region is not set.
    pub fn get_guest_stack_data_size(&self) -> u64 {
        self.guest_stack_data
            .as_ref()
            .expect("Stack data region is not set")
            .size
    }

    /// Gets the top of the guest stack data region (i.e., guest memory base address + guest stack
    /// offset + guest stack size).
    pub fn get_top_of_guest_stack_data(&self) -> u64 {
        let region = self
            .guest_stack_data
            .as_ref()
            .expect("Guest stack data region not set");
        region.offset.unwrap() + self.guest_memory_base_address + region.size
    }

    /// Calculate the minimum guest stack address (start of guest stack data region in the guest
    /// address space).
    pub fn calculate_min_stack_address(&self) -> u64 {
        let region = self
            .guest_stack_data
            .as_ref()
            .expect("Guest stack data region not set");
        region.offset.unwrap() + self.guest_memory_base_address
    }

    /// Sets the guest heap data region.
    /// - HyperlightPEB is always set with a default size for heap from the guest binary, there's an
    ///     option to override this size with the `size_override` parameter.
    pub fn set_guest_heap_data_region(&mut self, offset: u64, size_override: Option<u64>) {
        let size = size_override.unwrap_or_else(|| {
            self.guest_heap_data
                .as_ref()
                .expect("Guest heap region must be defined")
                .size
        });
        self.guest_heap_data = Some(MemoryRegion {
            offset: Some(offset),
            size,
        });

        if size == 0 {
            panic!("Heap data size is 0 after setting guest heap data region");
        }
    }

    /// Gets the guest heap data region depending on the running mode (i.e., if `RunMode::Hypervisor` this
    /// returns the heap data guest address. If `RunMode::InProcessWindows` or `RunMode::InProcessLinux`, it
    /// returns the heap data host address).
    pub fn get_heap_data_address(&self) -> u64 {
        let region = self
            .guest_heap_data
            .as_ref()
            .expect("Heap data region not set");
        match self.run_mode {
            RunMode::Hypervisor => region.offset.unwrap() + self.guest_memory_base_address,
            RunMode::InProcessWindows | RunMode::InProcessLinux => {
                region.offset.unwrap() + self.guest_memory_host_base_address
            }
            _ => panic!("Invalid running mode"),
        }
    }

    /// Returns the size of the guest heap data region. Panics if region is not set.
    pub fn get_guest_heap_data_size(&self) -> u64 {
        self.guest_heap_data
            .as_ref()
            .expect("Heap data region is not set")
            .size
    }

    /// Sets the input data region.
    pub fn set_input_data_region(&mut self, offset: u64, size: u64) {
        self.input_data = Some(MemoryRegion {
            offset: Some(offset),
            size,
        });
    }

    /// Gets the input data region with guest addresses.
    pub fn get_input_data_guest_region(&self) -> (u64, u64) {
        let region = self.input_data.as_ref().expect("Input data region not set");
        (
            region.offset.unwrap() + self.guest_memory_base_address,
            region.size,
        )
    }

    /// Gets the input data region with host addresses.
    pub fn get_input_data_host_region(&self) -> (u64, u64) {
        let region = self.input_data.as_ref().expect("Input data region not set");
        (
            region.offset.unwrap() + self.guest_memory_host_base_address,
            region.size,
        )
    }

    /// Gets the input data region based on the running mode (i.e., if `RunMode::Hypervisor` this
    /// function outputs the same as `get_input_data_guest_region`. If `RunMode::InProcessWindows`
    /// or `RunMode::InProcessLinux`, it outputs the same as `get_input_data_host_region`).
    pub fn get_input_data_region(&self) -> (u64, u64) {
        match self.run_mode {
            RunMode::Hypervisor => self.get_input_data_guest_region(),
            RunMode::InProcessWindows | RunMode::InProcessLinux => {
                self.get_input_data_host_region()
            }
            _ => panic!("Invalid running mode"),
        }
    }

    /// Sets the output data region.
    pub fn set_output_data_region(&mut self, offset: u64, size: u64) {
        self.output_data = Some(MemoryRegion {
            offset: Some(offset),
            size,
        });
    }

    /// Gets the output data region with guest addresses.
    pub fn get_output_data_guest_region(&self) -> (u64, u64) {
        let region = self
            .output_data
            .as_ref()
            .expect("Output data region not set");
        (
            region.offset.unwrap() + self.guest_memory_base_address,
            region.size,
        )
    }

    /// Gets the output data region with host addresses.
    pub fn get_output_data_host_region(&self) -> (u64, u64) {
        let region = self
            .output_data
            .as_ref()
            .expect("Output data region not set");
        (
            region.offset.unwrap() + self.guest_memory_host_base_address,
            region.size,
        )
    }

    /// Gets the output data region based on the running mode (i.e., if `RunMode::Hypervisor` this
    /// returns the same as `get_output_data_guest_region`. If `RunMode::InProcessWindows`
    /// or `RunMode::InProcessLinux`, it returns the same as `get_output_data_host_region`).
    pub fn get_output_data_region(&self) -> (u64, u64) {
        match self.run_mode {
            RunMode::Hypervisor => self.get_output_data_guest_region(),
            RunMode::InProcessWindows | RunMode::InProcessLinux => {
                self.get_output_data_host_region()
            }
            _ => panic!("Invalid running mode"),
        }
    }

    /// Sets the guest panic context region.
    pub fn set_guest_panic_context_region(&mut self, offset: u64, size: u64) {
        self.guest_panic_context = Some(MemoryRegion {
            offset: Some(offset),
            size,
        });
    }

    /// Gets the guest panic context region depending on the running mode (i.e., if `RunMode::Hypervisor` this
    /// returns the same as `get_guest_panic_context_guest_address`. If `RunMode::InProcessWindows` or `RunMode::InProcessLinux`, it
    /// returns the panic context host address).
    pub fn get_guest_panic_context_address(&self) -> u64 {
        let region = self
            .guest_panic_context
            .as_ref()
            .expect("Guest panic context region not set");
        match self.run_mode {
            RunMode::Hypervisor => self.get_guest_panic_context_guest_address(),
            RunMode::InProcessWindows | RunMode::InProcessLinux => {
                region.offset.unwrap() + self.guest_memory_host_base_address
            }
            _ => panic!("Invalid running mode"),
        }
    }

    /// Gets the guest panic context region with guest addresses.
    pub fn get_guest_panic_context_guest_address(&self) -> u64 {
        self.guest_panic_context
            .as_ref()
            .expect("Guest panic context region not set")
            .offset
            .unwrap()
            + self.guest_memory_base_address
    }

    /// Gets the guest panic context size.
    pub fn get_guest_panic_context_size(&self) -> u64 {
        self.guest_panic_context
            .as_ref()
            .expect("Guest panic context region not set")
            .size
    }

    /// Sets the pointer to the outb handler function used to simulate the outb instruction when running
    /// in-process.
    pub fn set_outb_ptr(&mut self, ptr: u64) {
        self.outb_ptr = ptr;
    }

    /// Gets the pointer to the outb handler function.
    pub fn get_outb_ptr(&self) -> u64 {
        self.outb_ptr
    }

    /// Sets the outb pointer context used together with the outb ptr when running in-process.
    pub fn set_outb_ptr_ctx(&mut self, ptr: u64) {
        self.outb_ptr_ctx = ptr;
    }

    /// Gets the outb pointer context.
    pub fn get_outb_ptr_ctx(&self) -> u64 {
        self.outb_ptr_ctx
    }

    /// Gets the run mode.
    pub fn get_run_mode(&self) -> RunMode {
        self.run_mode.clone()
    }

    /// Sets the guest function dispatch pointer.
    pub fn set_guest_function_dispatch_ptr(&mut self, ptr: u64) {
        self.guest_function_dispatch_ptr = ptr;
    }

    /// Gets the guest function dispatch pointer.
    pub fn get_guest_function_dispatch_ptr(&self) -> u64 {
        self.guest_function_dispatch_ptr
    }
}
