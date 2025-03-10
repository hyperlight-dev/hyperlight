use alloc::vec::Vec;
use anyhow::Result;
use flatbuffers::{size_prefixed_root, FlatBufferBuilder};

use crate::flatbuffers::hyperlight::generated::{HyperlightPEB as FbHyperlightPEB, HyperlightPEBArgs as FbHyperlightPEBArgs};

/// Hyperlight supports 2 primary modes:
/// 1. Hypervisor mode
/// 2. In-process mode
///
/// When running in process, there's no hypervisor isolation.
/// In-process mode is primarily used for debugging and testing.
#[repr(u64)]
#[derive(Clone, Debug, PartialEq)]
pub enum RunMode {
    None = 0,
    Hypervisor = 1,
    InProcessWindows = 2,
    InProcessLinux = 3,
    Invalid = 4,
}

#[derive(Clone)]
pub struct HyperlightPEB {
    /// The guest function dispatch pointer is what allows
    /// a host to call "guest functions". The host can
    /// directly set the instruction pointer register to this
    /// before re-entering the guest.
    pub guest_function_dispatch_ptr: Option<u64>,

    // Host function details may be used in the guest before
    // issuing a host function call to validate it before
    // ensuing a `VMEXIT`.
    pub host_function_details_ptr: Option<u64>,
    pub host_function_details_size: Option<u64>,

    /// Guest error data can be used to pass error information
    /// between host and the guest.
    pub guest_error_data_ptr: Option<u64>,
    pub guest_error_data_size: Option<u64>,

    /// On Windows, Hyperlight supports in-process execution.
    /// In-process execution means a guest is running in
    /// Hyperlight, but with no hypervisor isolation. When we
    /// run in-process, we can't rely on the usual mechanism for
    /// host function calls (i.e., `outb`). Instead, we call a
    /// function directly, which is represented by this pointer.
    pub outb_ptr: Option<u64>,

    /// Hyperlight supports two primary modes:
    /// 1. Hypervisor mode
    /// 2. In-process mode
    ///
    /// When running in process, there's no hypervisor isolation.
    /// It's a mode primarily used for debugging and testing.
    pub run_mode: Option<RunMode>,

    /// The input data pointer is used to pass data from
    /// the host to the guest.
    pub input_data_ptr: Option<u64>,
    pub input_data_size: Option<u64>,

    /// The output data pointer is used to pass data from
    /// the guest to the host.
    pub output_data_ptr: Option<u64>,
    pub output_data_size: Option<u64>,

    /// The guest panic context pointer can be used to pass
    /// panic context data from the guest to the host.
    pub guest_panic_context_ptr: Option<u64>,
    pub guest_panic_context_size: Option<u64>,

    /// The guest heap data pointer points to a region of
    /// memory in the guest that is used for heap allocations.
    pub guest_heap_data_ptr: Option<u64>,
    pub guest_heap_data_size: Option<u64>,

    /// The guest stack data pointer points to a region of
    /// memory in the guest that is used for stack allocations.
    pub guest_stack_data_ptr: Option<u64>,
    pub guest_stack_data_size: Option<u64>,
}

impl TryFrom<&[u8]> for HyperlightPEB {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let peb_fb = size_prefixed_root::<FbHyperlightPEB>(value)
            .map_err(|e| anyhow::anyhow!("Error reading HyperlightPEB buffer: {:?}", e))?;

        let run_mode = match peb_fb.run_mode() {
            0 => Some(RunMode::None),
            1 => Some(RunMode::Hypervisor),
            2 => Some(RunMode::InProcessWindows),
            3 => Some(RunMode::InProcessLinux),
            4 => Some(RunMode::Invalid),
            _ => None, // Handles unexpected values gracefully
        };

        Ok(Self {
            guest_function_dispatch_ptr: Some(peb_fb.guest_function_dispatch_ptr()).filter(|&v| v != 0),
            host_function_details_ptr: Some(peb_fb.host_function_details_ptr()).filter(|&v| v != 0),
            host_function_details_size: Some(peb_fb.host_function_details_size()).filter(|&v| v != 0),
            guest_error_data_ptr: Some(peb_fb.guest_error_data_ptr()).filter(|&v| v != 0),
            guest_error_data_size: Some(peb_fb.guest_error_data_size()).filter(|&v| v != 0),
            outb_ptr: Some(peb_fb.outb_ptr()).filter(|&v| v != 0),
            run_mode,
            input_data_ptr: Some(peb_fb.input_data_ptr()).filter(|&v| v != 0),
            input_data_size: Some(peb_fb.input_data_size()).filter(|&v| v != 0),
            output_data_ptr: Some(peb_fb.output_data_ptr()).filter(|&v| v != 0),
            output_data_size: Some(peb_fb.output_data_size()).filter(|&v| v != 0),
            guest_panic_context_ptr: Some(peb_fb.guest_panic_context_ptr()).filter(|&v| v != 0),
            guest_panic_context_size: Some(peb_fb.guest_panic_context_size()).filter(|&v| v != 0),
            guest_heap_data_ptr: Some(peb_fb.guest_heap_data_ptr()).filter(|&v| v != 0),
            guest_heap_data_size: Some(peb_fb.guest_heap_data_size()).filter(|&v| v != 0),
            guest_stack_data_ptr: Some(peb_fb.guest_stack_data_ptr()).filter(|&v| v != 0),
            guest_stack_data_size: Some(peb_fb.guest_stack_data_size()).filter(|&v| v != 0),
        })
    }
}

impl TryFrom<&mut [u8]> for HyperlightPEB {
    type Error = anyhow::Error;

    fn try_from(value: &mut [u8]) -> Result<Self> {
        let peb_fb = size_prefixed_root::<FbHyperlightPEB>(value)
            .map_err(|e| anyhow::anyhow!("Error reading HyperlightPEB buffer: {:?}", e))?;

        let run_mode = match peb_fb.run_mode() {
            0 => Some(RunMode::None),
            1 => Some(RunMode::Hypervisor),
            2 => Some(RunMode::InProcessWindows),
            3 => Some(RunMode::InProcessLinux),
            4 => Some(RunMode::Invalid),
            _ => None, // Handles unexpected values gracefully
        };

        Ok(Self {
            guest_function_dispatch_ptr: Some(peb_fb.guest_function_dispatch_ptr()).filter(|&v| v != 0),
            host_function_details_ptr: Some(peb_fb.host_function_details_ptr()).filter(|&v| v != 0),
            host_function_details_size: Some(peb_fb.host_function_details_size()).filter(|&v| v != 0),
            guest_error_data_ptr: Some(peb_fb.guest_error_data_ptr()).filter(|&v| v != 0),
            guest_error_data_size: Some(peb_fb.guest_error_data_size()).filter(|&v| v != 0),
            outb_ptr: Some(peb_fb.outb_ptr()).filter(|&v| v != 0),
            run_mode,
            input_data_ptr: Some(peb_fb.input_data_ptr()).filter(|&v| v != 0),
            input_data_size: Some(peb_fb.input_data_size()).filter(|&v| v != 0),
            output_data_ptr: Some(peb_fb.output_data_ptr()).filter(|&v| v != 0),
            output_data_size: Some(peb_fb.output_data_size()).filter(|&v| v != 0),
            guest_panic_context_ptr: Some(peb_fb.guest_panic_context_ptr()).filter(|&v| v != 0),
            guest_panic_context_size: Some(peb_fb.guest_panic_context_size()).filter(|&v| v != 0),
            guest_heap_data_ptr: Some(peb_fb.guest_heap_data_ptr()).filter(|&v| v != 0),
            guest_heap_data_size: Some(peb_fb.guest_heap_data_size()).filter(|&v| v != 0),
            guest_stack_data_ptr: Some(peb_fb.guest_stack_data_ptr()).filter(|&v| v != 0),
            guest_stack_data_size: Some(peb_fb.guest_stack_data_size()).filter(|&v| v != 0),
        })
    }
}

impl TryFrom<HyperlightPEB> for Vec<u8> {
    type Error = anyhow::Error;

    fn try_from(value: HyperlightPEB) -> Result<Vec<u8>> {
        let mut builder = FlatBufferBuilder::new();

        // Convert RunMode into u64
        let run_mode: u64 = match value.run_mode {
            Some(RunMode::None) => 0,
            Some(RunMode::Hypervisor) => 1,
            Some(RunMode::InProcessWindows) => 2,
            Some(RunMode::InProcessLinux) => 3,
            Some(RunMode::Invalid) => 4,
            None => 0, // Default to None
        };

        let hyperlight_peb = FbHyperlightPEB::create(
            &mut builder,
            &FbHyperlightPEBArgs {
                guest_function_dispatch_ptr: value.guest_function_dispatch_ptr.unwrap_or(0),
                host_function_details_ptr: value.host_function_details_ptr.unwrap_or(0),
                host_function_details_size: value.host_function_details_size.unwrap_or(0),
                guest_error_data_ptr: value.guest_error_data_ptr.unwrap_or(0),
                guest_error_data_size: value.guest_error_data_size.unwrap_or(0),
                outb_ptr: value.outb_ptr.unwrap_or(0),
                run_mode,
                input_data_ptr: value.input_data_ptr.unwrap_or(0),
                input_data_size: value.input_data_size.unwrap_or(0),
                output_data_ptr: value.output_data_ptr.unwrap_or(0),
                output_data_size: value.output_data_size.unwrap_or(0),
                guest_panic_context_ptr: value.guest_panic_context_ptr.unwrap_or(0),
                guest_panic_context_size: value.guest_panic_context_size.unwrap_or(0),
                guest_heap_data_ptr: value.guest_heap_data_ptr.unwrap_or(0),
                guest_heap_data_size: value.guest_heap_data_size.unwrap_or(0),
                guest_stack_data_ptr: value.guest_stack_data_ptr.unwrap_or(0),
                guest_stack_data_size: value.guest_stack_data_size.unwrap_or(0),
            },
        );

        builder.finish_size_prefixed(hyperlight_peb, None);
        let res = builder.finished_data().to_vec();

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use anyhow::Result;
    use crate::flatbuffer_wrappers::hyperlight_peb::{HyperlightPEB, RunMode};

    #[test]
    fn test_hyperlight_peb_to_vec_u8() -> Result<()> {
        let peb = HyperlightPEB {
            guest_function_dispatch_ptr: Some(0x1000),
            host_function_details_ptr: Some(0x2000),
            host_function_details_size: Some(64),
            guest_error_data_ptr: Some(0x3000),
            guest_error_data_size: Some(128),
            outb_ptr: Some(0x4000),
            run_mode: Some(RunMode::Hypervisor),
            input_data_ptr: Some(0x5000),
            input_data_size: Some(256),
            output_data_ptr: Some(0x6000),
            output_data_size: Some(512),
            guest_panic_context_ptr: Some(0x7000),
            guest_panic_context_size: Some(32),
            guest_heap_data_ptr: Some(0x8000),
            guest_heap_data_size: Some(1024),
            guest_stack_data_ptr: Some(0x9000),
            guest_stack_data_size: Some(2048),
        };

        let buffer: Vec<u8> = peb.try_into()?;
        let parsed_peb = HyperlightPEB::try_from(buffer.as_slice())?;

        assert_eq!(parsed_peb.guest_function_dispatch_ptr, Some(0x1000));
        assert_eq!(parsed_peb.host_function_details_ptr, Some(0x2000));
        assert_eq!(parsed_peb.host_function_details_size, Some(64));
        assert_eq!(parsed_peb.guest_error_data_ptr, Some(0x3000));
        assert_eq!(parsed_peb.guest_error_data_size, Some(128));
        assert_eq!(parsed_peb.outb_ptr, Some(0x4000));
        assert_eq!(parsed_peb.run_mode, Some(RunMode::Hypervisor));
        assert_eq!(parsed_peb.input_data_ptr, Some(0x5000));
        assert_eq!(parsed_peb.input_data_size, Some(256));
        assert_eq!(parsed_peb.output_data_ptr, Some(0x6000));
        assert_eq!(parsed_peb.output_data_size, Some(512));
        assert_eq!(parsed_peb.guest_panic_context_ptr, Some(0x7000));
        assert_eq!(parsed_peb.guest_panic_context_size, Some(32));
        assert_eq!(parsed_peb.guest_heap_data_ptr, Some(0x8000));
        assert_eq!(parsed_peb.guest_heap_data_size, Some(1024));
        assert_eq!(parsed_peb.guest_stack_data_ptr, Some(0x9000));
        assert_eq!(parsed_peb.guest_stack_data_size, Some(2048));

        Ok(())
    }
}