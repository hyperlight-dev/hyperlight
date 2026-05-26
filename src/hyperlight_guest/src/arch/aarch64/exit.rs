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

// TODO(aarch64): implement VM exit mechanism (e.g. hvc instruction)

const IO_PAGE_GVA: u64 = hyperlight_common::layout::io_page().unwrap().1;

/// Trigger a VM exit sending a 32-bit value to the host on the given port.
pub(crate) unsafe fn out32(port: u16, val: u32) {
    if port as usize > (hyperlight_common::vmem::PAGE_SIZE / core::mem::size_of::<u64>()) {
        panic!("aarch64 mmio: unsupported hypercall number {}", port);
    }
    unsafe {
        (IO_PAGE_GVA as *mut u64)
            .wrapping_add(port as usize)
            .write_volatile(val as u64);
    }
}
