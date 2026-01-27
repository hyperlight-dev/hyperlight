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

// This file is just dummy definitions at the moment, in order to
// allow compiling the guest for real mode boot scenarios.

use crate::vmem::{BasicMapping, Mapping, TableOps};

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_TABLE_SIZE: usize = 4096;
pub type PageTableEntry = u32;
pub type VirtAddr = u32;
pub type PhysAddr = u32;

#[allow(clippy::missing_safety_doc)]
pub unsafe fn map<Op: TableOps>(_op: &Op, _mapping: Mapping) {
    panic!("vmem::map: i686 guests do not support booting the full hyperlight guest kernel");
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn virt_to_phys<Op: TableOps>(_op: &Op, _address: u64) -> Option<(u64, BasicMapping)> {
    panic!(
        "vmem::virt_to_phys: i686 guests do not support booting the full hyperlight guest kernel"
    );
}
