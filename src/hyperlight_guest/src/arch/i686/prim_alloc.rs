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

#[allow(clippy::missing_safety_doc)]
pub unsafe fn alloc_phys_pages(_n: u64) -> u64 {
    panic!(
        "prim_alloc::alloc_phys_pages: i686 guests do not support booting the full hyperlight guest kernel"
    );
}
