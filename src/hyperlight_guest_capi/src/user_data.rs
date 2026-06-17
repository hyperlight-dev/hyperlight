/*
Copyright 2025 The Hyperlight Authors.

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

use core::ptr::null_mut;

use hyperlight_guest_bin::host_comm::{user_data_ptr, user_data_size};

/// Return the user data region capacity advertised in the PEB.
#[unsafe(no_mangle)]
pub extern "C" fn hl_user_data_size() -> usize {
    user_data_size().unwrap_or(0) as usize
}

/// Return the user data region pointer advertised in the PEB.
///
/// C callers must bound all memory access by [`hl_user_data_size`]. This is a
/// raw pointer into guest scratch memory, not a guard-page-isolated mapping.
#[unsafe(no_mangle)]
pub extern "C" fn hl_user_data_ptr() -> *mut u8 {
    user_data_ptr().unwrap_or_else(|_| null_mut())
}
