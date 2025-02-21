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

/// Exception handler
#[no_mangle]
pub extern "sysv64" fn hl_exception_handler(
    stack_pointer: u64,
    exception_number: u64,
    page_fault_address: u64,
) {
    panic!(
        "EXCEPTION: {:#x}\n\
            Page Fault Address: {:#x}\n\
            Stack Pointer: {:#x}",
        exception_number, page_fault_address, stack_pointer
    );
}
