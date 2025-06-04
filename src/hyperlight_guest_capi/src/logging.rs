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

use core::ffi::c_char;

#[unsafe(no_mangle)]
pub extern "C" fn hl_log(
    level: log::Level,
    message: *const c_char,
    line: i32,
    file: *const c_char,
) {
    if log::log_enabled!(level) {
        let message = unsafe { core::ffi::CStr::from_ptr(message).to_string_lossy() };
        let file = unsafe { core::ffi::CStr::from_ptr(file).to_string_lossy() };

        log::logger().log(
            &log::RecordBuilder::new()
                .args(format_args!("{}: {}", level, message))
                .level(level)
                .line(Some(line as u32))
                .file(Some(&file))
                .build(),
        );
    }
}
