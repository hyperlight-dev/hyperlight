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

// implements  security cookie used by /GS compiler option and checks value is valid
// calls report_gsfailure if value is invalid

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::GsCheckFailed;

use crate::__security_cookie;
use crate::guest_error::set_error_and_halt;

///cbindgen:ignore
#[unsafe(no_mangle)]
pub(crate) extern "C" fn __security_check_cookie(cookie: u64) {
    unsafe {
        if __security_cookie != cookie {
            set_error_and_halt(GsCheckFailed, "GS Check Failed");
        }
    }
}
