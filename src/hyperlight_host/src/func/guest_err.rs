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

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

use crate::error::HyperlightError::{GuestError, StackOverflow};
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::{METRIC_GUEST_ERROR, METRIC_GUEST_ERROR_LABEL_CODE};
use crate::sandbox::mem_mgr::MemMgrWrapper;
use crate::{log_then_return, Result};

/// Check for a guest error and return an `Err` if one was found,
/// and `Ok` if one was not found.
pub(crate) fn check_for_guest_error(mgr: &mut MemMgrWrapper<HostSharedMemory>) -> Result<()> {
    let guest_err = mgr.as_mut().get_guest_error().ok();
    let Some(guest_err) = guest_err else {
        return Ok(());
    };

    metrics::counter!(
        METRIC_GUEST_ERROR,
        METRIC_GUEST_ERROR_LABEL_CODE => (guest_err.code as u64).to_string()
    )
    .increment(1);

    match guest_err.code {
        ErrorCode::NoError => Ok(()),
        ErrorCode::StackOverflow => {
            log_then_return!(StackOverflow());
        }
        _ => {
            log_then_return!(GuestError(guest_err.code, guest_err.message.clone()));
        }
    }
}
