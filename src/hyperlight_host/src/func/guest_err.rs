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

use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError as FbGuestError};

use crate::error::HyperlightError::{GuestError, OutBHandlingError, StackOverflow};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::{METRIC_GUEST_ERROR, METRIC_GUEST_ERROR_LABEL_CODE};
use crate::{log_then_return, Result};

/// Check for a guest error and return an `Err` if one was found,
/// and `Ok` if one was not found.
pub(crate) fn check_for_guest_error(
    mgr: &mut SandboxMemoryManager<HostSharedMemory>,
) -> Result<()> {
    let peb = mgr.memory_sections.read_hyperlight_peb()?;
    let (odr_buffer, odr_size) = peb.get_output_data_guest_region()?;
    let maybe_guest_err = mgr
        .shared_mem
        .try_pop_buffer_into::<FbGuestError>(odr_buffer as usize, odr_size as usize);

    let guest_err = if let Ok(err) = maybe_guest_err {
        err
    } else {
        // No guest error found, return Ok
        return Ok(());
    };

    match guest_err.code {
        ErrorCode::NoError => Ok(()),
        ErrorCode::OutbError => {
            metrics::counter!(METRIC_GUEST_ERROR, METRIC_GUEST_ERROR_LABEL_CODE => (guest_err.code as u64).to_string()).increment(1);

            log_then_return!(OutBHandlingError(guest_err.message.clone()));
        }
        ErrorCode::StackOverflow => {
            metrics::counter!(METRIC_GUEST_ERROR, METRIC_GUEST_ERROR_LABEL_CODE => (guest_err.code as u64).to_string()).increment(1);
            log_then_return!(StackOverflow());
        }
        _ => {
            metrics::counter!(METRIC_GUEST_ERROR, METRIC_GUEST_ERROR_LABEL_CODE => (guest_err.code as u64).to_string()).increment(1);
            log_then_return!(GuestError(guest_err.code, guest_err.message.clone()));
        }
    }
}
