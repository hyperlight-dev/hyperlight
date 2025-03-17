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

use hyperlight_common::flatbuffer_wrappers::guest_error::{
    ErrorCode, GuestError as GuestErrorStruct,
};

use crate::error::HyperlightError::{GuestError, OutBHandlingError, StackOverflow};
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox::mem_mgr::MemMgrWrapper;
use crate::sandbox::metrics::SandboxMetric::GuestErrorCount;
use crate::{Result, int_counter_vec_inc, log_then_return};
/// Check for a guest error and return an `Err` if one was found,
/// and `Ok` if one was not found.
pub(crate) fn check_for_guest_error(mgr: &MemMgrWrapper<HostSharedMemory>) -> Result<()> {
    let guest_err = mgr.as_ref().get_guest_error()?;
    match guest_err.code {
        ErrorCode::NoError => Ok(()),
        ErrorCode::OutbError => match mgr.as_ref().get_host_error()? {
            Some(host_err) => {
                increment_guest_error_count(&guest_err);
                log_then_return!(OutBHandlingError(
                    host_err.source.clone(),
                    guest_err.message.clone()
                ));
            }
            // TODO: Not sure this is correct behavior. We should probably return error here
            None => Ok(()),
        },
        ErrorCode::StackOverflow => {
            increment_guest_error_count(&guest_err.clone());
            log_then_return!(StackOverflow());
        }
        _ => {
            increment_guest_error_count(&guest_err.clone());
            log_then_return!(GuestError(
                guest_err.code.clone(),
                guest_err.message.clone()
            ));
        }
    }
}

fn increment_guest_error_count(guest_err: &GuestErrorStruct) {
    let guest_err_code_string: String = guest_err.code.clone().into();
    int_counter_vec_inc!(
        &GuestErrorCount,
        &[&guest_err_code_string, guest_err.message.clone().as_str()]
    );
}
