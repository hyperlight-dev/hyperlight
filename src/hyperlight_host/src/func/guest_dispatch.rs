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

use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use tracing::{instrument, Span};

use super::guest_err::check_for_guest_error;
use crate::hypervisor::hypervisor_handler::{HypervisorHandler, HypervisorHandlerAction};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
use crate::HyperlightError::GuestExecutionHungOnHostFunctionCall;
use crate::{HyperlightError, Result};

/// Call a guest function by name, using the given `wrapper_getter`.
#[instrument(
    err(Debug),
    skip(hv_handler, mem_mgr, args),
    parent = Span::current(),
    level = "Trace"
)]
pub(crate) fn call_function_on_guest(
    hv_handler: &mut HypervisorHandler,
    mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    function_name: &str,
    return_type: ReturnType,
    args: Option<Vec<ParameterValue>>,
) -> Result<ReturnValue> {
    let mut timedout = false;

    let fc = FunctionCall::new(
        function_name.to_string(),
        args,
        FunctionCallType::Guest,
        return_type,
    );

    let buffer: Vec<u8> = fc
        .try_into()
        .map_err(|_| HyperlightError::Error("Failed to serialize FunctionCall".to_string()))?;

    let input_data_region = mem_mgr
        .memory_sections
        .read_hyperlight_peb()?
        .get_input_data_guest_region();

    mem_mgr.set_stack_guard()?;
    mem_mgr.write_guest_function_call(input_data_region, &buffer)?;

    match hv_handler.execute_hypervisor_handler_action(
        HypervisorHandlerAction::DispatchCallFromHost(function_name.to_string()),
    ) {
        Ok(()) => {}
        Err(e) => match e {
            HyperlightError::HypervisorHandlerMessageReceiveTimedout() => {
                timedout = true;
                match hv_handler.terminate_hypervisor_handler_execution_and_reinitialise(mem_mgr)? {
                    HyperlightError::HypervisorHandlerExecutionCancelAttemptOnFinishedExecution() =>
                        {}
                    // ^^^ do nothing, we just want to actually get the Flatbuffer return value
                    // from shared memory in this case
                    e => return Err(e),
                }
            }
            e => return Err(e),
        },
    };

    mem_mgr.check_stack_guard()?; // <- wrapper around mem_mgr `check_for_stack_guard`
    check_for_guest_error(mem_mgr)?;

    let output_data_region = mem_mgr
        .memory_sections
        .read_hyperlight_peb()?
        .get_output_data_guest_region();

    mem_mgr
        .get_guest_function_call_result(output_data_region)
        .map_err(|e| {
            if timedout {
                // if we timed-out, but still got here
                // that means we had actually gotten stuck
                // on the execution of a host function, and;
                // hence, couldn't cancel guest execution.
                // This particular check is needed now, because
                // unlike w/ the previous scoped thread usage,
                // we can't check if the thread completed or not.
                log::error!("Guest execution hung on host function call");
                GuestExecutionHungOnHostFunctionCall()
            } else {
                e
            }
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use hyperlight_testing::{callback_guest_as_string, simple_guest_as_string};

    use super::*;
    use crate::func::host_functions::HostFunction0;
    use crate::sandbox::is_hypervisor_present;
    use crate::sandbox::sandbox_builder::SandboxBuilder;
    use crate::sandbox_state::sandbox::EvolvableSandbox;
    use crate::sandbox_state::transition::Noop;
    use crate::{GuestBinary, HyperlightError, MultiUseSandbox, Result, UninitializedSandbox};

    #[track_caller]
    fn test_call_guest_function_by_name(u_sbox: UninitializedSandbox) -> Result<()> {
        let mu_sbox: MultiUseSandbox = u_sbox.evolve(Noop::default())?;

        let mut ctx = mu_sbox.new_call_context();
        let result = ctx.call(
            "EchoDouble",
            ReturnType::Double,
            Some(vec![ParameterValue::Double(std::f64::consts::PI)]),
        )?;

        assert_eq!(result, ReturnValue::Double(std::f64::consts::PI));

        Ok(())
    }

    fn call_guest_function_by_name_hv() -> Result<()> {
        let sandbox_builder =
            SandboxBuilder::new(GuestBinary::FilePath(simple_guest_as_string()?))?;
        let uninitialized_sandbox = sandbox_builder.build()?;

        test_call_guest_function_by_name(uninitialized_sandbox)
    }

    fn terminate_vcpu_after_1000ms() -> Result<()> {
        // This test relies upon a Hypervisor being present so for now
        // we will skip it if there isn't one.
        if !is_hypervisor_present() {
            println!("Skipping terminate_vcpu_after_1000ms because no hypervisor is present");
            return Ok(());
        }

        let sandbox_builder =
            SandboxBuilder::new(GuestBinary::FilePath(simple_guest_as_string()?))?;
        let uninitialized_sandbox = sandbox_builder.build()?;

        let sandbox: MultiUseSandbox = uninitialized_sandbox.evolve(Noop::default())?;

        let mut ctx = sandbox.new_call_context();
        let result = ctx.call("Spin", ReturnType::Void, None);

        assert!(result.is_err());
        match result.unwrap_err() {
            HyperlightError::ExecutionCanceledByHost() => {}
            e => panic!(
                "Expected HyperlightError::ExecutionCanceledByHost() but got {:?}",
                e
            ),
        }
        Ok(())
    }

    // Test that we can terminate a VCPU that has been running the VCPU for too long.
    #[test]
    fn test_terminate_vcpu_spinning_cpu() -> Result<()> {
        terminate_vcpu_after_1000ms()
    }

    // Test that we can terminate a VCPU that has been running the VCPU for too long and then call a guest function on the same host thread.
    #[test]
    fn test_terminate_vcpu_and_then_call_guest_function_on_the_same_host_thread() -> Result<()> {
        terminate_vcpu_after_1000ms()?;
        call_guest_function_by_name_hv()
    }

    // This test is to capture the case where the guest execution is running a host function when cancelled and that host function
    // is never going to return.
    // The host function that is called will end after 5 seconds, but by this time the cancellation will have given up
    // (using default timeout settings)  , so this tests looks for the error "Failed to cancel guest execution".

    #[test]
    fn test_terminate_vcpu_calling_host_spinning_cpu() -> Result<()> {
        // This test relies upon a Hypervisor being present so for now
        // we will skip it if there isn't one.
        if !is_hypervisor_present() {
            println!("Skipping test_call_guest_function_by_name because no hypervisor is present");
            return Ok(());
        }

        let sandbox_builder =
            SandboxBuilder::new(GuestBinary::FilePath(callback_guest_as_string()?))?;
        let mut uninitialized_sandbox = sandbox_builder.build()?;

        // Make this host call run for 5 seconds

        fn spin() -> Result<()> {
            thread::sleep(std::time::Duration::from_secs(5));
            Ok(())
        }

        let host_spin_func = Arc::new(Mutex::new(spin));

        #[cfg(any(target_os = "windows", not(feature = "seccomp")))]
        host_spin_func
            .register(&mut uninitialized_sandbox, "Spin")
            .unwrap();

        #[cfg(all(target_os = "linux", feature = "seccomp"))]
        host_spin_func
            .register_with_extra_allowed_syscalls(
                &mut uninitialized_sandbox,
                "Spin",
                vec![libc::SYS_clock_nanosleep],
            )
            .unwrap();

        let sandbox: MultiUseSandbox = uninitialized_sandbox.evolve(Noop::default())?;
        let mut ctx = sandbox.new_call_context();
        let result = ctx.call("CallHostSpin", ReturnType::Void, None);

        assert!(result.is_err());
        match result.unwrap_err() {
            HyperlightError::GuestExecutionHungOnHostFunctionCall() => {}
            e => panic!(
                "Expected HyperlightError::GuestExecutionHungOnHostFunctionCall but got {:?}",
                e
            ),
        }

        Ok(())
    }

    #[test]
    #[cfg(not(inprocess))]
    fn test_trigger_exception_on_guest() -> Result<()> {
        let sandbox_builder =
            SandboxBuilder::new(GuestBinary::FilePath(simple_guest_as_string()?))?;
        let uninitialized_sandbox = sandbox_builder.build()?;

        let mut multi_use_sandbox: MultiUseSandbox =
            uninitialized_sandbox.evolve(Noop::default())?;

        let res = multi_use_sandbox.call_guest_function_by_name(
            "TriggerException",
            ReturnType::Void,
            None,
        );

        assert!(res.is_err());

        match res.unwrap_err() {
            HyperlightError::GuestAborted(_, msg) => {
                // msg should indicate we got an invalid opcode exception
                assert!(msg.contains("EXCEPTION: 0x6"));
            }
            e => panic!(
                "Expected HyperlightError::GuestExecutionError but got {:?}",
                e
            ),
        }

        Ok(())
    }
}
