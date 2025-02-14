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
use crate::hypervisor::hypervisor_handler::HypervisorHandlerAction;
use crate::sandbox::WrapperGetter;
use crate::HyperlightError::GuestExecutionHungOnHostFunctionCall;
use crate::{HyperlightError, Result};

/// Call a guest function by name, using the given `wrapper_getter`.
#[instrument(
    err(Debug),
    skip(wrapper_getter, args),
    parent = Span::current(),
    level = "Trace"
)]
pub(crate) fn call_function_on_guest<WrapperGetterT: WrapperGetter>(
    wrapper_getter: &mut WrapperGetterT,
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

    {
        let mem_mgr = wrapper_getter.get_mgr_wrapper_mut();
        mem_mgr.as_mut().write_guest_function_call(&buffer)?;
    }

    let mut hv_handler = wrapper_getter.get_hv_handler().clone();
    match hv_handler.execute_hypervisor_handler_action(
        HypervisorHandlerAction::DispatchCallFromHost(function_name.to_string()),
    ) {
        Ok(()) => {}
        Err(e) => match e {
            HyperlightError::HypervisorHandlerMessageReceiveTimedout() => {
                timedout = true;
                match hv_handler.terminate_hypervisor_handler_execution_and_reinitialise(
                    wrapper_getter.get_mgr_wrapper_mut().unwrap_mgr_mut(),
                )? {
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

    let mem_mgr = wrapper_getter.get_mgr_wrapper_mut();
    mem_mgr.check_stack_guard()?; // <- wrapper around mem_mgr `check_for_stack_guard`
    check_for_guest_error(mem_mgr)?;

    mem_mgr
        .as_mut()
        .get_guest_function_call_result()
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
    use crate::func::call_ctx::MultiUseGuestCallContext;
    use crate::func::host_functions::HostFunction0;
    use crate::sandbox::is_hypervisor_present;
    use crate::sandbox::uninitialized::GuestBinary;
    use crate::sandbox_state::sandbox::EvolvableSandbox;
    use crate::sandbox_state::transition::Noop;
    use crate::{new_error, HyperlightError, MultiUseSandbox, Result, UninitializedSandbox};

    // simple function
    fn test_function0(_: MultiUseGuestCallContext) -> Result<i32> {
        Ok(42)
    }

    struct GuestStruct;

    // function that return type unsupported by the host
    fn test_function1(_: MultiUseGuestCallContext) -> Result<GuestStruct> {
        Ok(GuestStruct)
    }

    // function that takes a parameter
    fn test_function2(_: MultiUseGuestCallContext, param: i32) -> Result<i32> {
        Ok(param)
    }

    #[test]
    // TODO: Investigate why this test fails with an incorrect error when run alongside other tests
    #[ignore]
    #[cfg(target_os = "linux")]
    fn test_violate_seccomp_filters() -> Result<()> {
        if !is_hypervisor_present() {
            panic!("Panic on create_multi_use_sandbox because no hypervisor is present");
        }

        fn make_get_pid_syscall() -> Result<u64> {
            let pid = unsafe { libc::syscall(libc::SYS_getpid) };
            Ok(pid as u64)
        }

        // First, run  to make sure it fails.
        {
            let make_get_pid_syscall_func = Arc::new(Mutex::new(make_get_pid_syscall));

            let mut usbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
                None,
                None,
            )
            .unwrap();

            make_get_pid_syscall_func.register(&mut usbox, "MakeGetpidSyscall")?;

            let mut sbox: MultiUseSandbox = usbox.evolve(Noop::default())?;

            let res =
                sbox.call_guest_function_by_name("ViolateSeccompFilters", ReturnType::ULong, None);

            #[cfg(feature = "seccomp")]
            match res {
                Ok(_) => panic!("Expected to fail due to seccomp violation"),
                Err(e) => match e {
                    HyperlightError::DisallowedSyscall => {}
                    _ => panic!("Expected DisallowedSyscall error: {}", e),
                },
            }

            #[cfg(not(feature = "seccomp"))]
            match res {
                Ok(_) => (),
                Err(e) => panic!("Expected to succeed without seccomp: {}", e),
            }
        }

        // Second, run with allowing `SYS_getpid`
        #[cfg(feature = "seccomp")]
        {
            let make_get_pid_syscall_func = Arc::new(Mutex::new(make_get_pid_syscall));

            let mut usbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
                None,
                None,
            )
            .unwrap();

            make_get_pid_syscall_func.register_with_extra_allowed_syscalls(
                &mut usbox,
                "MakeGetpidSyscall",
                vec![libc::SYS_getpid],
            )?;
            // ^^^ note, we are allowing SYS_getpid

            let mut sbox: MultiUseSandbox = usbox.evolve(Noop::default())?;

            let res =
                sbox.call_guest_function_by_name("ViolateSeccompFilters", ReturnType::ULong, None);

            match res {
                Ok(_) => {}
                Err(e) => panic!("Expected to succeed due to seccomp violation: {}", e),
            }
        }

        Ok(())
    }

    #[test]
    fn test_execute_in_host() {
        let uninitialized_sandbox = || {
            UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
                None,
                None,
            )
            .unwrap()
        };

        // test_function0
        {
            let usbox = uninitialized_sandbox();
            let sandbox: MultiUseSandbox = usbox
                .evolve(Noop::default())
                .expect("Failed to initialize sandbox");
            let result = test_function0(sandbox.new_call_context());
            assert_eq!(result.unwrap(), 42);
        }

        // test_function1
        {
            let usbox = uninitialized_sandbox();
            let sandbox: MultiUseSandbox = usbox
                .evolve(Noop::default())
                .expect("Failed to initialize sandbox");
            let result = test_function1(sandbox.new_call_context());
            assert!(result.is_ok());
        }

        // test_function2
        {
            let usbox = uninitialized_sandbox();
            let sandbox: MultiUseSandbox = usbox
                .evolve(Noop::default())
                .expect("Failed to initialize sandbox");
            let result = test_function2(sandbox.new_call_context(), 42);
            assert_eq!(result.unwrap(), 42);
        }

        // test concurrent calls with a local closure that returns current count
        {
            let count = Arc::new(Mutex::new(0));
            let order = Arc::new(Mutex::new(vec![]));

            let mut handles = vec![];

            for _ in 0..10 {
                let usbox = uninitialized_sandbox();
                let sandbox: MultiUseSandbox = usbox
                    .evolve(Noop::default())
                    .expect("Failed to initialize sandbox");
                let _ctx = sandbox.new_call_context();
                let count = Arc::clone(&count);
                let order = Arc::clone(&order);
                let handle = thread::spawn(move || {
                    // we're not actually using the context, but we're calling
                    // it here to test the mutual exclusion
                    let mut num = count
                        .try_lock()
                        .map_err(|_| new_error!("Error locking"))
                        .unwrap();
                    *num += 1;
                    order
                        .try_lock()
                        .map_err(|_| new_error!("Error locking"))
                        .unwrap()
                        .push(*num);
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            // Check if the order of operations is sequential
            let order = order
                .try_lock()
                .map_err(|_| new_error!("Error locking"))
                .unwrap();
            for i in 0..10 {
                assert_eq!(order[i], i + 1);
            }
        }

        // TODO: Add tests to ensure State has been reset.
    }

    #[track_caller]
    fn guest_bin() -> GuestBinary {
        GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing"))
    }

    #[track_caller]
    fn test_call_guest_function_by_name(u_sbox: UninitializedSandbox) {
        let mu_sbox: MultiUseSandbox = u_sbox.evolve(Noop::default()).unwrap();

        let msg = "Hello, World!!\n".to_string();
        let len = msg.len() as i32;
        let mut ctx = mu_sbox.new_call_context();
        let result = ctx
            .call(
                "PrintOutput",
                ReturnType::Int,
                Some(vec![ParameterValue::String(msg.clone())]),
            )
            .unwrap();

        assert_eq!(result, ReturnValue::Int(len));
    }

    fn call_guest_function_by_name_hv() {
        // in-hypervisor mode
        let u_sbox = UninitializedSandbox::new(
            guest_bin(),
            // for now, we're using defaults. In the future, we should get
            // variability below
            None,
            // by default, the below represents in-hypervisor mode
            None,
            // just use the built-in host print function
            None,
        )
        .unwrap();
        test_call_guest_function_by_name(u_sbox);
    }

    #[test]
    fn test_call_guest_function_by_name_hv() {
        call_guest_function_by_name_hv();
    }

    #[test]
    #[cfg(all(target_os = "windows", inprocess))]
    fn test_call_guest_function_by_name_in_proc_load_lib() {
        use hyperlight_testing::simple_guest_exe_as_string;

        let u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_exe_as_string().expect("Guest Exe Missing")),
            None,
            Some(crate::SandboxRunOptions::RunInProcess(true)),
            None,
        )
        .unwrap();
        test_call_guest_function_by_name(u_sbox);
    }

    #[test]
    #[cfg(inprocess)]
    fn test_call_guest_function_by_name_in_proc_manual() {
        let u_sbox = UninitializedSandbox::new(
            guest_bin(),
            None,
            Some(crate::SandboxRunOptions::RunInProcess(false)),
            None,
        )
        .unwrap();
        test_call_guest_function_by_name(u_sbox);
    }

    fn terminate_vcpu_after_1000ms() -> Result<()> {
        // This test relies upon a Hypervisor being present so for now
        // we will skip it if there isn't one.
        if !is_hypervisor_present() {
            println!("Skipping terminate_vcpu_after_1000ms because no hypervisor is present");
            return Ok(());
        }
        let usbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
            None,
            None,
        )?;
        let sandbox: MultiUseSandbox = usbox.evolve(Noop::default())?;
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
        terminate_vcpu_after_1000ms()?;
        Ok(())
    }

    // Test that we can terminate a VCPU that has been running the VCPU for too long and then call a guest function on the same host thread.
    #[test]
    fn test_terminate_vcpu_and_then_call_guest_function_on_the_same_host_thread() -> Result<()> {
        terminate_vcpu_after_1000ms()?;
        call_guest_function_by_name_hv();
        Ok(())
    }

    // This test is to capture the case where the guest execution is running a host function when cancelled and that host function
    // is never going to return.
    // The host function that is called will end after 5 seconds, but by this time the cancellation will have given up
    // (using default timeout settings)  , so this tests looks for the error "Failed to cancel guest execution".

    #[test]
    fn test_terminate_vcpu_calling_host_spinning_cpu() {
        // This test relies upon a Hypervisor being present so for now
        // we will skip it if there isn't one.
        if !is_hypervisor_present() {
            println!("Skipping test_call_guest_function_by_name because no hypervisor is present");
            return;
        }
        let mut usbox = UninitializedSandbox::new(
            GuestBinary::FilePath(callback_guest_as_string().expect("Guest Binary Missing")),
            None,
            None,
            None,
        )
        .unwrap();

        // Make this host call run for 5 seconds

        fn spin() -> Result<()> {
            thread::sleep(std::time::Duration::from_secs(5));
            Ok(())
        }

        let host_spin_func = Arc::new(Mutex::new(spin));

        #[cfg(any(target_os = "windows", not(feature = "seccomp")))]
        host_spin_func.register(&mut usbox, "Spin").unwrap();

        #[cfg(all(target_os = "linux", feature = "seccomp"))]
        host_spin_func
            .register_with_extra_allowed_syscalls(
                &mut usbox,
                "Spin",
                vec![libc::SYS_clock_nanosleep],
            )
            .unwrap();

        let sandbox: MultiUseSandbox = usbox.evolve(Noop::default()).unwrap();
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
    }

    #[test]
    #[cfg(not(inprocess))]
    fn test_trigger_exception_on_guest() {
        let usbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
            None,
            None,
        )
        .unwrap();

        let mut multi_use_sandbox: MultiUseSandbox = usbox.evolve(Noop::default()).unwrap();

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
    }
}
