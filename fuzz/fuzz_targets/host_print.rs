#![no_main]

use std::sync::{Mutex, OnceLock};

use hyperlight_host::func::{ParameterValue, ReturnType, ReturnValue};
use hyperlight_host::sandbox::uninitialized::GuestBinary;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simple_guest_for_fuzzing_as_string;
use libfuzzer_sys::{fuzz_target, Corpus};

static SANDBOX: OnceLock<Mutex<MultiUseSandbox>> = OnceLock::new();

// This fuzz target is used to test the HostPrint host function. We generate
// an arbitrary ParameterValue::String, which is passed to the guest, which passes
// it without modification to the host function.
// For fuzzing efficiency, we create one Sandbox and reuse it for all fuzzing iterations.
fuzz_target!(
    init: {
        let u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_for_fuzzing_as_string().expect("Guest Binary Missing")),
            None,
            None,
            None,
        )
        .unwrap();

        let mu_sbox: MultiUseSandbox = u_sbox.evolve(Noop::default()).unwrap();
        SANDBOX.set(Mutex::new(mu_sbox)).unwrap();
    },

    |data: ParameterValue| -> Corpus {
        // only interested in String types
        if !matches!(data, ParameterValue::String(_)) {
            return Corpus::Reject;
        }

        let mut sandbox = SANDBOX.get().unwrap().lock().unwrap();
        let res = sandbox.call_guest_function_by_name(
            "PrintOutput",
            ReturnType::Int,
            Some(vec![data.clone()]),
        );
        match res {
            Ok(ReturnValue::Int(len)) => assert!(len >= 0),
            _ => panic!("Unexpected return value: {:?}", res),
        }

        Corpus::Keep
});
