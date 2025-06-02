#![no_main]

use std::sync::{Mutex, OnceLock};

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
        )
        .unwrap();

        let mu_sbox: MultiUseSandbox = u_sbox.evolve(Noop::default()).unwrap();
        SANDBOX.set(Mutex::new(mu_sbox)).unwrap();
    },

    |data: String| -> Corpus {
        let mut sandbox = SANDBOX.get().unwrap().lock().unwrap();
        let len: i32 = sandbox.call_guest_function_by_name::<i32>(
            "PrintOutput",
            data,
        )
        .expect("Unexpected return value");
        assert!(len >= 0);

        Corpus::Keep
});
