#![no_main]

use std::sync::{Mutex, OnceLock};

use hyperlight_host::{MultiUseSandbox, SandboxBuilder};
use hyperlight_testing::simple_guest_for_fuzzing_as_pathbuf;
use libfuzzer_sys::{Corpus, fuzz_target};

static SANDBOX: OnceLock<Mutex<MultiUseSandbox>> = OnceLock::new();

// This fuzz target is used to test the HostPrint host function. We generate
// an arbitrary ParameterValue::String, which is passed to the guest, which passes
// it without modification to the host function.
// For fuzzing efficiency, we create one Sandbox and reuse it for all fuzzing iterations.
fuzz_target!(
    init: {
        let mu_sbox = SandboxBuilder::from_file(simple_guest_for_fuzzing_as_pathbuf())
            .build()
            .unwrap();
        SANDBOX.set(Mutex::new(mu_sbox)).unwrap();
    },

    |data: String| -> Corpus {
        let mut sandbox = SANDBOX.get().unwrap().lock().unwrap();
        let len: i32 = sandbox.call::<i32>(
            "PrintOutput",
            data,
        )
        .expect("Unexpected return value");
        assert!(len >= 0);

        Corpus::Keep
});
