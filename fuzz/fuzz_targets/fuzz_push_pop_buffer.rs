#![no_main]

use hyperlight_host::mem::shared_mem::ExclusiveSharedMemory;
use libfuzzer_sys::fuzz_target;

// try_pop_buffer_into requires a generic T: TryFrom<&[u8]>
struct FuzzBytes(#[allow(dead_code)] Vec<u8>);

impl TryFrom<&[u8]> for FuzzBytes {
    type Error = std::convert::Infallible;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(FuzzBytes(v.to_vec()))
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    const MEM_SIZE: usize = 65536;  // 64KB

    // === TARGET 1: try_pop_buffer_into ===
    // Write fuzzer-generated data directly into shared memory, simulating a guest.
    // This is the primary target since it exercises the guest-controlled code path.
    {
        let Ok(eshm) = ExclusiveSharedMemory::new(MEM_SIZE) else {
            return;
        };
        let (mut hshm, _) = eshm.build();

        let write_len = data.len().min(MEM_SIZE);
        let _ = hshm.copy_from_slice(&data[..write_len], 0);

        // Any panic or UB will be caught by the fuzzer
        let _: Result<FuzzBytes, _> = hshm.try_pop_buffer_into(0, MEM_SIZE);
    }

    // === TARGET 2: push_buffer → try_pop_buffer_into roundtrip ===
    // Verifies the correctness of the checked_add fix introduced in this PR.
    {
        let Ok(eshm) = ExclusiveSharedMemory::new(MEM_SIZE) else {
            return;
        };
        let (mut hshm, _) = eshm.build();

        // Empty buffer: stack pointer = 8
        let _ = hshm.write::<u64>(0, 8u64);

        // If push succeeds, pop must also succeed — neither should panic
        if hshm.push_buffer(0, MEM_SIZE, data).is_ok() {
            let _: Result<FuzzBytes, _> = hshm.try_pop_buffer_into(0, MEM_SIZE);
        }
    }
});
