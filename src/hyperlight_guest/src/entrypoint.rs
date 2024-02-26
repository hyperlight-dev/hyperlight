use crate::{
    __security_cookie,
    guest_error::reset_error,
    guest_function_call::dispatch_function,
    guest_functions::finalise_function_table,
    host_function_call::{outb, OutBAction},
    hyperlight_peb::HyperlightPEB,
    HEAP_ALLOCATOR, MIN_STACK_ADDRESS, OS_PAGE_SIZE, OUTB_PTR, OUTB_PTR_WITH_CONTEXT, P_PEB,
    RUNNING_IN_HYPERLIGHT,
};

use core::{ffi::c_void, hint::unreachable_unchecked};

pub fn halt() {
    unsafe {
        if RUNNING_IN_HYPERLIGHT {
            let mut hlt_opcode: u8 = 0xF4;
            let hlt_func: fn() = core::mem::transmute(&hlt_opcode);
            core::ptr::write_volatile(&mut hlt_opcode as *mut u8, 0xF4);
            // ^^^ write_volatile prevents the compiler
            // from optimizing away access to the hlt_opcode.
            hlt_func();
        }
    }
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    abort_with_code(0)
}
#[no_mangle]
pub extern "C" fn abort_with_code(code: i32) -> ! {
    outb(OutBAction::Abort as u16, code as u8);
    unsafe { unreachable_unchecked() }
}

extern "C" {
    fn hyperlight_main();
    fn srand(seed: u32);
}

#[no_mangle]
pub extern "C" fn entrypoint(peb_address: i64, seed: i64, ops: i32) -> i32 {
    unsafe {
        if peb_address == 0 {
            // TODO this should call abort with a code
            return -1;
        }

        // Set up the security cookie using the seed and the value passed in the PEB
        // The security cookie is the first value in the peb struct so its address is the same as the peb address

        __security_cookie = peb_address as u64 ^ seed as u64;

        // for now we will calcualte a seed for srand from the data used for the security cookie but we should pass in a proper seed

        let srand_seed = ((peb_address << 8 ^ seed >> 4) >> 32) as u32;

        // Set the seed for the random number generator
        srand(srand_seed);

        P_PEB = Some(peb_address as *mut HyperlightPEB);

        let peb_ptr = P_PEB.unwrap();

        let heap_start = (*peb_ptr).guestheapData.guestHeapBuffer as usize;
        let heap_size = (*peb_ptr).guestheapData.guestHeapSize as usize;
        HEAP_ALLOCATOR.lock().init(heap_start, heap_size);

        // In C, at this point, we call __security_init_cookie.
        // That's a dependency on MSVC, which we can't utilize here.
        // This is to protect against buffer overflows in C, which
        // are inherently protected in Rust.

        // In C, here, we have a `if (!setjmp(jmpbuf))`, which is used in case an error occurs
        // because longjmp is called, which will cause execution to return to this point to
        // halt the program. In Rust, we don't have or need this sort of error handling as the
        // language relies on specific structures like `Result`, and `?` that allow for
        // propagating up the call stack.

        OS_PAGE_SIZE = ops as u32;

        let outb_ptr: fn(u16, u8) = core::mem::transmute((*peb_ptr).pOutb);
        OUTB_PTR = Some(outb_ptr as fn(u16, u8));

        OUTB_PTR_WITH_CONTEXT = if (*peb_ptr).pOutbContext.is_null() {
            None
        } else {
            let outb_ptr_with_context: fn(*mut c_void, u16, u8) =
                core::mem::transmute((*peb_ptr).pOutb);
            Some(outb_ptr_with_context as fn(*mut c_void, u16, u8))
        };

        if (*peb_ptr).pOutb.is_null() {
            RUNNING_IN_HYPERLIGHT = true;
            // This static is to make it easier to implement the __chksstk function in assembly.
            // It also means that should we change the layout of the struct in the future, we
            // don't have to change the assembly code.
            MIN_STACK_ADDRESS = (*peb_ptr).gueststackData.minStackAddress;
        }

        (*peb_ptr).guest_function_dispatch_ptr = dispatch_function as usize as u64;

        reset_error();

        hyperlight_main();

        finalise_function_table();
    }

    halt();
    0
}
