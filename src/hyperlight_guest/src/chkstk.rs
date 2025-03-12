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

use core::arch::global_asm;
use core::mem::size_of;

use hyperlight_common::mem::RunMode;

use crate::guest_error::{set_invalid_runmode_error, set_stack_allocate_error};
use crate::{MIN_STACK_ADDRESS, RUNNING_MODE};

unsafe extern "win64" {
    fn __chkstk();
    fn __chkstk_in_proc();
}

global_asm!(
    "
    .global __chkstk
    __chkstk:
        /* Save R10, R11 */
        push r10
        push r11

        /* Load run_mode into r10 */
        mov r10, qword ptr [rip+{run_mode}]

        cmp r10, 0
        je handle_none
        cmp r10, 1
        je handle_hypervisor
        cmp r10, 2
        je handle_inproc_windows
        cmp r10, 3
        je handle_inproc_linux
        /* run_mode > 3 (invalid), so treat like handle_none */
        jmp handle_invalid

    handle_hypervisor:
        /* Load the minimum stack address from the PEB */
        mov r11, [rip+{min_stack_addr}]  

        /* Get the current stack pointer */
        lea r10, [rsp+0x18]  

        /* Calculate what the new stack pointer will be */
        sub r10, rax
        
        /* If result is negative, cause StackOverflow */
        js call_set_error
        
        /* Compare the new stack pointer with the minimum stack address */
        cmp r10, r11   
        /* If the new stack pointer is greater or equal to the minimum stack address,  
            then we are good. Otherwise set the error code to 9 (stack overflow) call set_error and halt */
        jae cs_ret

    call_set_error:
        call {set_error}
        hlt
    
    handle_inproc_windows:
        /* Get the current stack pointer */
        lea r10, [rsp + 0x18]

        /* Calculate what the new stack pointer will be */
        sub r10, rax
        cmovb r10, r11
        mov r11, qword ptr gs:[0x0000000000000010]
        cmp r10, r11
        jae cs_ret
        and r10w, 0x0F000
    csip_stackprobe:
        lea r11, [r11 + 0x0FFFFFFFFFFFFF000]
        mov byte ptr [r11], 0
        cmp r10, r11
        jne csip_stackprobe
    cs_ret:
        /* Restore RAX, R11 */
        pop r11
        pop r10
        ret
    handle_inproc_linux:
        /* no-op */
        jmp cs_ret
    handle_none:
        /* no-op. This can entrypoint has a large stack allocation
            before RunMode variable is set */
        jmp cs_ret
    handle_invalid:
        call {invalid_runmode}",
    run_mode = sym RUNNING_MODE,
    min_stack_addr = sym MIN_STACK_ADDRESS,
    set_error = sym set_stack_allocate_error,
    invalid_runmode = sym set_invalid_runmode_error
);

// Assumptions made in implementation above. If these are no longer true, compilation will fail
// and the developer will need to update the assembly code.
const _: () = {
    assert!(size_of::<RunMode>() == size_of::<u64>());
    assert!(RunMode::None as u64 == 0);
    assert!(RunMode::Hypervisor as u64 == 1);
    assert!(RunMode::InProcessWindows as u64 == 2);
    assert!(RunMode::InProcessLinux as u64 == 3);
    assert!(RunMode::Invalid as u64 == 4);
};
