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

use crate::guest_error::set_stack_allocate_error;
use crate::MIN_STACK_ADDRESS;

extern "win64" {
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
    
    cs_ret:
        /* Restore RAX, R11 */
        pop r11
        pop r10
        ret",
    min_stack_addr = sym MIN_STACK_ADDRESS,
    set_error = sym set_stack_allocate_error,
);
