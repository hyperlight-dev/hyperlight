// ; source https://raw.githubusercontent.com/koka-lang/libhandler/master/src/asm/setjmp_x64.asm
// ; ----------------------------------------------------------------------------
// ; Copyright (c) 2016, Microsoft Research, Daan Leijen
// ; This is free software; you can redistribute it and/or modify it under the
// ; terms of the Apache License, Version 2.0. A copy of the License can be
// ; found in the file "license.txt" at the root of this distribution.
// ; -----------------------------------------------------------------------------

// ; -------------------------------------------------------
// ; Code for x64 (x86_64) calling convention as used on Windows
// ; see:
// ; - https://en.wikipedia.org/wiki/X86_calling_conventions
// ; - https://msdn.microsoft.com/en-us/library/ms235286.aspx
// ; - http://www.agner.org/optimize/calling_conventions.pdf
// ;

use core::arch::global_asm;
global_asm!(
    "
.global win64_setjmp
win64_setjmp:
    mov     rax, [rsp]
    mov     [rcx+80], rax      

    lea     rax, [rsp+8]  
    mov     [rcx+16], rax

    mov     [rcx+ 0], edx 
    mov     [rcx+ 8], rbx    
    mov     [rcx+24], rbp
    mov     [rcx+32], rsi
    mov     [rcx+40], rdi
    mov     [rcx+48], r12
    mov     [rcx+56], r13
    mov     [rcx+64], r14
    mov     [rcx+72], r15

    stmxcsr [rcx+88] 
    fnstcw  [rcx+92]     

    movdqu  [rcx+96],  xmm6  
    movdqu  [rcx+112], xmm7
    movdqu  [rcx+128], xmm8
    movdqu  [rcx+144], xmm9 
    movdqu  [rcx+160], xmm10
    movdqu  [rcx+176], xmm11
    movdqu  [rcx+192], xmm12
    movdqu  [rcx+208], xmm13
    movdqu  [rcx+224], xmm14
    movdqu  [rcx+240], xmm15

    xor     eax, eax
    ret
    "
);

global_asm!(
    "
.global win64_longjmp
win64_longjmp:
    mov     eax, edx             
    
    mov     rdx,   [rcx+ 0]       
    mov     rbx,   [rcx+ 8]
    mov     rbp,   [rcx+24]
    mov     rsi,   [rcx+32]
    mov     rdi,   [rcx+40]
    mov     r12,   [rcx+48]
    mov     r13,   [rcx+56]
    mov     r14,   [rcx+64]
    mov     r15,   [rcx+72]

    ldmxcsr [rcx+88]              
    fnclex                        
    fldcw   [rcx+92]              

    movdqu  xmm6,  [rcx+96]       
    movdqu  xmm7,  [rcx+112]
    movdqu  xmm8,  [rcx+128]
    movdqu  xmm9,  [rcx+144]
    movdqu  xmm10, [rcx+160]
    movdqu  xmm11, [rcx+176]
    movdqu  xmm12, [rcx+192]
    movdqu  xmm13, [rcx+208]
    movdqu  xmm14, [rcx+224]
    movdqu  xmm15, [rcx+240]
    
    test    eax, eax              
    jnz     ok
    inc     eax
ok:
    mov     rsp, [rcx+16]        
    jmp     qword ptr [rcx+80]    
"
);

/* Adapt the calling convention of the above to the native "C" calling
 * convention. */
unsafe extern "win64" {
    fn win64_setjmp(x: u64) -> u64;
    fn win64_longjmp(x: u64, y: u64) -> !;
}
#[unsafe(no_mangle)]
extern "C" fn setjmp(x: u64) -> u64 {
    unsafe { win64_setjmp(x) }
}
#[unsafe(no_mangle)]
extern "C" fn longjmp(x: u64, y: u64) -> ! {
    unsafe { win64_longjmp(x, y) }
}
