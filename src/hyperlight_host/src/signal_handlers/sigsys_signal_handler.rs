/*
Copyright 2025  The Hyperlight Authors.

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

#[cfg(feature = "seccomp")]
pub(super) extern "C" fn handle_sigsys(
    signal: i32,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            // si_code contains the reason for the SIGSYS signal.
            // SYS_SECCOMP is 1 as per:
            // https://github.com/torvalds/linux/blob/81983758430957d9a5cb3333fe324fd70cf63e7e/include/uapi/asm-generic/siginfo.h#L301C9-L301C21
            const SYS_SECCOMP: libc::c_int = 1;
            // Sanity checks to make sure SIGSYS was triggered by a BPF filter.
            // If something else triggered a SIGSYS (i.e., kill()), we do nothing.
            // Inspired by Chromium's sandbox:
            // https://chromium.googlesource.com/chromium/chromium/+/master/sandbox/linux/seccomp-bpf/sandbox_bpf.cc#572
            if signal != libc::SIGSYS
                || (*info).si_code != SYS_SECCOMP
                || context.is_null()
                || (*info).si_errno < 0
            {
                let err_msg =
                    b"[ERROR][HYPERLIGHT] SIGSYS triggered by something other than a BPF filter\n";
                libc::write(
                    libc::STDERR_FILENO,
                    err_msg.as_ptr() as *const _,
                    err_msg.len(),
                );
                return;
            }

            let err_msg = b"[ERROR][HYPERLIGHT] Handling disallowed syscall\n";
            libc::write(
                libc::STDERR_FILENO,
                err_msg.as_ptr() as *const _,
                err_msg.len(),
            );

            // We get the syscall number by accessing a particular offset in the `siginfo_t` struct.
            // This only works because this is handling a SIGSYS signal (i.e., the `siginfo_t` struct
            // is implemented as a union in the kernel:
            // https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/siginfo.h).
            // Note: This is not necessarily platform-agnostic, so we might want to be more careful here
            // in the future.
            const SI_OFF_SYSCALL: isize = 6;
            let syscall = *(info as *const i32).offset(SI_OFF_SYSCALL) as usize;
            let syscall_bytes = raw_format(b"[ERROR][HYPERLIGHT] Disallowed Syscall: ", syscall);

            // `write` as per https://man7.org/linux/man-pages/man7/signal-safety.7.html
            // is async-signal-safe.
            libc::write(
                libc::STDERR_FILENO,
                syscall_bytes.as_ptr() as *const _,
                syscall_bytes.len(),
            );

            // Note: This is not necessarily platform-agnostic, so we might want to be more careful here
            // in the future.
            let ucontext = context as *mut libc::ucontext_t;
            let mcontext = &mut (*ucontext).uc_mcontext;

            if syscall == libc::SYS_ioctl as usize {
                let ioctl_param = mcontext.gregs[libc::REG_EBRACE as usize] as usize;
                let ioctl_param_bytes =
                    raw_format(b"[ERROR][HYPERLIGHT] IOCTL Param: ", ioctl_param);
                libc::write(
                    libc::STDERR_FILENO,
                    ioctl_param_bytes.as_ptr() as *const _,
                    ioctl_param_bytes.len(),
                );
            }

            // We don't want to return execution to the offending host function, so
            // we alter the RIP register to point to a function that will panic out of
            // the host function call.
            mcontext.gregs[libc::REG_RIP as usize] =
                after_syscall_violation as usize as libc::greg_t;
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        compile_error!("Unsupported architecture for seccomp feature");
    }
}

extern "C-unwind" fn after_syscall_violation() {
    #[allow(clippy::panic)]
    std::panic::panic_any(crate::HyperlightError::DisallowedSyscall);
}

fn raw_format(prefix: &[u8], raw: usize) -> [u8; 64] {
    const PREFIX_BUF_LEN: usize = 64;
    const DIGITS_BUF_LEN: usize = 20;

    let mut buffer = [0u8; PREFIX_BUF_LEN];
    let mut i = prefix.len();

    // Copy the prefix message into the buffer.
    buffer[..i].copy_from_slice(prefix);

    // Format the number at the end of the buffer.
    let mut num = raw;
    let mut digits = [0u8; DIGITS_BUF_LEN];
    let mut j = 19;
    if num == 0 {
        digits[j] = b'0';
        j -= 1;
    } else {
        while num > 0 {
            digits[j] = b'0' + (num % 10) as u8;
            num /= 10;
            j -= 1;
        }
    }

    // Copy the number digits to the buffer after the prefix.
    let num_len = 19 - j;
    buffer[i..i + num_len].copy_from_slice(&digits[j + 1..20]);
    i += num_len;

    // Add a newline at the end.
    buffer[i] = b'\n';

    buffer
}
