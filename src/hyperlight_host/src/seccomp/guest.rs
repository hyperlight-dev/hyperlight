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

use seccompiler::SeccompCmpOp::Eq;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen as ArgLen, SeccompCondition as Cond, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::sandbox::ExtraAllowedSyscall;
use crate::{Result, and, or};

fn syscalls_allowlist() -> Result<Vec<(i64, Vec<SeccompRule>)>> {
    Ok(vec![
        // SYS_signalstack, SYS_munmap, SYS_rt_sigprocmask, SYS_madvise, and SYS_exit
        // are minimally required syscalls to be able to setup our seccomp filter.
        (libc::SYS_sigaltstack, vec![]),
        (libc::SYS_munmap, vec![]),
        (libc::SYS_rt_sigprocmask, vec![]),
        (libc::SYS_madvise, vec![]),
        (libc::SYS_exit, vec![]),
        // SYS_rt_sigaction, SYS_write, and SYS_rt_sigreturn are required for the
        // signal handler inside the host function worker thread.
        (libc::SYS_rt_sigaction, vec![]),
        (
            libc::SYS_write,
            or![
                and![Cond::new(0, ArgLen::Dword, Eq, 1)?], // stdout
                and![Cond::new(0, ArgLen::Dword, Eq, 2)?], // stderr
            ],
        ),
        (libc::SYS_rt_sigreturn, vec![]),
        // Note: This `ioctl` is used to get information about the terminal.
        // I believe it is used to get terminal information by our default writer function.
        // That said, I am registering it here instead of in the function specifically
        // because we don't currently support registering parameterized syscalls.
        (
            libc::SYS_ioctl,
            or![and![Cond::new(
                1,
                ArgLen::Dword,
                Eq,
                #[cfg(all(
                    target_arch = "x86_64",
                    target_vendor = "unknown",
                    target_os = "linux",
                    target_env = "musl"
                ))]
                libc::TCGETS.try_into()?,
                #[cfg(not(all(
                    target_arch = "x86_64",
                    target_vendor = "unknown",
                    target_os = "linux",
                    target_env = "musl"
                )))]
                libc::TCGETS,
            )?]],
        ),
        // `futex` is needed for some tests that run in parallel (`simple_test_parallel`,
        // and `callback_test_parallel`).
        (libc::SYS_futex, vec![]),
        // `sched_yield` is needed for many synchronization primitives that may be invoked
        // on the host function worker thread
        (libc::SYS_sched_yield, vec![]),
        // `mprotect` is needed by malloc during memory allocation
        (libc::SYS_mprotect, vec![]),
        // `openat` is marked allowed here because it may be called by `libc::free()`
        // since it will try to open /proc/sys/vm/overcommit_memory (https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/malloc-sysdep.h;h=778d8971d53e284397c3a5dcdd923e93be5e4731;hb=HEAD)
        // We have another more restrictive filter for it below so it will return EACCES instead of trap, in which case libc will use the default value
        (libc::SYS_openat, vec![]),
    ])
}

/// Creates two `BpfProgram`s for a `SeccompFilter` over specific syscalls/`SeccompRule`s
/// intended to be applied on host function threads.
///
/// Note: This does not provide coverage over the Hyperlight host, which is why we don't need
/// `SeccompRules` for operations we definitely perform but are outside the handler thread
/// (e.g., `KVM_SET_USER_MEMORY_REGION`, `KVM_GET_API_VERSION`, `KVM_CREATE_VM`,
/// or `KVM_CREATE_VCPU`).
pub(crate) fn get_seccomp_filter_for_host_function_worker_thread(
    extra_allowed_syscalls: Option<&[ExtraAllowedSyscall]>,
) -> Result<Vec<BpfProgram>> {
    let mut allowed_syscalls = syscalls_allowlist()?;

    if let Some(extra_allowed_syscalls) = extra_allowed_syscalls {
        allowed_syscalls.extend(
            extra_allowed_syscalls
                .iter()
                .copied()
                .map(|syscall| (syscall, vec![])),
        );

        // Remove duplicates
        allowed_syscalls.sort_by(|a, b| a.0.cmp(&b.0));
        allowed_syscalls.dedup();
    }

    let arch: TargetArch = std::env::consts::ARCH.try_into()?;

    // Allowlist filter that traps on unknown syscalls
    let allowlist = SeccompFilter::new(
        allowed_syscalls.into_iter().collect(),
        SeccompAction::Trap,
        SeccompAction::Allow,
        arch,
    )?
    .try_into()?;

    // If `openat` is an explicitly allowed syscall, we shouldn't return the filter that forces it to return EACCES.
    if let Some(extra_syscalls) = extra_allowed_syscalls
        && extra_syscalls.contains(&libc::SYS_openat)
    {
        return Ok(vec![allowlist]);
    }

    // Otherwise, we return both filters.

    // Filter that forces `openat` to return EACCES
    let errno_on_openat = SeccompFilter::new(
        [(libc::SYS_openat, vec![])].into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EACCES.try_into()?),
        arch,
    )?
    .try_into()?;

    // Note: the order of the 2 filters are important. If we applied the strict filter first,
    // we wouldn't be allowed to setup the second filter (would be trapped since the syscalls to setup seccomp are not allowed).
    // However, from an seccomp filter perspective, the order of the filters is not important:
    //
    //    If multiple filters exist, they are all executed, in reverse order
    //    of their addition to the filter tree—that is, the most recently
    //    installed filter is executed first.  (Note that all filters will
    //    be called even if one of the earlier filters returns
    //    SECCOMP_RET_KILL.  This is done to simplify the kernel code and to
    //    provide a tiny speed-up in the execution of sets of filters by
    //    avoiding a check for this uncommon case.)  The return value for
    //    the evaluation of a given system call is the first-seen action
    //    value of highest precedence (along with its accompanying data)
    //    returned by execution of all of the filters.
    //
    //  (https://man7.org/linux/man-pages/man2/seccomp.2.html).
    //
    Ok(vec![errno_on_openat, allowlist])
}
