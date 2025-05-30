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

use seccompiler::SeccompCmpOp::Eq;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen as ArgLen, SeccompCondition as Cond, SeccompFilter,
    SeccompRule,
};

use crate::sandbox::ExtraAllowedSyscall;
use crate::{and, or, Result};

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
            or![and![Cond::new(1, ArgLen::Dword, Eq, libc::TCGETS)?]],
        ),
        // `futex` is needed for some tests that run in parallel (`simple_test_parallel`,
        // and `callback_test_parallel`).
        (libc::SYS_futex, vec![]),
        // `sched_yield` is needed for many synchronization primitives that may be invoked
        // on the host function worker thread
        (libc::SYS_sched_yield, vec![]),
    ])
}

/// Creates a `BpfProgram` for a `SeccompFilter` over specific syscalls/`SeccompRule`s
/// intended to be applied in the Hypervisor Handler thread - i.e., over untrusted guest code
/// execution.
///
/// Note: This does not provide coverage over the Hyperlight host, which is why we don't need
/// `SeccompRules` for operations we definitely perform but are outside the handler thread
/// (e.g., `KVM_SET_USER_MEMORY_REGION`, `KVM_GET_API_VERSION`, `KVM_CREATE_VM`,
/// or `KVM_CREATE_VCPU`).
pub(crate) fn get_seccomp_filter_for_host_function_worker_thread(
    extra_allowed_syscalls: Option<&[ExtraAllowedSyscall]>,
) -> Result<BpfProgram> {
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

    Ok(SeccompFilter::new(
        allowed_syscalls.into_iter().collect(),
        SeccompAction::Trap,  // non-match syscall will kill the offending thread
        SeccompAction::Allow, // match syscall will be allowed
        std::env::consts::ARCH.try_into()?,
    )
    .and_then(|filter| filter.try_into())?)
}
