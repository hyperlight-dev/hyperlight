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

// For more information on seccomp and its implementation in Hyperlight,
// refer to: https://github.com/hyperlight-dev/hyperlight/blob/dev/docs/seccomp.md

/// This module defines all seccomp filters (i.e., used for blockage of non-specified syscalls)
/// needed for execution of guest code within Hyperlight through a syscalls allow-list.
pub(crate) mod guest;

// The credit on the creation of the macros below goes to the cloud-hypervisor team
// (https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/vmm/src/seccomp_filters.rs)

/// Shorthand for chaining `SeccompCondition`s with the `and` operator  in a `SeccompRule`.
/// The rule will take the `Allow` action if _all_ the conditions are true.
#[macro_export]
macro_rules! and {
    ($($x:expr),*) => (SeccompRule::new(vec![$($x),*]).unwrap())
}

/// Shorthand for chaining `SeccompRule`s with the `or` operator in a `SeccompFilter`.
#[macro_export]
macro_rules! or {
    ($($x:expr,)*) => (vec![$($x),*]);
    ($($x:expr),*) => (vec![$($x),*])
}
