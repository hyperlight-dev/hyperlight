// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_os = "windows")]
use std::collections::HashSet;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::*;

#[cfg(target_os = "windows")]
#[derive(Debug, PartialEq)]
pub(crate) enum FromWhpRegisterError {
    MissingRegister(HashSet<i32>),
    InvalidLength(usize),
    InvalidEncoding,
    DuplicateRegister(i32),
    InvalidRegister(i32),
}
