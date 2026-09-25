// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::*;
