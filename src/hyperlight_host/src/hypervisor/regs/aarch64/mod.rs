// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

// TODO(aarch64): implement real register definitions

mod common_regs;
pub(crate) use common_regs::*;

mod special_regs;
pub(crate) use special_regs::*;

mod common_fpu;
pub(crate) use common_fpu::*;

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonDebugRegs {
    _placeholder: u64,
}

#[cfg(kvm)]
pub(crate) mod kvm_reg;
