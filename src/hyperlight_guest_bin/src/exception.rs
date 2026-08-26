// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#[cfg(target_arch = "x86_64")]
pub mod arch {
    pub use crate::arch::context::Context;
    pub use crate::arch::exception::handle::HANDLERS;
    pub use crate::arch::machine::ExceptionInfo;
}

#[cfg(target_arch = "aarch64")]
pub mod arch {
    pub use hyperlight_common::arch::exn::Exception;

    pub use crate::arch::exception::handle::{
        ExceptionHandler, register_exception_handler, unregister_exception_handler,
    };
}
