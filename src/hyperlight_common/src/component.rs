/*
Copyright 2026 The Hyperlight Authors.

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

//! Support types for the bindings that `host_bindgen!` generates.

use crate::resource::BorrowedResourceGuard;

mod private {
    pub trait Sealed {}
}

/// Whether an instance/resource/etc is being used in a positive or
/// negative position in the top-level component type that governs the
/// interface. That is to say, whether the functions provided by this
/// instance/resource (or exported by this component) are expected to
/// be implemented in the guest and called on the host or vice versa.
///
/// We say that a piece of a top-level component type is in "negative
/// position" if it is on the left hand side of an odd number of
/// arrows, and positive otherwise. With only first-order component
/// types, this distinction collapses to whether it is part of an
/// import (negative) or export (positive), but with higher-order
/// components, this is no longer the case. For example, if a
/// component imports another component which itself imports some
/// functions, those functions are in positive position in the overall
/// type---because they are supplied by the guest when it instantiates
/// the component it imported---even though they are syntactically
/// imports.
pub trait Positivity: private::Sealed {
    type NegativeOfThis: Positivity<NegativeOfThis = Self>;
    /// How a call to one of the interface's functions returns.
    type CallResult<T>;
    /// How a borrowed resource handle reaches the implementation.
    type Borrow<'a, T: 'a>;
}

/// A type is being used in a negative position in the overall type:
/// it is implemented by the host, and the guest calls it.
pub enum Negative {}

/// A type is being used in a positive position in the overall type:
/// it is implemented by the guest, and the host calls it.
pub enum Positive {}

impl private::Sealed for Negative {}
impl private::Sealed for Positive {}

impl Positivity for Negative {
    type NegativeOfThis = Positive;
    /// A host implementation is called directly, so it cannot fail.
    type CallResult<T> = T;
    /// A handle arrives as an index into the resource table, held borrowed
    /// for the duration of the call.
    type Borrow<'a, T: 'a> = BorrowedResourceGuard<'a, T>;
}

impl Positivity for Positive {
    type NegativeOfThis = Negative;
    /// Every call from the host crosses into the VM, where the guest can trap.
    #[cfg(feature = "std")]
    type CallResult<T> = anyhow::Result<T>;
    /// The guest is not permitted to semantically enlarge its
    /// functions to include kinds of failures other than the usual
    /// trap/VM issue
    #[cfg(not(feature = "std"))]
    type CallResult<T> = T;
    /// The host owns the value, so it hands out a plain reference.
    type Borrow<'a, T: 'a> = &'a T;
}
