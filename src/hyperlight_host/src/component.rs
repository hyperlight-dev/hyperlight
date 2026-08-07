/*
Copyright 2025 The Hyperlight Authors.

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

use hyperlight_common::resource::BorrowedResourceGuard;

mod private {
    pub trait Sealed {}
}

/// Whether a component imports or exports an interface, and so which way
/// calls to it cross the VM boundary.
///
/// A wit interface can appear as both an import and an export of one world,
/// so a single generated trait has to serve both. Instance and resource
/// traits take a trailing parameter of this trait, and each use site picks
/// the marker.
///
/// Sealed: [`Imported`] and [`Exported`] are the only directions.
pub trait InterfaceDirection: private::Sealed {
    /// How a call to one of the interface's functions returns.
    type CallResult<T>;
    /// How a borrowed resource handle reaches the implementation.
    type Borrow<'a, T: 'a>;
}

/// The component imports the interface, so calls run guest to host and the
/// host implements it.
pub struct Imported;

/// The component exports the interface, so calls run host to guest and the
/// guest implements it.
pub struct Exported;

impl private::Sealed for Imported {}
impl private::Sealed for Exported {}

impl InterfaceDirection for Imported {
    /// A host implementation is called directly, so it cannot fail.
    type CallResult<T> = T;
    /// A handle arrives as an index into the resource table, held borrowed
    /// for the duration of the call.
    type Borrow<'a, T: 'a> = BorrowedResourceGuard<'a, T>;
}

impl InterfaceDirection for Exported {
    /// Every call crosses into the VM, where the guest can trap.
    type CallResult<T> = crate::Result<T>;
    /// The host owns the value, so it hands out a plain reference.
    type Borrow<'a, T: 'a> = &'a T;
}
