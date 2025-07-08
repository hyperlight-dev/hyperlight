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

use std::marker::PhantomData;

use super::sandbox::Sandbox;

/// TODO: fix this comment, it is not accurate anymore.
/// 
/// Metadata about an evolution. Any `Sandbox` implementation
/// that also implements `EvolvableSandbox` can decide the following
/// things in a type-safe way:
///
/// 1. That transition is possible
/// 2. That transition requires a specific kind of metadata
///
/// For example, if you have the following structs:
///
/// ```ignore
/// struct MySandbox1 {}
/// struct MySandbox2 {}
///
/// impl Sandbox for MySandbox1 {...}
/// impl Sandbox for MySandbox2 {...}
/// ```
///
/// ...then you can define a metadata-free evolve transition between
/// `MySandbox1` and `MySandbox2` as follows:
///
/// ```ignore
/// impl EvolvableSandbox<
///     MySandbox1,
///     MySandbox2,
///     Noop<MySandbox1, MySandbox2>
/// > for MySandbox1 {
///     fn evolve(
///         self,
///         _: Noop<MySandbox1, MySandbox2>
///     ) -> Result<MySandbox2> {
///         Ok(MySandbox2{})
///     }
/// }
///
/// ```
///
/// Most transitions will likely involve `Noop`, but some may involve
/// implementing their own.
pub trait TransitionMetadata<Cur: Sandbox, Next: Sandbox> {}

/// Transition metadata that contains and does nothing. `Noop` is a
/// placeholder when you want to implement an `EvolvableSandbox`
/// that needs no additional metadata to succeed.
///
/// Construct one of these by using the `default()` method.
pub struct Noop<Cur: Sandbox, Next: Sandbox> {
    cur_ph: PhantomData<Cur>,
    next_ph: PhantomData<Next>,
}

impl<Cur: Sandbox, Next: Sandbox> Default for Noop<Cur, Next> {
    fn default() -> Self {
        Self {
            cur_ph: PhantomData,
            next_ph: PhantomData,
        }
    }
}

impl<Cur: Sandbox, Next: Sandbox> TransitionMetadata<Cur, Next> for Noop<Cur, Next> {}
