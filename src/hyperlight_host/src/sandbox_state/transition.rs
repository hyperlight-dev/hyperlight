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

use tracing::{Span, instrument};

use super::sandbox::Sandbox;
use crate::Result;
use crate::func::call_ctx::MultiUseGuestCallContext;

/// Metadata about an evolution or devolution. Any `Sandbox` implementation
/// that also implements `EvolvableSandbox` or `DevolvableSandbox`
/// can decide the following things in a type-safe way:
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
/// `MySandbox1` and `MySandbox2`, and a devolve transition that requires
/// a callback between `MySandbox2` and `MySandbox` as follows:
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
/// or `DevolvableSandbox` that needs no additional metadata to succeed.
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

/// A `TransitionMetadata` that calls a callback. The callback function takes
/// a mutable reference to a `MultiUseGuestCallContext` and returns a `Result<()>`
/// to signify success or failure of the function.
///
/// The function use the context to call guest functions.
///
/// Construct one of these by passing your callback to
/// `MultiUseContextCallback::from`, as in the following code (assuming `MySandbox`
/// is a `Sandbox` implementation):
///
/// ```ignore
/// let my_cb_fn: dyn FnOnce(&mut MultiUseGuestCallContext) -> Result<()> = |_sbox| {
///     println!("hello world!");
/// };
/// let mutating_cb = MultiUseContextCallback::from(my_cb_fn);
/// ```
pub struct MultiUseContextCallback<'func, Cur: Sandbox, F>
where
    F: FnOnce(&mut MultiUseGuestCallContext) -> Result<()> + 'func,
{
    cur_ph: PhantomData<Cur>,
    fn_life_ph: PhantomData<&'func ()>,
    cb: F,
}

impl<Cur: Sandbox, Next: Sandbox, F> TransitionMetadata<Cur, Next>
    for MultiUseContextCallback<'_, Cur, F>
where
    F: FnOnce(&mut MultiUseGuestCallContext) -> Result<()>,
{
}

impl<Cur: Sandbox, F> MultiUseContextCallback<'_, Cur, F>
where
    F: FnOnce(&mut MultiUseGuestCallContext) -> Result<()>,
{
    /// Invokes the callback on the provided guest context
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn call(self, cur: &mut MultiUseGuestCallContext) -> Result<()> {
        (self.cb)(cur)
    }
}

impl<'a, Cur: Sandbox, F> From<F> for MultiUseContextCallback<'a, Cur, F>
where
    F: FnOnce(&mut MultiUseGuestCallContext) -> Result<()> + 'a,
{
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(val: F) -> Self {
        MultiUseContextCallback {
            cur_ph: PhantomData,
            fn_life_ph: PhantomData,
            cb: val,
        }
    }
}
