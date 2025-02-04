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

use std::sync::{Arc, Mutex};

use tracing::{instrument, Span};

use crate::{new_error, Result};

/// The trait representing custom logic to handle the case when
/// a Hypervisor's virtual CPU (vCPU) informs Hyperlight the guest
/// has initiated an outb operation.
pub trait OutBHandlerCaller: Sync + Send {
    /// Function that gets called when an outb operation has occurred.
    fn call(&mut self, port: u16, payload: u64) -> Result<()>;
}

/// A convenient type representing a common way `OutBHandler` implementations
/// are passed as parameters to functions
///
/// Note: This needs to be wrapped in a Mutex to be able to grab a mutable
/// reference to the underlying data (i.e., handle_outb in `Sandbox` takes
/// a &mut self).
pub type OutBHandlerWrapper = Arc<Mutex<dyn OutBHandlerCaller>>;

pub(crate) type OutBHandlerFunction = Box<dyn FnMut(u16, u64) -> Result<()> + Send>;

/// A `OutBHandler` implementation using a `OutBHandlerFunction`
///
/// Note: This handler must live no longer than the `Sandbox` to which it belongs
pub(crate) struct OutBHandler(Arc<Mutex<OutBHandlerFunction>>);

impl From<OutBHandlerFunction> for OutBHandler {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(func: OutBHandlerFunction) -> Self {
        Self(Arc::new(Mutex::new(func)))
    }
}

impl OutBHandlerCaller for OutBHandler {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn call(&mut self, port: u16, payload: u64) -> Result<()> {
        let mut func = self
            .0
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        func(port, payload)
    }
}

/// The trait representing custom logic to handle the case when
/// a Hypervisor's virtual CPU (vCPU) informs Hyperlight a memory access
/// outside the designated address space has occurred.
pub trait MemAccessHandlerCaller: Send {
    /// Function that gets called when unexpected memory access has occurred.
    fn call(&mut self) -> Result<()>;
}

/// A convenient type representing a common way `MemAccessHandler` implementations
/// are passed as parameters to functions
///
/// Note: This needs to be wrapped in a Mutex to be able to grab a mutable
/// reference to the underlying data (i.e., handle_mmio_exit in `Sandbox` takes
/// a &mut self).
pub type MemAccessHandlerWrapper = Arc<Mutex<dyn MemAccessHandlerCaller>>;

pub(crate) type MemAccessHandlerFunction = Box<dyn FnMut() -> Result<()> + Send>;

/// A `MemAccessHandler` implementation using `MemAccessHandlerFunction`.
///
/// Note: This handler must live for as long as its Sandbox or for
/// static in the case of its C API usage.
pub(crate) struct MemAccessHandler(Arc<Mutex<MemAccessHandlerFunction>>);

impl From<MemAccessHandlerFunction> for MemAccessHandler {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(func: MemAccessHandlerFunction) -> Self {
        Self(Arc::new(Mutex::new(func)))
    }
}

impl MemAccessHandlerCaller for MemAccessHandler {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn call(&mut self) -> Result<()> {
        let mut func = self
            .0
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        func()
    }
}

/// The trait representing custom logic to handle the case when
/// a Hypervisor's virtual CPU (vCPU) informs Hyperlight a debug memory access
/// has been requested.
#[cfg(gdb)]
pub trait DbgMemAccessHandlerCaller: Send {
    /// Function that gets called when a read is requested.
    fn read(&mut self, addr: usize, data: &mut [u8]) -> Result<()>;

    /// Function that gets called when a write is requested.
    fn write(&mut self, addr: usize, data: &[u8]) -> Result<()>;

    /// Function that gets called for a request to get guest code offset.
    fn get_code_offset(&mut self) -> Result<usize>;
}

/// A convenient type representing an implementer of `DbgMemAccessHandlerCaller`
///
/// Note: This needs to be wrapped in a Mutex to be able to grab a mutable
/// reference to the underlying data
#[cfg(gdb)]
pub type DbgMemAccessHandlerWrapper = Arc<Mutex<dyn DbgMemAccessHandlerCaller>>;
