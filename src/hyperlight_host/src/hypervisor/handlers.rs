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

use std::sync::{Arc, Mutex};

use crate::Result;

/// The trait representing custom logic to handle the case when
/// a Hypervisor's virtual CPU (vCPU) informs Hyperlight a debug memory access
/// has been requested.
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
pub type DbgMemAccessHandlerWrapper = Arc<Mutex<dyn DbgMemAccessHandlerCaller>>;
