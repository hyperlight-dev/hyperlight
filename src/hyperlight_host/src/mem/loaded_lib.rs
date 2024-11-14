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

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, Mutex, Weak};

use tracing::{instrument, Span};
use windows::core::PCWSTR;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows_sys::Win32::Foundation::FreeLibrary;

use super::ptr::RawPtr;
use crate::hypervisor::wrappers::HModuleWrapper;
use crate::{log_then_return, Result};

/// A wrapper around a binary loaded with the Windows
/// [`LoadLibraryW`](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/LibraryLoader/fn.LoadLibraryW.html)
/// function.
///
/// This struct ensures that per process, only one binary can be loaded at at one time.
/// This is needed as it's not possible to load different copies of the same binary.
///
/// `LoadedLib` is concurrency safe and the `Drop` implementation
/// automatically unloads the binary with
/// [`FreeLibrary`](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/LibraryLoader/fn.FreeLibrary.html).
///
/// Use the `load` method to create a new instance.
#[derive(Clone)]
pub struct LoadedLib {
    inner: Arc<LoadedLibInner>,
}

static LOADED_LIB: Mutex<Weak<LoadedLibInner>> = Mutex::new(Weak::new());

impl LoadedLib {
    #[instrument(err(Debug), parent = Span::current(), level= "Trace")]
    pub fn load(path: impl AsRef<OsStr> + std::fmt::Debug) -> Result<Self> {
        // There's a potential race condition where the upgrade call runs after the last
        // arc reference is dropped, but before the destructor is executed. This however
        // is ok, as it means that the old library is not going to be used anymore and
        // we can use it instead.
        let mut lock = LOADED_LIB.lock().unwrap();
        if lock.upgrade().is_some() {
            // An owning copy of the loaded library still exists somewhere,
            // we can't load a new library yet
            log_then_return!("LoadedLib: Only one guest binary can be loaded at any single time");
        }
        let inner = Arc::new(LoadedLibInner::load(path)?);
        *lock = Arc::downgrade(&inner);
        Ok(Self { inner })
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn base_addr(&self) -> RawPtr {
        self.inner.base_addr()
    }
}

struct LoadedLibInner {
    handle: HModuleWrapper,
}

impl LoadedLibInner {
    fn load(path: impl AsRef<OsStr>) -> Result<Self> {
        // convert path to a wide string, and append a null terminator
        let path: Vec<u16> = path.as_ref().encode_wide().chain([0]).collect();
        let pcwstr = PCWSTR::from_raw(path.as_ptr());
        let handle = unsafe { LoadLibraryW(pcwstr) }?;

        Ok(Self {
            handle: handle.into(),
        })
    }

    fn base_addr(&self) -> RawPtr {
        RawPtr::from(<HModuleWrapper as Into<HMODULE>>::into(self.handle).0 as u64)
    }
}

impl Drop for LoadedLibInner {
    fn drop(&mut self) {
        unsafe { FreeLibrary(<HModuleWrapper as Into<HMODULE>>::into(self.handle).0) };
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_testing::{rust_guest_as_pathbuf, simple_guest_exe_as_string};
    use serial_test::serial;

    use super::LoadedLib;

    /// universal test for all LoadedLib-related functionality. It's necessary
    /// to put everything into a single test because LoadedLib relies on global
    /// state.
    #[test]
    #[serial]
    fn test_universal() {
        // test basic load/unload functionality
        {
            // a test to just ensure we can load and unload (when dropped)
            // a library using LoadLibraryA and FreeLibrary, respectively
            let path = simple_guest_exe_as_string().unwrap();
            let lib = LoadedLib::load(path).unwrap();
            drop(lib);
        }
        // test the locking mechanism allowing only one loaded library
        {
            let path = simple_guest_exe_as_string().unwrap();
            let lib1 = LoadedLib::load(&path);
            assert!(lib1.is_ok());
            let lib2 = LoadedLib::load(&path);
            assert!(lib2.is_err());
            drop(lib1);
            let lib3 = LoadedLib::load(&path);
            assert!(lib3.is_ok());
        }
        // test actually loading a library from a real compiled
        // binary
        {
            let lib_name = rust_guest_as_pathbuf("simpleguest.exe");
            let lib = LoadedLib::load(lib_name).unwrap();
            for _ in 0..9 {
                let l = lib.clone();
                assert_eq!(lib.base_addr(), l.base_addr());
            }
        }
    }
}
