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

use std::fmt::Debug;

use tracing::{Span, instrument};

/// A struct that stores a `*mut EltT` and allows the creator of the struct
/// to specify the functionality to be run when the struct is dropped.
///
/// This struct is `Send`, but purposely not `Sync` or `Clone`, so you can
/// move these across threads but not duplicate them. Since you can't duplicate
/// them, you don't need to synchronize them across threads (i.e. `lock()`).
///
/// If you do want to duplicate `CustomPtrDrop` instances, and synchronize
/// access to them across threads, put them inside of an
///  `Arc<Mutex<CustomPtrDrop>>`. That configuration is likely the most useful
pub(crate) struct CustomPtrDrop<'a, EltT> {
    t: SendablePtr<EltT>,
    drop: Box<dyn Fn(*mut EltT) + 'a + Send>,
}

impl<'a, EltT> CustomPtrDrop<'a, EltT> {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(elt: *mut EltT, drop_fn: Box<dyn Fn(*mut EltT) + Send>) -> Self {
        Self {
            t: SendablePtr(elt),
            drop: drop_fn,
        }
    }
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn as_mut_ptr(&self) -> *mut EltT {
        self.t.0
    }
}

impl<'a, EltT> Debug for CustomPtrDrop<'a, EltT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomDrop").finish()
    }
}

impl<'a, EltT> Drop for CustomPtrDrop<'a, EltT> {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn drop(&mut self) {
        let drop_fn = &self.drop;
        drop_fn(self.t.0)
    }
}
struct SendablePtr<T>(*mut T);

unsafe impl<T> Send for SendablePtr<T> {}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "windows")]
    use std::sync::{Arc, Mutex};
    #[cfg(target_os = "windows")]
    use std::thread;

    #[cfg(target_os = "windows")]
    use super::CustomPtrDrop;

    /// A test to ensure that CustomDrop cannot be cloned, must be stored
    /// inside an `Arc` to be able to be sent across threads, and must
    /// be stored inside a `Mutex` to be sync-ed across threads.
    ///
    /// Further, ensures that the `drop` function is called when the
    /// `CustomDrop` is dropped.
    #[test]
    #[cfg(target_os = "windows")]
    fn test_custom_drop_multithreaded() {
        let i_ptr = Box::into_raw(Box::new(1));
        let cd_arc = {
            let cd = CustomPtrDrop::new(
                i_ptr,
                Box::new(|ptr| {
                    unsafe {
                        let _ = Box::from_raw(ptr);
                    };
                }),
            );
            Arc::new(Mutex::new(cd))
        };

        let mut join_handles = Vec::new();
        for _ in 0..10 {
            let cd = cd_arc.clone();
            let join_handle = thread::spawn(move || print!("cd: {cd:?}"));
            join_handles.push(join_handle);
        }
        for join_handle in join_handles {
            join_handle.join().unwrap();
        }
    }
}
