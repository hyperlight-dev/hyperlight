//! Shared operations around resources

// "Needless" lifetimes are useful for clarity
#![allow(clippy::needless_lifetimes)]

use alloc::sync::Arc;

#[cfg(feature = "std")]
extern crate std;
use core::marker::{PhantomData, Send};
use core::ops::Deref;
#[cfg(feature = "std")]
use std::sync::{RwLock, RwLockReadGuard};

#[cfg(not(feature = "std"))]
use spin::{RwLock, RwLockReadGuard};

/// The semantics of component model resources are, pleasingly,
/// roughly compatible with those of Rust. Less pleasingly, it's not
/// terribly easy to show that statically.
///
/// In particular, if the host calls into the guest and gives it a
/// borrow of a resource, reentrant host function calls that use that
/// borrow need to be able to resolve the original reference and use
/// it in an appropriately scoped manner, but it is not simple to do
/// this, because the core Hyperlight machinery doesn't offer an easy
/// way to augment the host's context for the span of time of a guest
/// function call.  This may be worth revisiting at some time, but in
/// the meantime, it's easier to just do it dynamically.
///
/// # Safety
/// Informally: this only creates SharedRead references, so having a
/// bunch of them going at once is fine.  Safe Rust in the host can't
/// use any earlier borrows (potentially invalidating these) until
/// borrow passed into [`ResourceEntry::lend`] has expired.  Because
/// that borrow outlives the [`LentResourceGuard`], it will not expire
/// until that destructor is called. That destructor ensures that (a)
/// there are no outstanding [`BorrowedResourceGuard`]s alive (since
/// they would be holding the read side of the [`RwLock`] if they
/// were), and that (b) the shared flag has been set to false, so
/// [`ResourceEntry::borrow`] will never create another borrow
pub enum ResourceEntry<T> {
    Empty,
    Owned(T),
    Borrowed(Arc<RwLock<bool>>, *const T),
}
unsafe impl<T: Send> Send for ResourceEntry<T> {}

pub struct LentResourceGuard<'a> {
    flag: Arc<RwLock<bool>>,
    already_revoked: bool,
    _phantom: core::marker::PhantomData<&'a mut ()>,
}
impl<'a> LentResourceGuard<'a> {
    pub fn revoke_nonblocking(&mut self) -> bool {
        #[cfg(feature = "std")]
        let Ok(mut flag) = self.flag.try_write() else {
            return false;
        };
        #[cfg(not(feature = "std"))]
        let Some(mut flag) = self.flag.try_write() else {
            return false;
        };
        *flag = false;
        self.already_revoked = true;
        true
    }
}
impl<'a> Drop for LentResourceGuard<'a> {
    fn drop(&mut self) {
        if !self.already_revoked {
            #[allow(unused_mut)] // it isn't actually unused
            let mut guard = self.flag.write();
            #[cfg(feature = "std")]
            // If a mutex that is just protecting us from our own
            // mistakes is poisoned, something is so seriously
            // wrong that dying is a sensible response.
            #[allow(clippy::unwrap_used)]
            {
                *guard.unwrap() = false;
            }
            #[cfg(not(feature = "std"))]
            {
                *guard = false;
            }
        }
    }
}
pub struct BorrowedResourceGuard<'a, T> {
    _flag: Option<RwLockReadGuard<'a, bool>>,
    reference: &'a T,
}
impl<'a, T> Deref for BorrowedResourceGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.reference
    }
}
impl<T> ResourceEntry<T> {
    pub fn give(x: T) -> ResourceEntry<T> {
        ResourceEntry::Owned(x)
    }
    pub fn lend<'a>(x: &'a T) -> (LentResourceGuard<'a>, ResourceEntry<T>) {
        let flag = Arc::new(RwLock::new(true));
        (
            LentResourceGuard {
                flag: flag.clone(),
                already_revoked: false,
                _phantom: PhantomData {},
            },
            ResourceEntry::Borrowed(flag, x as *const T),
        )
    }
    pub fn borrow<'a>(&'a self) -> Option<BorrowedResourceGuard<'a, T>> {
        match self {
            ResourceEntry::Empty => None,
            ResourceEntry::Owned(t) => Some(BorrowedResourceGuard {
                _flag: None,
                reference: t,
            }),
            ResourceEntry::Borrowed(flag, t) => {
                let guard = flag.read();
                // If a mutex that is just protecting us from our own
                // mistakes is poisoned, something is so seriously
                // wrong that dying is a sensible response.
                #[allow(clippy::unwrap_used)]
                let flag = {
                    #[cfg(feature = "std")]
                    {
                        guard.unwrap()
                    }
                    #[cfg(not(feature = "std"))]
                    {
                        guard
                    }
                };
                if *flag {
                    Some(BorrowedResourceGuard {
                        _flag: Some(flag),
                        reference: unsafe { &**t },
                    })
                } else {
                    None
                }
            }
        }
    }
    pub fn take(&mut self) -> Option<T> {
        match core::mem::replace(self, ResourceEntry::Empty) {
            ResourceEntry::Owned(t) => Some(t),
            _ => None,
        }
    }
}
