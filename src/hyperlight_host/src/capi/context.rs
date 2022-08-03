use super::handle::{new_key, Handle, Key};
use super::hdl::Hdl;
use crate::mem::pe::PEInfo;
use crate::sandbox::Sandbox;
use crate::{func::args::Val, mem::config::SandboxMemoryConfiguration};
use crate::{func::def::HostFunc, mem::layout::SandboxMemoryLayout};
use anyhow::{bail, Error, Result};
use chashmap::{CHashMap, ReadGuard, WriteGuard};

/// Context is a memory storage mechanism for the C API functions
/// provided by this crate.
///
/// It is intended to be referred to by `Handle`s, which are passed
/// between C code and Rust implementation herein as the rough equivalent
/// of pointers.
///
/// Using this `Handle` and `Context` scheme to refer to allocated
/// memory provides a somewhat safer, though less efficient, way
/// to refer to memory on the heap than "raw" C pointers do.
#[derive(Default)]
pub struct Context {
    /// All `anyhow::Error`s stored in this context.
    pub errs: CHashMap<Key, Error>,
    /// All `Sandbox`es stored in this context
    pub sandboxes: CHashMap<Key, Sandbox>,
    /// All `Val`s stored in this context
    pub vals: CHashMap<Key, Val>,
    /// All `HostFunc`s stored in this context
    pub host_funcs: CHashMap<Key, HostFunc>,
    /// All `String`s stored in this context
    pub strings: CHashMap<Key, String>,
    /// All `Vec<u8>`s stored in this context
    pub byte_arrays: CHashMap<Key, Vec<u8>>,
    /// All `PEInfo`s stored in this context
    pub pe_infos: CHashMap<Key, PEInfo>,
    /// All `SandboxMemoryConfiguration`s stored in this context
    pub mem_configs: CHashMap<Key, SandboxMemoryConfiguration>,
    /// All `SandboxMemoryLayout`s stored in this context
    pub mem_layouts: CHashMap<Key, SandboxMemoryLayout>,
}

/// A type alias for a `CHashMap` `ReadGuard` type wrapped in a
/// `Result`.
pub type ReadResult<'a, T> = Result<ReadGuard<'a, Key, T>>;
/// A type alias for a `CHashMap` `WriteGuard` type wrapped in a
/// `Result`.
pub type WriteResult<'a, T> = Result<WriteGuard<'a, Key, T>>;

impl Context {
    /// Create a new key and register the given `obj` in the given
    /// collection `coll`.
    ///
    /// The given `FnOnce` called `make_handle` can be used to
    /// create a new `Handle` from the newly created key, and to
    /// verify that the given `obj` is of the correct type.
    pub fn register<T, HandleFn: FnOnce(Key) -> Hdl>(
        obj: T,
        coll: &CHashMap<Key, T>,
        make_handle: HandleFn,
    ) -> Handle {
        let key = new_key();
        let handle = Handle::from(make_handle(key));
        coll.insert(handle.key(), obj);
        handle
    }

    /// A convenience function for `register`, typed specifically
    /// for `Error` types.
    pub fn register_err(&mut self, err: Error) -> Handle {
        Self::register(err, &self.errs, Hdl::Err)
    }

    /// Get a type `T` from the given collection `coll` using
    /// `handle.key()` as the index to `coll`.
    ///
    /// The `chk` function will be called with the `Hdl` created
    /// from the given `handle`, and if it returns `false`, an
    /// `Err` will be returned.
    ///
    /// This function is only suitable for immutable operations on
    /// `coll`. If you intend to mutate `coll`, use `get_mut`.
    pub fn get<T, ChkFn: FnOnce(&Hdl) -> bool>(
        handle: Handle,
        coll: &CHashMap<Key, T>,
        chk: ChkFn,
    ) -> ReadResult<T> {
        let hdl = Hdl::try_from(handle)?;
        if !chk(&hdl) {
            bail!("invalid handle")
        }
        match coll.get(&handle.key()) {
            Some(obj) => Ok(obj),
            None => bail!("object {} not found for key {}", hdl, handle.key()),
        }
    }

    /// Similar to `get`, except returns a `WriteResult` rather than
    /// a `ReadResult`, making this function suitable for mutating
    /// `coll` in a thread-safe manner.
    pub fn get_mut<T, ChkFn: FnOnce(&Hdl) -> bool>(
        handle: Handle,
        coll: &CHashMap<Key, T>,
        chk: ChkFn,
    ) -> WriteResult<T> {
        let hdl = Hdl::try_from(handle)?;
        if !chk(&hdl) {
            bail!("invalid handle")
        }
        match coll.get_mut(&handle.key()) {
            Some(obj) => Ok(obj),
            None => bail!("object {} not found for key {}", hdl, handle.key()),
        }
    }

    /// Convert the given `Handle` parameter to a `Hdl` type (returning
    /// an `Err` if the conversion fails), then call `chk_fn` and
    /// immediately return an `Err` if it returns `false`, and finally
    /// remove that `Hdl`'s key from the collection that corresponds to
    /// it, returning `true` if an element was removed and `false`
    /// otherwise.
    pub fn remove<ChkFn: FnOnce(&Hdl) -> bool>(&mut self, handle: Handle, chk_fn: ChkFn) -> bool {
        match Hdl::try_from(handle) {
            Ok(hdl) => {
                if !chk_fn(&hdl) {
                    return false;
                }
                match hdl {
                    Hdl::Err(key) => self.errs.remove(&key).is_some(),
                    Hdl::Sandbox(key) => self.sandboxes.remove(&key).is_some(),
                    Hdl::Empty() => true,
                    Hdl::Val(key) => self.vals.remove(&key).is_some(),
                    Hdl::HostFunc(key) => self.host_funcs.remove(&key).is_some(),
                    Hdl::String(key) => self.strings.remove(&key).is_some(),
                    Hdl::ByteArray(key) => self.byte_arrays.remove(&key).is_some(),
                    Hdl::PEInfo(key) => self.pe_infos.remove(&key).is_some(),
                    Hdl::MemConfig(key) => self.mem_configs.remove(&key).is_some(),
                    Hdl::MemLayout(key) => self.mem_layouts.remove(&key).is_some(),
                }
            }
            Err(_) => false,
        }
    }
}

/// Create a new context for use in the C API.
#[no_mangle]
pub extern "C" fn context_new() -> *mut Context {
    Box::into_raw(Box::new(Context::default()))
}

/// Free the memory referenced by with `ctx`.
///
/// # Safety
///
/// You must only call this function:
///
/// - Exactly once per `ctx` parameter
/// - Only after a given `ctx` is done being used
/// - With `Context`s created by `context_new`
#[no_mangle]
pub unsafe extern "C" fn context_free(ctx: *mut Context) {
    Box::from_raw(ctx);
}

#[cfg(test)]
mod tests {
    use super::Context;
    use crate::capi::byte_array::get_byte_array_mut;
    use crate::capi::hdl::Hdl;
    use crate::capi::strings::get_string;
    use crate::capi::val_ref::get_val;
    use crate::func::args::Val;
    use crate::func::SerializationType;
    use anyhow::Result;

    #[test]
    fn round_trip_string() -> Result<()> {
        let ctx = Context::default();
        let start = "hello".to_string();
        let hdl_res = Context::register(start, &ctx.strings, Hdl::String);
        Context::get(hdl_res, &ctx.strings, |s| matches!(s, Hdl::String(_)))?;
        Ok(())
    }

    #[test]
    fn round_trip_val() -> Result<()> {
        let ctx = Context::default();
        let start = Val::new(Vec::new(), SerializationType::Raw);
        let start_clone = start.clone();
        let hdl_res = Context::register(start, &ctx.vals, Hdl::Val);
        get_val(&ctx, hdl_res).map(|f| assert_eq!(*f, start_clone))
    }

    #[test]
    fn round_trip_byte_array() -> Result<()> {
        let ctx = Context::default();
        let start = vec![1, 2, 3, 4, 5];
        let start_clone = start.clone();
        let hdl_res = Context::register(start, &ctx.byte_arrays, Hdl::ByteArray);
        get_byte_array_mut(&ctx, hdl_res).map(|b| assert_eq!(**b, start_clone))
    }

    #[test]
    fn remove_handle() -> Result<()> {
        let mut ctx = Context::default();
        let hdl = Context::register("hello".to_string(), &ctx.strings, Hdl::String);
        ctx.remove(hdl, |h| matches!(h, Hdl::String(_)));
        assert!(get_string(&ctx, hdl).is_err());
        Ok(())
    }
}