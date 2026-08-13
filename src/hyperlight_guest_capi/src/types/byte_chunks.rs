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

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::{ptr, slice};

use hyperlight_common::flatbuffer_wrappers::function_types::Bytes;

/// One borrowed byte chunk exposed through the C API.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiByteChunk {
    data: *const u8,
    len: usize,
}

impl FfiByteChunk {
    #[cfg(test)]
    pub(crate) fn data(&self) -> *const u8 {
        self.data
    }

    fn borrowed(value: &Bytes) -> Self {
        Self {
            data: value.as_ptr(),
            len: value.len(),
        }
    }

    fn from_owned_vec(value: Vec<u8>) -> Self {
        let value = value.into_boxed_slice();
        let len = value.len();
        let data = Box::into_raw(value) as *mut u8;
        Self { data, len }
    }

    /// # Safety
    ///
    /// `data` must reference `len` readable bytes when `len` is nonzero.
    unsafe fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            &[]
        } else {
            // SAFETY: required by the caller.
            unsafe { slice::from_raw_parts(self.data, self.len) }
        }
    }

    /// # Safety
    ///
    /// This chunk must have been created by [`Self::from_owned_vec`] and must
    /// not have been consumed before.
    unsafe fn into_owned_bytes(self) -> Bytes {
        let value = ptr::slice_from_raw_parts_mut(self.data.cast_mut(), self.len);
        // SAFETY: required by the caller.
        let value = unsafe { Box::from_raw(value) };
        Bytes::from(value.into_vec())
    }

    /// # Safety
    ///
    /// This chunk must have been created by [`Self::from_owned_vec`] and must
    /// not have been consumed before.
    unsafe fn drop_owned(self) {
        let value = ptr::slice_from_raw_parts_mut(self.data.cast_mut(), self.len);
        // SAFETY: required by the caller.
        drop(unsafe { Box::from_raw(value) });
    }
}

/// A borrowed array of byte chunks exposed through the C API.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiByteChunks {
    chunks: *const FfiByteChunk,
    count: usize,
}

impl FfiByteChunks {
    /// # Safety
    ///
    /// `chunks` must reference `count` live descriptors when `count` is
    /// nonzero. Each descriptor must reference its declared number of bytes.
    pub(crate) unsafe fn copy_to_bytes(self) -> Vec<Bytes> {
        // SAFETY: required by the caller.
        unsafe { self.as_slice() }
            .iter()
            .map(|chunk| {
                // SAFETY: required by the caller.
                Bytes::copy_from_slice(unsafe { chunk.as_slice() })
            })
            .collect()
    }

    /// # Safety
    ///
    /// `chunks` must reference `count` live descriptors when `count` is
    /// nonzero. Each descriptor must reference its declared number of bytes.
    pub(crate) unsafe fn copy_owned(self) -> Self {
        // Copy every input before leaking any allocation into the owned view.
        // SAFETY: required by the caller.
        let chunks = unsafe { self.as_slice() }
            .iter()
            .map(|chunk| {
                // SAFETY: required by the caller.
                unsafe { chunk.as_slice() }.to_vec()
            })
            .collect();
        Self::from_owned_chunks(chunks)
    }

    /// # Safety
    ///
    /// This value must have been created by [`Self::copy_owned`] and must not
    /// have been consumed before.
    pub(crate) unsafe fn into_owned_bytes(self) -> Vec<Bytes> {
        // SAFETY: required by the caller.
        let chunks = unsafe { self.into_owned_descriptors() };
        chunks
            .into_vec()
            .into_iter()
            .map(|chunk| {
                // SAFETY: every descriptor owns an allocation created by
                // `from_owned_chunks`.
                unsafe { chunk.into_owned_bytes() }
            })
            .collect()
    }

    /// # Safety
    ///
    /// This value must have been created by [`Self::copy_owned`] and must not
    /// have been consumed before.
    pub(crate) unsafe fn drop_owned(self) {
        // SAFETY: required by the caller.
        let chunks = unsafe { self.into_owned_descriptors() };
        for chunk in chunks.iter().copied() {
            // SAFETY: every descriptor owns an allocation created by
            // `from_owned_chunks`.
            unsafe { chunk.drop_owned() };
        }
    }

    /// # Safety
    ///
    /// `chunks` must reference `count` live descriptors when `count` is
    /// nonzero.
    pub(crate) unsafe fn as_slice(&self) -> &[FfiByteChunk] {
        if self.count == 0 {
            &[]
        } else {
            // SAFETY: required by the caller.
            unsafe { slice::from_raw_parts(self.chunks, self.count) }
        }
    }

    fn from_owned_chunks(chunks: Vec<Vec<u8>>) -> Self {
        let chunks: Vec<_> = chunks
            .into_iter()
            .map(FfiByteChunk::from_owned_vec)
            .collect();

        let chunks = chunks.into_boxed_slice();
        let count = chunks.len();
        let chunks = Box::into_raw(chunks) as *mut FfiByteChunk;

        Self { chunks, count }
    }

    /// # Safety
    ///
    /// This value must have been created by [`Self::from_owned_chunks`] and
    /// must not have been consumed before.
    unsafe fn into_owned_descriptors(self) -> Box<[FfiByteChunk]> {
        let chunks = ptr::slice_from_raw_parts_mut(self.chunks.cast_mut(), self.count);
        // SAFETY: required by the caller.
        unsafe { Box::from_raw(chunks) }
    }
}

/// Owns the Rust chunks and descriptors behind one borrowed C view.
pub(crate) struct FfiByteChunksOwner {
    _chunks: Vec<Bytes>,
    descriptors: Box<[FfiByteChunk]>,
}

impl FfiByteChunksOwner {
    pub(crate) fn new(chunks: Vec<Bytes>) -> Self {
        let descriptors = chunks
            .iter()
            .map(FfiByteChunk::borrowed)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            _chunks: chunks,
            descriptors,
        }
    }

    pub(crate) fn view(&self) -> FfiByteChunks {
        FfiByteChunks {
            chunks: self.descriptors.as_ptr(),
            count: self.descriptors.len(),
        }
    }
}

/// Keeps a host return alive behind the public view pointer.
#[repr(C)]
pub(crate) struct OwnedFfiByteChunks {
    view: FfiByteChunks,
    _owner: FfiByteChunksOwner,
}

impl OwnedFfiByteChunks {
    pub(crate) fn into_raw(chunks: Vec<Bytes>) -> *mut FfiByteChunks {
        let owner = FfiByteChunksOwner::new(chunks);
        let value = Box::new(Self {
            view: owner.view(),
            _owner: owner,
        });
        Box::into_raw(value).cast()
    }

    /// # Safety
    ///
    /// `value` must be null or a pointer returned by [`Self::into_raw`] that
    /// has not already been freed.
    pub(crate) unsafe fn free(value: *mut FfiByteChunks) {
        if !value.is_null() {
            // SAFETY: `view` is the first field of this `repr(C)` allocation.
            drop(unsafe { Box::from_raw(value.cast::<Self>()) });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_view_preserves_chunks_without_copying() {
        let chunks = vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")];
        let addresses = chunks.iter().map(Bytes::as_ptr).collect::<Vec<_>>();
        let owner = FfiByteChunksOwner::new(chunks);
        let view = owner.view();

        // SAFETY: `owner` keeps the descriptor array and chunks alive.
        let descriptors = unsafe { view.as_slice() };
        assert_eq!(descriptors.len(), 2);
        assert_eq!(descriptors[0].data, addresses[0]);
        assert_eq!(descriptors[1].data, addresses[1]);
    }

    #[test]
    fn owned_view_preserves_chunk_contents() {
        let source = FfiByteChunksOwner::new(vec![
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
        ]);

        // SAFETY: `source` keeps the view live while it is copied.
        let owned = unsafe { source.view().copy_owned() };
        // SAFETY: `owned` has not been consumed since `copy_owned`.
        let chunks = unsafe { owned.into_owned_bytes() };

        assert_eq!(
            chunks,
            vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")]
        );
    }
}
