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

use std::any::type_name;
use std::ffi::c_void;
use std::io::Error;
#[cfg(target_os = "linux")]
use std::ptr::null_mut;
use std::sync::{Arc, RwLock};

use hyperlight_common::mem::PAGE_SIZE_USIZE;
use tracing::{instrument, Span};
#[cfg(target_os = "windows")]
use windows::core::PCSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(all(target_os = "windows", inprocess))]
use windows::Win32::System::Memory::FILE_MAP_EXECUTE;
#[cfg(all(target_os = "windows", not(inprocess)))]
use windows::Win32::System::Memory::PAGE_READWRITE;
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{
    CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, VirtualProtect, FILE_MAP_ALL_ACCESS,
    MEMORY_MAPPED_VIEW_ADDRESS, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
};

#[cfg(target_os = "windows")]
use crate::HyperlightError::MemoryAllocationFailed;
#[cfg(target_os = "windows")]
use crate::HyperlightError::{MemoryRequestTooBig, WindowsAPIError};
use crate::{log_then_return, new_error, Result};

/// Makes sure that the given `offset` and `size` are within the bounds of the memory with size `mem_size`.
macro_rules! bounds_check {
    ($offset:expr, $size:expr, $mem_size:expr) => {
        if $offset + $size > $mem_size {
            return Err(new_error!(
                "Cannot read value from offset {} with size {} in memory of size {}",
                $offset,
                $size,
                $mem_size
            ));
        }
    };
}

/// generates a reader function for the given type
macro_rules! generate_reader {
    ($fname:ident, $ty:ty) => {
        /// Read a value of type `$ty` from the memory at the given offset.
        #[allow(dead_code)]
        #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
        pub(crate) fn $fname(&self, offset: usize) -> Result<$ty> {
            let data = self.as_slice();
            bounds_check!(offset, std::mem::size_of::<$ty>(), data.len());
            Ok(<$ty>::from_le_bytes(
                data[offset..offset + std::mem::size_of::<$ty>()].try_into()?,
            ))
        }
    };
}

/// generates a writer function for the given type
macro_rules! generate_writer {
    ($fname:ident, $ty:ty) => {
        /// Write a value of type `$ty` to the memory at the given offset.
        #[allow(dead_code)]
        #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
        pub(crate) fn $fname(&mut self, offset: usize, value: $ty) -> Result<()> {
            let data = self.as_mut_slice();
            bounds_check!(offset, std::mem::size_of::<$ty>(), data.len());
            data[offset..offset + std::mem::size_of::<$ty>()].copy_from_slice(&value.to_le_bytes());
            Ok(())
        }
    };
}

/// A representation of a host mapping of a shared memory region,
/// which will be released when this structure is Drop'd. This is not
/// individually Clone (since it holds ownership of the mapping), or
/// Send or Sync, since it doesn't ensure any particular synchronization.
#[derive(Debug)]
pub struct HostMapping {
    ptr: *mut u8,
    size: usize,
    #[cfg(target_os = "windows")]
    handle: HANDLE,
}

impl Drop for HostMapping {
    #[cfg(target_os = "linux")]
    fn drop(&mut self) {
        use libc::munmap;

        unsafe {
            munmap(self.ptr as *mut c_void, self.size);
        }
    }
    #[cfg(target_os = "windows")]
    fn drop(&mut self) {
        let mem_mapped_address = MEMORY_MAPPED_VIEW_ADDRESS {
            Value: self.ptr as *mut c_void,
        };
        if let Err(e) = unsafe { UnmapViewOfFile(mem_mapped_address) } {
            tracing::error!(
                "Failed to drop HostMapping (UnmapViewOfFile failed): {:?}",
                e
            );
        }

        let file_handle: HANDLE = self.handle;
        if let Err(e) = unsafe { CloseHandle(file_handle) } {
            tracing::error!("Failed to  drop HostMapping (CloseHandle failed): {:?}", e);
        }
    }
}

/// These three structures represent various phases of the lifecycle of
/// a memory buffer that is shared with the guest. An
/// ExclusiveSharedMemory is used for certain operations that
/// unrestrictedly write to the shared memory, including setting it up
/// and taking snapshots.
#[derive(Debug)]
pub struct ExclusiveSharedMemory {
    region: Arc<HostMapping>,
}
unsafe impl Send for ExclusiveSharedMemory {}

/// A GuestSharedMemory is used by the hypervisor handler to represent
/// the reference to all-of-memory that is taken by the virtual cpu.
/// Because of the memory model limitations that affect
/// HostSharedMemory, it is likely fairly important (to ensure that
/// our UB remains limited to interaction with an external compilation
/// unit that likely can't be discovered by the compiler) that _rust_
/// users do not perform racy accesses to the guest communication
/// buffers that are also accessed by HostSharedMemory.
#[derive(Debug)]
pub struct GuestSharedMemory {
    region: Arc<HostMapping>,
    /// The lock that indicates this shared memory is being used by non-Rust code
    ///
    /// This lock _must_ be held whenever the guest is executing,
    /// because it prevents the host from converting its
    /// HostSharedMemory to an ExclusiveSharedMemory. Since the guest
    /// may arbitrarily mutate the shared memory, only synchronized
    /// accesses from Rust should be allowed!
    ///
    /// We cannot enforce this in the type system, because the memory
    /// is mapped in to the VM at VM creation time.
    pub lock: Arc<RwLock<()>>,
}
unsafe impl Send for GuestSharedMemory {}

/// A HostSharedMemory allows synchronized accesses to guest
/// communication buffers, allowing it to be used concurrently with a
/// GuestSharedMemory.
///
/// Given future requirements for asynchronous I/O with a minimum
/// amount of copying (e.g. WASIp3 streams), we would like it to be
/// possible to safely access these buffers concurrently with the
/// guest, ensuring that (1) data is read appropriately if the guest
/// is well-behaved; and (2) the host's behaviour is defined
/// regardless of whether or not the guest is well-behaved.
///
/// The ideal (future) flow for a guest->host message is something like
///   - Guest writes (unordered) bytes describing a work item into a buffer
///   - Guest reveals buffer via a release-store of a pointer into an
///     MMIO ring-buffer
///   - Host acquire-loads the buffer pointer from the "MMIO" ring
///     buffer
///   - Host (unordered) reads the bytes from the buffer
///   - Host performs validation of those bytes and uses them
///
/// Unfortunately, there appears to be no way to do this with defined
/// behaviour in present Rust (see
/// e.g. https://github.com/rust-lang/unsafe-code-guidelines/issues/152).
/// Rust does not yet have its own defined memory model, but in the
/// interim, it is widely treated as inheriting the current C/C++
/// memory models.  The most immediate problem is that regardless of
/// anything else, under those memory models [1, p. 17-18; 2, p. 88],
///
///   > The execution of a program contains a _data race_ if it
///   > contains two [C++23: "potentially concurrent"] conflicting
///   > actions [C23: "in different threads"], at least one of which
///   > is not atomic, and neither happens before the other [C++23: ",
///   > except for the special case for signal handlers described
///   > below"].  Any such data race results in undefined behavior.
///
/// Consequently, if a misbehaving guest fails to correctly
/// synchronize its stores with the host, the host's innocent loads
/// will trigger undefined behaviour for the entire program, including
/// the host.  Note that this also applies if the guest makes an
/// unsynchronized read of a location that the host is writing!
///
/// Despite Rust's de jure inheritance of the C memory model at the
/// present time, the compiler in many cases de facto adheres to LLVM
/// semantics, so it is worthwhile to consider what LLVM does in this
/// case as well.  According to the the LangRef [3] memory model,
/// loads which are involved in a race that includes at least one
/// non-atomic access (whether the load or a store) return `undef`,
/// making them roughly equivalent to reading uninitialized
/// memory. While this is much better, it is still bad.
///
/// Considering a different direction, recent C++ papers have seemed
/// to lean towards using `volatile` for similar use cases. For
/// example, in P1152R0 [4], JF Bastien notes that
///
///   > We’ve shown that volatile is purposely defined to denote
///   > external modifications. This happens for:
///   >   - Shared memory with untrusted code, where volatile is the
///   >     right way to avoid time-of-check time-of-use (ToCToU)
///   >     races which lead to security bugs such as [PWN2OWN] and
///   >     [XENXSA155].
///
/// Unfortunately, although this paper was adopted for C++20 (and,
/// sadly, mostly un-adopted for C++23, although that does not concern
/// us), the paper did not actually redefine volatile accesses or data
/// races to prevent volatile accesses from racing with other accesses
/// and causing undefined behaviour.  P1382R1 [5] would have amendend
/// the wording of the data race definition to specifically exclude
/// volatile, but, unfortunately, despite receiving a
/// generally-positive reception at its first WG21 meeting more than
/// five years ago, it has not progressed.
///
/// Separately from the data race issue, there is also a concern that
/// according to the various memory models in use, there may be ways
/// in which the guest can semantically obtain uninitialized memory
/// and write it into the shared buffer, which may also result in
/// undefined behaviour on reads.  The degree to which this is a
/// concern is unclear, however, since it is unclear to what degree
/// the Rust abstract machine's conception of uninitialized memory
/// applies to the sandbox.  Returning briefly to the LLVM level,
/// rather than the Rust level, this, combined with the fact that
/// racing loads in LLVM return `undef`, as discussed above, we would
/// ideally `llvm.freeze` the result of any load out of the sandbox.
///
/// It would furthermore be ideal if we could run the flatbuffers
/// parsing code directly on the guest memory, in order to avoid
/// unnecessary copies.  That is unfortunately probably not viable at
/// the present time: because the generated flatbuffers parsing code
/// doesn't use atomic or volatile accesses, it is likely to introduce
/// double-read vulnerabilities.
///
/// In short, none of the Rust-level operations available to us do the
/// right thing, at the Rust spec level or the LLVM spec level. Our
/// major remaining options are therefore:
///   - Choose one of the options that is avaiblale to us, and accept
///     that we are doing something unsound according to the spec, but
///     hope that no reasonable compiler could possibly notice.
///   - Use inline assembly per architecture, for which we would only
///     need to worry about the _architecture_'s memory model (which
///     is far less demanding).
///
/// The leading candidate for the first option would seem to be to
/// simply use volatile accesses; there seems to be wide agreement
/// that this _should_ be a valid use case for them (even if it isn't
/// now), and projects like Linux and rust-vmm already use C11
/// `volatile` for this purpose.  It is also worth noting that because
/// we still do need to synchronize with the guest when it _is_ being
/// well-behaved, we would ideally use volatile acquire loads and
/// volatile release stores for interacting with the stack pointer in
/// the guest in this case.  Unfortunately, while those operations are
/// defined in LLVM, they are not presently exposed to Rust. While
/// atomic fences that are not associated with memory accesses
/// (std::sync::atomic::fence) might at first glance seem to help with
/// this problem, they unfortunately do not [6]:
///
///    > A fence ‘A’ which has (at least) Release ordering semantics,
///    > synchronizes with a fence ‘B’ with (at least) Acquire
///    > semantics, if and only if there exist operations X and Y,
///    > both operating on some atomic object ‘M’ such that A is
///    > sequenced before X, Y is sequenced before B and Y observes
///    > the change to M. This provides a happens-before dependence
///    > between A and B.
///
/// Note that the X and Y must be to an _atomic_ object.
///
/// We consequently assume that there has been a strong architectural
/// fence on a vmenter/vmexit between data being read and written.
/// This is unsafe (not guaranteed in the type system)!
///
/// [1] N3047 C23 Working Draft. https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3047.pdf
/// [2] N4950 C++23 Working Draft. https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/n4950.pdf
/// [3] LLVM Language Reference Manual, Memory Model for Concurrent Operations. https://llvm.org/docs/LangRef.html#memmodel
/// [4] P1152R0: Deprecating `volatile`. JF Bastien. https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/p1152r0.html
/// [5] P1382R1: `volatile_load<T>` and `volatile_store<T>`. JF Bastien, Paul McKenney, Jeffrey Yasskin, and the indefatigable TBD. https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p1382r1.pdf
/// [6] Documentation for std::sync::atomic::fence. https://doc.rust-lang.org/std/sync/atomic/fn.fence.html
#[derive(Clone, Debug)]
pub struct HostSharedMemory {
    region: Arc<HostMapping>,
    lock: Arc<RwLock<()>>,
}
unsafe impl Send for HostSharedMemory {}

impl ExclusiveSharedMemory {
    /// Create a new region of shared memory with the given minimum
    /// size in bytes. The region will be surrounded by guard pages.
    ///
    /// Return `Err` if shared memory could not be allocated.
    #[cfg(target_os = "linux")]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn new(min_size_bytes: usize) -> Result<Self> {
        use libc::{
            c_int, mmap, mprotect, off_t, size_t, MAP_ANONYMOUS, MAP_FAILED, MAP_NORESERVE,
            MAP_SHARED, PROT_NONE, PROT_READ, PROT_WRITE,
        };

        use crate::error::HyperlightError::{MemoryRequestTooBig, MmapFailed, MprotectFailed};

        if min_size_bytes == 0 {
            return Err(new_error!("Cannot create shared memory with size 0"));
        }

        let total_size = min_size_bytes
            .checked_add(2 * PAGE_SIZE_USIZE) // guard page around the memory
            .ok_or_else(|| new_error!("Memory required for sandbox exceeded usize::MAX"))?;

        assert!(
            total_size % PAGE_SIZE_USIZE == 0,
            "shared memory must be a multiple of 4096"
        );
        // usize and isize are guaranteed to be the same size, and
        // isize::MAX should be positive, so this cast should be safe.
        if total_size > isize::MAX as usize {
            return Err(MemoryRequestTooBig(total_size, isize::MAX as usize));
        }

        // allocate the memory
        let addr = unsafe {
            mmap(
                null_mut(),
                total_size as size_t,
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_SHARED | MAP_NORESERVE,
                -1 as c_int,
                0 as off_t,
            )
        };
        if addr == MAP_FAILED {
            log_then_return!(MmapFailed(Error::last_os_error().raw_os_error()));
        }

        // protect the guard pages

        let res = unsafe { mprotect(addr, PAGE_SIZE_USIZE, PROT_NONE) };
        if res != 0 {
            return Err(MprotectFailed(Error::last_os_error().raw_os_error()));
        }
        let res = unsafe {
            mprotect(
                (addr as *const u8).add(total_size - PAGE_SIZE_USIZE) as *mut c_void,
                PAGE_SIZE_USIZE,
                PROT_NONE,
            )
        };
        if res != 0 {
            return Err(MprotectFailed(Error::last_os_error().raw_os_error()));
        }

        Ok(Self {
            // HostMapping is only non-Send/Sync because raw pointers
            // are not ("as a lint", as the Rust docs say). We don't
            // want to mark HostMapping Send/Sync immediately, because
            // that could socially imply that it's "safe" to use
            // unsafe accesses from multiple threads at once. Instead, we
            // directly impl Send and Sync on this type. Since this
            // type does have Send and Sync manually impl'd, the Arc
            // is not pointless as the lint suggests.
            #[allow(clippy::arc_with_non_send_sync)]
            region: Arc::new(HostMapping {
                ptr: addr as *mut u8,
                size: total_size,
            }),
        })
    }

    /// Create a new region of shared memory with the given minimum
    /// size in bytes. The region will be surrounded by guard pages.
    ///
    /// Return `Err` if shared memory could not be allocated.
    #[cfg(target_os = "windows")]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn new(min_size_bytes: usize) -> Result<Self> {
        if min_size_bytes == 0 {
            return Err(new_error!("Cannot create shared memory with size 0"));
        }

        let total_size = min_size_bytes
            .checked_add(2 * PAGE_SIZE_USIZE)
            .ok_or_else(|| new_error!("Memory required for sandbox exceeded {}", usize::MAX))?;

        if total_size % PAGE_SIZE_USIZE != 0 {
            return Err(new_error!(
                "shared memory must be a multiple of {}",
                PAGE_SIZE_USIZE
            ));
        }

        // usize and isize are guaranteed to be the same size, and
        // isize::MAX should be positive, so this cast should be safe.
        if total_size > isize::MAX as usize {
            return Err(MemoryRequestTooBig(total_size, isize::MAX as usize));
        }

        let mut dwmaximumsizehigh = 0;
        let mut dwmaximumsizelow = 0;

        if std::mem::size_of::<usize>() == 8 {
            dwmaximumsizehigh = (total_size >> 32) as u32;
            dwmaximumsizelow = (total_size & 0xFFFFFFFF) as u32;
        }

        // Allocate the memory use CreateFileMapping instead of VirtualAlloc
        // This allows us to map the memory into the surrogate process using MapViewOfFile2

        #[cfg(not(inprocess))]
        let flags = PAGE_READWRITE;
        #[cfg(inprocess)]
        let flags = PAGE_EXECUTE_READWRITE;

        let handle = unsafe {
            CreateFileMappingA(
                INVALID_HANDLE_VALUE,
                None,
                flags,
                dwmaximumsizehigh,
                dwmaximumsizelow,
                PCSTR::null(),
            )?
        };

        if handle.is_invalid() {
            log_then_return!(MemoryAllocationFailed(
                Error::last_os_error().raw_os_error()
            ));
        }

        #[cfg(not(inprocess))]
        let file_map = FILE_MAP_ALL_ACCESS;
        #[cfg(inprocess)]
        let file_map = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;

        let addr = unsafe { MapViewOfFile(handle, file_map, 0, 0, 0) };

        if addr.Value.is_null() {
            log_then_return!(MemoryAllocationFailed(
                Error::last_os_error().raw_os_error()
            ));
        }

        // Set the first and last pages to be guard pages

        let mut unused_out_old_prot_flags = PAGE_PROTECTION_FLAGS(0);

        // If the following calls to VirtualProtect are changed make sure to update the calls to VirtualProtectEx in surrogate_process_manager.rs

        let first_guard_page_start = addr.Value;
        if let Err(e) = unsafe {
            VirtualProtect(
                first_guard_page_start,
                PAGE_SIZE_USIZE,
                PAGE_NOACCESS,
                &mut unused_out_old_prot_flags,
            )
        } {
            log_then_return!(WindowsAPIError(e.clone()));
        }

        let last_guard_page_start = unsafe { addr.Value.add(total_size - PAGE_SIZE_USIZE) };
        if let Err(e) = unsafe {
            VirtualProtect(
                last_guard_page_start,
                PAGE_SIZE_USIZE,
                PAGE_NOACCESS,
                &mut unused_out_old_prot_flags,
            )
        } {
            log_then_return!(WindowsAPIError(e.clone()));
        }

        Ok(Self {
            // HostMapping is only non-Send/Sync because raw pointers
            // are not ("as a lint", as the Rust docs say). We don't
            // want to mark HostMapping Send/Sync immediately, because
            // that could socially imply that it's "safe" to use
            // unsafe accesses from multiple threads at once. Instead, we
            // directly impl Send and Sync on this type. Since this
            // type does have Send and Sync manually impl'd, the Arc
            // is not pointless as the lint suggests.
            #[allow(clippy::arc_with_non_send_sync)]
            region: Arc::new(HostMapping {
                ptr: addr.Value as *mut u8,
                size: total_size,
                handle,
            }),
        })
    }

    pub(super) fn make_memory_executable(&self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let mut _old_flags = PAGE_PROTECTION_FLAGS::default();
            if let Err(e) = unsafe {
                VirtualProtect(
                    self.region.ptr as *const c_void,
                    self.region.size,
                    PAGE_EXECUTE_READWRITE,
                    &mut _old_flags as *mut PAGE_PROTECTION_FLAGS,
                )
            } {
                log_then_return!(WindowsAPIError(e.clone()));
            }
        }

        // make the memory executable on Linux
        #[cfg(target_os = "linux")]
        {
            use libc::{mprotect, PROT_EXEC, PROT_READ, PROT_WRITE};

            let res = unsafe {
                mprotect(
                    self.region.ptr as *mut c_void,
                    self.region.size,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                )
            };

            if res != 0 {
                return Err(new_error!(
                    "Failed to make memory executable: {:#?}",
                    Error::last_os_error().raw_os_error()
                ));
            }
        }
        Ok(())
    }

    /// Internal helper method to get the backing memory as a mutable slice.
    ///
    /// # Safety
    /// As per std::slice::from_raw_parts_mut:
    /// - self.base_addr() must be valid for both reads and writes for
    ///   self.mem_size() * mem::size_of::<u8>() many bytes, and it
    ///   must be properly aligned.
    ///
    ///   The rules on validity are still somewhat unspecified, but we
    ///   assume that the result of our calls to mmap/CreateFileMappings may
    ///   be considered a single "allocated object". The use of
    ///   non-atomic accesses is alright from a Safe Rust standpoint,
    ///   because SharedMemoryBuilder is  not Sync.
    /// - self.base_addr() must point to self.mem_size() consecutive
    ///   properly initialized values of type u8
    ///
    ///   Again, the exact provenance restrictions on what is
    ///   considered to be initialized values are unclear, but we make
    ///   sure to use mmap(MAP_ANONYMOUS) and
    ///   CreateFileMapping(SEC_COMMIT), so the pages in question are
    ///   zero-initialized, which we hope counts for u8.
    /// - The memory referenced by the returned slice must not be
    ///   accessed through any other pointer (not derived from the
    ///   return value) for the duration of the lifetime 'a. Both read
    ///   and write accesses are forbidden.
    ///
    ///   Accesses from Safe Rust necessarily follow this rule,
    ///   because the returned slice's lifetime is the same as that of
    ///   a mutable borrow of self.
    /// - The total size self.mem_size() * mem::size_of::<u8>() of the
    ///   slice must be no larger than isize::MAX, and adding that
    ///   size to data must not "wrap around" the address space. See
    ///   the safety documentation of pointer::offset.
    ///
    ///   This is ensured by a check in ::new()
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn as_mut_slice<'a>(&'a mut self) -> &'a mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.base_ptr(), self.mem_size()) }
    }

    /// Internal helper method to get the backing memory as a slice.
    ///
    /// # Safety
    /// See the discussion on as_mut_slice, with the third point
    /// replaced by:
    /// - The memory referenced by the returned slice must not be
    ///   mutated for the duration of lifetime 'a, except inside an
    ///   UnsafeCell.
    ///
    ///   Host accesses from Safe Rust necessarily follow this rule,
    ///   because the returned slice's lifetime is the same as that of
    ///   a borrow of self, preventing mutations via other methods.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        unsafe { std::slice::from_raw_parts(self.base_ptr(), self.mem_size()) }
    }

    /// Copy the entire contents of `self` into a `Vec<u8>`, then return it
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn copy_all_to_vec(&self) -> Result<Vec<u8>> {
        let data = self.as_slice();
        Ok(data.to_vec())
    }

    /// Copies all bytes from `src` to `self` starting at offset
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn copy_from_slice(&mut self, src: &[u8], offset: usize) -> Result<()> {
        let data = self.as_mut_slice();
        bounds_check!(offset, src.len(), data.len());
        data[offset..offset + src.len()].copy_from_slice(src);
        Ok(())
    }

    /// Return the address of memory at an offset to this `SharedMemory` checking
    /// that the memory is within the bounds of the `SharedMemory`.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn calculate_address(&self, offset: usize) -> Result<usize> {
        bounds_check!(offset, 0, self.mem_size());
        Ok(self.base_addr() + offset)
    }

    generate_reader!(read_u8, u8);
    generate_reader!(read_i8, i8);
    generate_reader!(read_u16, u16);
    generate_reader!(read_i16, i16);
    generate_reader!(read_u32, u32);
    generate_reader!(read_i32, i32);
    generate_reader!(read_u64, u64);
    generate_reader!(read_i64, i64);
    generate_reader!(read_usize, usize);
    generate_reader!(read_isize, isize);

    generate_writer!(write_u8, u8);
    generate_writer!(write_i8, i8);
    generate_writer!(write_u16, u16);
    generate_writer!(write_i16, i16);
    generate_writer!(write_u32, u32);
    generate_writer!(write_i32, i32);
    generate_writer!(write_u64, u64);
    generate_writer!(write_i64, i64);
    generate_writer!(write_usize, usize);
    generate_writer!(write_isize, isize);

    /// Convert the ExclusiveSharedMemory, which may be freely
    /// modified, into a GuestSharedMemory, which may be somewhat
    /// freely modified (mostly by the guest), and a HostSharedMemory,
    /// which may only make certain kinds of accesses that do not race
    /// in the presence of malicious code inside the guest mutating
    /// the GuestSharedMemory.
    pub fn build(self) -> (HostSharedMemory, GuestSharedMemory) {
        let lock = Arc::new(RwLock::new(()));
        (
            HostSharedMemory {
                region: self.region.clone(),
                lock: lock.clone(),
            },
            GuestSharedMemory {
                region: self.region.clone(),
                lock: lock.clone(),
            },
        )
    }

    /// Gets the file handle of the shared memory region for this Sandbox
    #[cfg(target_os = "windows")]
    pub fn get_mmap_file_handle(&self) -> HANDLE {
        self.region.handle
    }
}

/// A trait that abstracts over the particular kind of SharedMemory,
/// used when invoking operations from Rust that absolutely must have
/// exclusive control over the shared memory for correctness +
/// performance, like snapshotting.
pub trait SharedMemory {
    /// Return a readonly reference to the host mapping backing this SharedMemory
    fn region(&self) -> &HostMapping;

    /// Return the base address of the host mapping of this
    /// region. Following the general Rust philosophy, this does not
    /// need to be marked as `unsafe` because doing anything with this
    /// pointer itself requires `unsafe`.
    fn base_addr(&self) -> usize {
        self.region().ptr as usize + PAGE_SIZE_USIZE
    }

    /// Return the base address of the host mapping of this region as
    /// a pointer. Following the general Rust philosophy, this does
    /// not need to be marked as `unsafe` because doing anything with
    /// this pointer itself requires `unsafe`.
    fn base_ptr(&self) -> *mut u8 {
        self.base_addr() as *mut u8
    }

    /// Return the length of usable memory contained in `self`.
    /// The returned size does not include the size of the surrounding
    /// guard pages.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn mem_size(&self) -> usize {
        self.region().size - 2 * PAGE_SIZE_USIZE
    }

    /// Return the raw base address of the host mapping, including the
    /// guard pages.
    fn raw_ptr(&self) -> *mut u8 {
        self.region().ptr
    }

    /// Return the raw size of the host mapping, including the guard
    /// pages.
    fn raw_mem_size(&self) -> usize {
        self.region().size
    }

    /// Run some code with exclusive access to the SharedMemory
    /// underlying this.  If the SharedMemory is not an
    /// ExclusiveSharedMemory, any concurrent accesses to the relevant
    /// HostSharedMemory/GuestSharedMemory may make this fail, or be
    /// made to fail by this, and should be avoided.
    fn with_exclusivity<T, F: FnOnce(&mut ExclusiveSharedMemory) -> T>(
        &mut self,
        f: F,
    ) -> Result<T>;
}

impl SharedMemory for ExclusiveSharedMemory {
    fn region(&self) -> &HostMapping {
        &self.region
    }
    fn with_exclusivity<T, F: FnOnce(&mut ExclusiveSharedMemory) -> T>(
        &mut self,
        f: F,
    ) -> Result<T> {
        Ok(f(self))
    }
}

impl SharedMemory for GuestSharedMemory {
    fn region(&self) -> &HostMapping {
        &self.region
    }
    fn with_exclusivity<T, F: FnOnce(&mut ExclusiveSharedMemory) -> T>(
        &mut self,
        f: F,
    ) -> Result<T> {
        let guard = self
            .lock
            .try_write()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        let mut excl = ExclusiveSharedMemory {
            region: self.region.clone(),
        };
        let ret = f(&mut excl);
        drop(excl);
        drop(guard);
        Ok(ret)
    }
}

/// An unsafe marker trait for types for which all bit patterns are valid.
/// This is required in order for it to be safe to read a value of a particular
/// type out of the sandbox from the HostSharedMemory.
///
/// # Safety
/// This must only be implemented for types for which all bit patterns
/// are valid. It requires that any (non-undef/poison) value of the
/// correct size can be transmuted to the type.
pub unsafe trait AllValid {}
unsafe impl AllValid for u8 {}
unsafe impl AllValid for u16 {}
unsafe impl AllValid for u32 {}
unsafe impl AllValid for u64 {}
unsafe impl AllValid for i8 {}
unsafe impl AllValid for i16 {}
unsafe impl AllValid for i32 {}
unsafe impl AllValid for i64 {}
unsafe impl AllValid for [u8; 16] {}

impl HostSharedMemory {
    /// Read a value of type T, whose representation is the same
    /// between the sandbox and the host, and which has no invalid bit
    /// patterns
    pub fn read<T: AllValid>(&self, offset: usize) -> Result<T> {
        bounds_check!(offset, std::mem::size_of::<T>(), self.mem_size());
        let ret = unsafe {
            let mut ret: core::mem::MaybeUninit<T> = core::mem::MaybeUninit::uninit();
            {
                let slice: &mut [u8] = core::slice::from_raw_parts_mut(
                    ret.as_mut_ptr() as *mut u8,
                    std::mem::size_of::<T>(),
                );
                self.copy_to_slice(slice, offset)?;
            }
            Ok(ret.assume_init())
        };
        ret
    }

    /// Write a value of type T, whose representation is the same
    /// between the sandbox and the host, and which has no invalid bit
    /// patterns
    pub fn write<T: AllValid>(&self, offset: usize, data: T) -> Result<()> {
        bounds_check!(offset, std::mem::size_of::<T>(), self.mem_size());
        unsafe {
            let slice: &[u8] = core::slice::from_raw_parts(
                core::ptr::addr_of!(data) as *const u8,
                std::mem::size_of::<T>(),
            );
            self.copy_from_slice(slice, offset)?;
        }
        Ok(())
    }

    /// Copy the contents of the slice into the sandbox at the
    /// specified offset
    pub fn copy_to_slice(&self, slice: &mut [u8], offset: usize) -> Result<()> {
        bounds_check!(offset, slice.len(), self.mem_size());
        let base = self.base_ptr().wrapping_add(offset);
        let guard = self
            .lock
            .try_read()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        // todo: replace with something a bit more optimized + correct
        for (i, b) in slice.iter_mut().enumerate() {
            unsafe {
                *b = base.wrapping_add(i).read_volatile();
            }
        }
        drop(guard);
        Ok(())
    }

    /// Copy the contents of the sandbox at the specified offset into
    /// the slice
    pub fn copy_from_slice(&self, slice: &[u8], offset: usize) -> Result<()> {
        bounds_check!(offset, slice.len(), self.mem_size());
        let base = self.base_ptr().wrapping_add(offset);
        let guard = self
            .lock
            .try_read()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        // todo: replace with something a bit more optimized + correct
        for (i, b) in slice.iter().enumerate() {
            unsafe {
                base.wrapping_add(i).write_volatile(*b);
            }
        }
        drop(guard);
        Ok(())
    }

    /// Fill the memory in the range `[offset, offset + len)` with `value`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn fill(&mut self, value: u8, offset: usize, len: usize) -> Result<()> {
        bounds_check!(offset, len, self.mem_size());
        let base = self.base_ptr().wrapping_add(offset);
        let guard = self
            .lock
            .try_read()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        // todo: replace with something a bit more optimized + correct
        for i in 0..len {
            unsafe { base.wrapping_add(i).write_volatile(value) };
        }
        drop(guard);
        Ok(())
    }

    /// Pushes the given data onto shared memory to the buffer at the given offset.
    /// NOTE! buffer_start_offset must point to the beginning of the buffer
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn push_buffer(
        &mut self,
        buffer_start_offset: usize,
        buffer_size: usize,
        data: &[u8],
    ) -> Result<()> {
        let stack_pointer_rel = self.read::<u64>(buffer_start_offset).unwrap() as usize;
        let buffer_size_u64: u64 = buffer_size.try_into()?;

        if stack_pointer_rel > buffer_size || stack_pointer_rel < 8 {
            return Err(new_error!(
                "Unable to push data to buffer: Stack pointer is out of bounds. Stack pointer: {}, Buffer size: {}",
                stack_pointer_rel,
                buffer_size_u64
            ));
        }

        let size_required = data.len() + 8;
        let size_available = buffer_size - stack_pointer_rel;

        if size_required > size_available {
            return Err(new_error!(
                "Not enough space in buffer to push data. Required: {}, Available: {}",
                size_required,
                size_available
            ));
        }

        // get absolute
        let stack_pointer_abs = stack_pointer_rel + buffer_start_offset;

        // write the actual data to the top of stack
        self.copy_from_slice(data, stack_pointer_abs)?;

        // write the offset to the newly written data, to the top of stack.
        // this is used when popping the stack, to know how far back to jump
        self.write::<u64>(stack_pointer_abs + data.len(), stack_pointer_rel as u64)?;

        // update stack pointer to point to the next free address
        self.write::<u64>(
            buffer_start_offset,
            (stack_pointer_rel + data.len() + 8) as u64,
        )?;
        Ok(())
    }

    /// Pops the given given buffer into a `T` and returns it.
    /// NOTE! the data must be a size-prefixed flatbuffer, and
    /// buffer_start_offset must point to the beginning of the buffer
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn try_pop_buffer_into<T>(
        &mut self,
        buffer_start_offset: usize,
        buffer_size: usize,
    ) -> Result<T>
    where
        T: for<'b> TryFrom<&'b [u8]>,
    {
        // get the stackpointer
        let stack_pointer_rel = self.read::<u64>(buffer_start_offset)? as usize;

        if stack_pointer_rel > buffer_size || stack_pointer_rel < 16 {
            return Err(new_error!(
                "Unable to pop data from buffer: Stack pointer is out of bounds. Stack pointer: {}, Buffer size: {}",
                stack_pointer_rel,
                buffer_size
            ));
        }

        // make it absolute
        let last_element_offset_abs = stack_pointer_rel + buffer_start_offset;

        // go back 8 bytes to get offset to element on top of stack
        let last_element_offset_rel: usize =
            self.read::<u64>(last_element_offset_abs - 8).unwrap() as usize;

        // make it absolute
        let last_element_offset_abs = last_element_offset_rel + buffer_start_offset;

        // Get the size of the flatbuffer buffer from memory
        let fb_buffer_size = {
            let size_i32 = self.read::<u32>(last_element_offset_abs)? + 4;
            // ^^^ flatbuffer byte arrays are prefixed by 4 bytes
            // indicating its size, so, to get the actual size, we need
            // to add 4.
            usize::try_from(size_i32)
        }?;

        let mut result_buffer = vec![0; fb_buffer_size];

        self.copy_to_slice(&mut result_buffer, last_element_offset_abs)?;
        let to_return = T::try_from(result_buffer.as_slice()).map_err(|_e| {
            new_error!(
                "pop_buffer_into: failed to convert buffer to {}",
                type_name::<T>()
            )
        })?;

        // update the stack pointer to point to the element we just popped off since that is now free
        self.write::<u64>(buffer_start_offset, last_element_offset_rel as u64)?;

        // zero out the memory we just popped off
        let num_bytes_to_zero = stack_pointer_rel - last_element_offset_rel;
        self.fill(0, last_element_offset_abs, num_bytes_to_zero)?;

        Ok(to_return)
    }
}

impl SharedMemory for HostSharedMemory {
    fn region(&self) -> &HostMapping {
        &self.region
    }
    fn with_exclusivity<T, F: FnOnce(&mut ExclusiveSharedMemory) -> T>(
        &mut self,
        f: F,
    ) -> Result<T> {
        let guard = self
            .lock
            .try_write()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        let mut excl = ExclusiveSharedMemory {
            region: self.region.clone(),
        };
        let ret = f(&mut excl);
        drop(excl);
        drop(guard);
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_common::mem::PAGE_SIZE_USIZE;
    use proptest::prelude::*;

    use super::{ExclusiveSharedMemory, HostSharedMemory, SharedMemory};
    use crate::mem::shared_mem_tests::read_write_test_suite;
    use crate::Result;

    #[test]
    fn fill() {
        let mem_size: usize = 4096;
        let eshm = ExclusiveSharedMemory::new(mem_size).unwrap();
        let (mut hshm, _) = eshm.build();

        hshm.fill(1, 0, 1024).unwrap();
        hshm.fill(2, 1024, 1024).unwrap();
        hshm.fill(3, 2048, 1024).unwrap();
        hshm.fill(4, 3072, 1024).unwrap();

        let vec = hshm
            .with_exclusivity(|e| e.copy_all_to_vec().unwrap())
            .unwrap();

        assert!(vec[0..1024].iter().all(|&x| x == 1));
        assert!(vec[1024..2048].iter().all(|&x| x == 2));
        assert!(vec[2048..3072].iter().all(|&x| x == 3));
        assert!(vec[3072..4096].iter().all(|&x| x == 4));

        hshm.fill(5, 0, 4096).unwrap();

        let vec2 = hshm
            .with_exclusivity(|e| e.copy_all_to_vec().unwrap())
            .unwrap();
        assert!(vec2.iter().all(|&x| x == 5));

        assert!(hshm.fill(0, 0, mem_size + 1).is_err());
        assert!(hshm.fill(0, mem_size, 1).is_err());
    }

    #[test]
    fn copy_into_from() -> Result<()> {
        let mem_size: usize = 4096;
        let vec_len = 10;
        let eshm = ExclusiveSharedMemory::new(mem_size)?;
        let (hshm, _) = eshm.build();
        let vec = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        // write the value to the memory at the beginning.
        hshm.copy_from_slice(&vec, 0)?;

        let mut vec2 = vec![0; vec_len];
        // read the value back from the memory at the beginning.
        hshm.copy_to_slice(vec2.as_mut_slice(), 0)?;
        assert_eq!(vec, vec2);

        let offset = mem_size - vec.len();
        // write the value to the memory at the end.
        hshm.copy_from_slice(&vec, offset)?;

        let mut vec3 = vec![0; vec_len];
        // read the value back from the memory at the end.
        hshm.copy_to_slice(&mut vec3, offset)?;
        assert_eq!(vec, vec3);

        let offset = mem_size / 2;
        // write the value to the memory at the middle.
        hshm.copy_from_slice(&vec, offset)?;

        let mut vec4 = vec![0; vec_len];
        // read the value back from the memory at the middle.
        hshm.copy_to_slice(&mut vec4, offset)?;
        assert_eq!(vec, vec4);

        // try and read a value from an offset that is beyond the end of the memory.
        let mut vec5 = vec![0; vec_len];
        assert!(hshm.copy_to_slice(&mut vec5, mem_size).is_err());

        // try and write a value to an offset that is beyond the end of the memory.
        assert!(hshm.copy_from_slice(&vec5, mem_size).is_err());

        // try and read a value from an offset that is too large.
        let mut vec6 = vec![0; vec_len];
        assert!(hshm.copy_to_slice(&mut vec6, mem_size * 2).is_err());

        // try and write a value to an offset that is too large.
        assert!(hshm.copy_from_slice(&vec6, mem_size * 2).is_err());

        // try and read a value that is too large.
        let mut vec7 = vec![0; mem_size * 2];
        assert!(hshm.copy_to_slice(&mut vec7, 0).is_err());

        // try and write a value that is too large.
        assert!(hshm.copy_from_slice(&vec7, 0).is_err());

        Ok(())
    }

    proptest! {
        #[test]
        fn read_write_i32(val in -0x1000_i32..0x1000_i32) {
            read_write_test_suite(
                val,
                ExclusiveSharedMemory::new,
                Box::new(ExclusiveSharedMemory::read_i32),
                Box::new(ExclusiveSharedMemory::write_i32),
            )
            .unwrap();
            read_write_test_suite(
                val,
                |s| {
                    let e = ExclusiveSharedMemory::new(s)?;
                    let (h, _) = e.build();
                    Ok(h)
                },
                Box::new(HostSharedMemory::read::<i32>),
                Box::new(|h, o, v| h.write::<i32>(o, v)),
            )
            .unwrap();
        }
    }

    #[test]
    fn alloc_fail() {
        let gm = ExclusiveSharedMemory::new(0);
        assert!(gm.is_err());
        let gm = ExclusiveSharedMemory::new(usize::MAX);
        assert!(gm.is_err());
    }

    #[test]
    fn clone() {
        let eshm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();
        let (hshm1, _) = eshm.build();
        let hshm2 = hshm1.clone();

        // after hshm1 is cloned, hshm1 and hshm2 should have identical
        // memory sizes and pointers.
        assert_eq!(hshm1.mem_size(), hshm2.mem_size());
        assert_eq!(hshm1.base_addr(), hshm2.base_addr());

        // we should be able to copy a byte array into both hshm1 and hshm2,
        // and have both changes be reflected in all clones
        hshm1.copy_from_slice(b"a", 0).unwrap();
        hshm2.copy_from_slice(b"b", 1).unwrap();

        // at this point, both hshm1 and hshm2 should have
        // offset 0 = 'a', offset 1 = 'b'
        for (raw_offset, expected) in &[(0, b'a'), (1, b'b')] {
            assert_eq!(hshm1.read::<u8>(*raw_offset).unwrap(), *expected);
            assert_eq!(hshm2.read::<u8>(*raw_offset).unwrap(), *expected);
        }

        // after we drop hshm1, hshm2 should still exist, be valid,
        // and have all contents from before hshm1 was dropped
        drop(hshm1);

        // at this point, hshm2 should still have offset 0 = 'a', offset 1 = 'b'
        for (raw_offset, expected) in &[(0, b'a'), (1, b'b')] {
            assert_eq!(hshm2.read::<u8>(*raw_offset).unwrap(), *expected);
        }
        hshm2.copy_from_slice(b"c", 2).unwrap();
        assert_eq!(hshm2.read::<u8>(2).unwrap(), b'c');
        drop(hshm2);
    }

    #[test]
    fn copy_all_to_vec() {
        let mut data = vec![b'a', b'b', b'c'];
        data.resize(4096, 0);
        let mut eshm = ExclusiveSharedMemory::new(data.len()).unwrap();
        eshm.copy_from_slice(data.as_slice(), 0).unwrap();
        let ret_vec = eshm.copy_all_to_vec().unwrap();
        assert_eq!(data, ret_vec);
    }

    /// A test to ensure that, if a `SharedMem` instance is cloned
    /// and _all_ clones are dropped, the memory region will no longer
    /// be valid.
    ///
    /// This test is ignored because it is incompatible with other tests as
    /// they may be allocating memory at the same time.
    ///
    /// Marking this test as ignored means that running `cargo test` will not
    /// run it. This feature will allow a developer who runs that command
    /// from their workstation to be successful without needing to know about
    /// test interdependencies. This test will, however, be run explicitly as a
    /// part of the CI pipeline.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn test_drop() {
        use proc_maps::maps_contain_addr;

        let pid = std::process::id();

        let eshm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();
        let (hshm1, gshm) = eshm.build();
        let hshm2 = hshm1.clone();
        let addr = hshm1.raw_ptr() as usize;

        // ensure the address is in the process's virtual memory
        let maps_before_drop = proc_maps::get_process_maps(pid.try_into().unwrap()).unwrap();
        assert!(
            maps_contain_addr(addr, &maps_before_drop),
            "shared memory address {:#x} was not found in process map, but should be",
            addr,
        );
        // drop both shared memory instances, which should result
        // in freeing the memory region
        drop(hshm1);
        drop(hshm2);
        drop(gshm);

        let maps_after_drop = proc_maps::get_process_maps(pid.try_into().unwrap()).unwrap();
        // now, ensure the address is not in the process's virtual memory
        assert!(
            !maps_contain_addr(addr, &maps_after_drop),
            "shared memory address {:#x} was found in the process map, but shouldn't be",
            addr
        );
    }

    #[cfg(target_os = "linux")]
    mod guard_page_crash_test {
        use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};

        const TEST_EXIT_CODE: u8 = 211; // an uncommon exit code, used for testing purposes

        /// hook sigsegv to exit with status code, to make it testable, rather than have it exit from a signal
        /// NOTE: We CANNOT panic!() in the handler, and make the tests #[should_panic], because
        ///     the test harness process will crash anyway after the test passes
        fn setup_signal_handler() {
            unsafe {
                signal_hook_registry::register_signal_unchecked(libc::SIGSEGV, || {
                    std::process::exit(TEST_EXIT_CODE.into());
                })
                .unwrap();
            }
        }

        #[test]
        #[ignore] // this test is ignored because it will crash the running process
        fn read() {
            setup_signal_handler();

            let eshm = ExclusiveSharedMemory::new(4096).unwrap();
            let (hshm, _) = eshm.build();
            let guard_page_ptr = hshm.raw_ptr();
            unsafe { std::ptr::read_volatile(guard_page_ptr) };
        }

        #[test]
        #[ignore] // this test is ignored because it will crash the running process
        fn write() {
            setup_signal_handler();

            let eshm = ExclusiveSharedMemory::new(4096).unwrap();
            let (hshm, _) = eshm.build();
            let guard_page_ptr = hshm.raw_ptr();
            unsafe { std::ptr::write_volatile(guard_page_ptr, 0u8) };
        }

        #[test]
        #[ignore] // this test is ignored because it will crash the running process
        fn exec() {
            setup_signal_handler();

            let eshm = ExclusiveSharedMemory::new(4096).unwrap();
            let (hshm, _) = eshm.build();
            let guard_page_ptr = hshm.raw_ptr();
            let func: fn() = unsafe { std::mem::transmute(guard_page_ptr) };
            func();
        }

        // provides a way for running the above tests in a separate process since they expect to crash
        #[test]
        fn guard_page_testing_shim() {
            let tests = vec!["read", "write", "exec"];

            for test in tests {
                let status = std::process::Command::new("cargo")
                    .args(["test", "-p", "hyperlight-host", "--", "--ignored", test])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .expect("Unable to launch tests");
                assert_eq!(
                    status.code(),
                    Some(TEST_EXIT_CODE.into()),
                    "Guard Page test failed: {}",
                    test
                );
            }
        }
    }
}
