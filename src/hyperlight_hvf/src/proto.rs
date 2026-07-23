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

//! IPC protocol between `hyperlight-host` (client) and the `hvf_surrogate`
//! process (server) that owns an HVF VM on behalf of one sandbox.
//!
//! Transport: a `SOCK_STREAM` unix socket pair inherited by the surrogate.
//! Frames are `u32` little-endian length-prefixed JSON bodies. Requests and
//! responses are strictly serialized with one exception: [`Request::Cancel`]
//! may be sent from another thread while a [`Request::RunVcpu`] is
//! outstanding, and receives no response (the pending `RunVcpu` answers with
//! [`Response::Exit`]`(`[`VmExit::Cancelled`]`)`).
//!
//! Guest memory is shared by reference, never copied: anonymous regions are
//! POSIX shm objects (`shm_open`) and file regions are filesystem paths; the
//! surrogate maps the same underlying object into its own address space and
//! then into the guest.

use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::core::{FpuState, Perms, Regs, Sregs, VmExit};

/// Current protocol version, exchanged in the [`Request::Hello`] handshake.
pub const PROTO_VERSION: u32 = 1;

/// Largest frame we are willing to read (16 MiB; real frames are a few KiB).
const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// How the surrogate can access the memory object backing a guest region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Backing {
    /// A POSIX shm object (created with `shm_open`), with the byte offset of
    /// the usable region within the object.
    Shm {
        /// Object name as passed to `shm_open` (e.g. `/hl-<random>`)
        name: String,
        /// Offset of the region start within the object
        offset: u64,
    },
    /// A filesystem path (used for read-only file mappings), with the byte
    /// offset of the region within the file.
    File {
        /// Path to the file
        path: PathBuf,
        /// Offset of the region start within the file
        offset: u64,
    },
}

/// A request from the host to the surrogate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Protocol handshake; must be the first message on a connection.
    Hello {
        /// Client protocol version ([`PROTO_VERSION`])
        version: u32,
    },
    /// Create the VM and vCPU. Must precede any other VM operation; the VM
    /// stays alive until [`Request::DestroyVm`] (or process exit).
    CreateVm,
    /// Destroy the VM and vCPU, returning the surrogate to its idle state so
    /// the process can be reused by another sandbox.
    DestroyVm,
    /// Map `size` bytes of `backing` into the guest at `gpa` for `slot`,
    /// replacing any existing mapping for that slot.
    MapMemory {
        /// Mapping slot identifier
        slot: u32,
        /// Guest physical address
        gpa: u64,
        /// Region size in bytes
        size: u64,
        /// Guest permissions
        perms: Perms,
        /// The memory object backing the region
        backing: Backing,
    },
    /// Unmap the region previously mapped for `slot` (`gpa`/`size` are a
    /// fallback when the slot is unknown to the server).
    UnmapMemory {
        /// Mapping slot identifier
        slot: u32,
        /// Guest physical address
        gpa: u64,
        /// Region size in bytes
        size: u64,
    },
    /// Run the vCPU until it exits. Responds with [`Response::Exit`].
    RunVcpu,
    /// Read the general-purpose registers. Responds with [`Response::Regs`].
    GetRegs,
    /// Write the general-purpose registers. Responds with [`Response::Ok`].
    SetRegs(Box<Regs>),
    /// Read the SIMD/FP registers. Responds with [`Response::Fpu`].
    GetFpu,
    /// Write the SIMD/FP registers. Responds with [`Response::Ok`].
    SetFpu(Box<FpuState>),
    /// Read the system registers. Responds with [`Response::Sregs`].
    GetSregs,
    /// Write the system registers. Responds with [`Response::Ok`].
    SetSregs(Sregs),
    /// Reset the vCPU to a clean state (GP/FP registers zeroed, debug
    /// breakpoint/watchpoint pair 0 cleared). Responds with
    /// [`Response::Ok`]. Translation system registers are untouched; the
    /// client applies them from the snapshot afterwards.
    ResetVcpu,
    /// Force the running vCPU out of `hv_vcpu_run`. May be sent while a
    /// [`Request::RunVcpu`] is outstanding; receives no response.
    Cancel,
}

/// A response from the surrogate to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Protocol handshake answer.
    Hello {
        /// Server protocol version ([`PROTO_VERSION`])
        version: u32,
    },
    /// The request succeeded with no payload.
    Ok,
    /// Answer to [`Request::GetRegs`].
    Regs(Box<Regs>),
    /// Answer to [`Request::GetFpu`].
    Fpu(Box<FpuState>),
    /// Answer to [`Request::GetSregs`].
    Sregs(Sregs),
    /// Answer to [`Request::RunVcpu`].
    Exit(VmExit),
    /// The request failed.
    Err(String),
}

/// Write one length-prefixed frame. The whole frame is serialized into a
/// single buffer and written with one `write_all`, so that frames written
/// from different threads sharing one writer cannot interleave on the wire.
pub fn write_frame<T: Serialize>(w: &mut impl Write, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    w.write_all(&frame)?;
    w.flush()
}

/// Read one length-prefixed frame. Returns `Ok(None)` on a clean EOF at a
/// frame boundary (peer closed the connection).
pub fn read_frame<T: DeserializeOwned>(r: &mut impl Read) -> io::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds maximum"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    let msg = serde_json::from_slice(&body).map_err(io::Error::other)?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let mut buf = Vec::new();
        let req = Request::MapMemory {
            slot: 3,
            gpa: 0x1000,
            size: 0x4000,
            perms: Perms {
                read: true,
                write: true,
                exec: false,
            },
            backing: Backing::Shm {
                name: "/hl-test".to_string(),
                offset: 0x4000,
            },
        };
        write_frame(&mut buf, &req).unwrap();
        let decoded: Request = read_frame(&mut &buf[..]).unwrap().unwrap();
        assert_eq!(format!("{decoded:?}"), format!("{req:?}"));
    }

    #[test]
    fn clean_eof_is_none() {
        let mut empty: &[u8] = &[];
        let res: Option<Response> = read_frame(&mut empty).unwrap();
        assert!(res.is_none());
    }
}
