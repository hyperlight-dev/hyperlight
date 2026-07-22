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

//! HVF surrogate server.
//!
//! HVF allows only one VM per process, so a host that runs multiple
//! concurrent sandboxes delegates each VM to a surrogate process. This
//! binary is that server: `hyperlight-host` spawns it with an inherited
//! `SOCK_STREAM` unix socket fd in `HVF_SURROGATE_FD` and speaks the
//! [`hyperlight_hvf::proto`] protocol to it.
//!
//! Threading (HVF requires vCPU create/run/register access on a single
//! thread; `hv_vcpus_exit` may be called from any thread):
//!
//! - The **main thread** is the vCPU thread: it owns the VM and executes
//!   every stateful request.
//! - A **reader thread** reads request frames from the socket. `Cancel` is
//!   handled directly there and gets no response; every other request is
//!   forwarded to the main thread.
//! - A **writer thread** writes response frames. Responses are written by
//!   exactly one thread, and — unlike folding the writer role into the
//!   reader thread — the reader never blocks waiting for a response, so a
//!   `Cancel` that arrives while a `RunVcpu` is executing is always seen.
//!
//! Exit codes: `0` on clean EOF (the host went away), `2` on protocol
//! errors (bad handshake, malformed frame, socket failure).

use std::collections::HashMap;
use std::ffi::{CString, c_void};
use std::io;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

use hyperlight_hvf::core::{self, Perms, Vm};
use hyperlight_hvf::proto::{self, Backing, PROTO_VERSION, Request, Response};

/// Environment variable carrying the inherited control-socket fd.
const FD_ENV_VAR: &str = "HVF_SURROGATE_FD";

/// Exit code for protocol errors (bad handshake, malformed frame).
const EXIT_PROTOCOL_ERROR: i32 = 2;

/// A live `mmap` of a memory object into this process, unmapped on drop.
struct Mapping {
    va: usize,
    size: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `va`/`size` describe a live mapping created in
        // `map_memory`, and this drop runs at most once.
        unsafe {
            libc::munmap(self.va as *mut c_void, self.size);
        }
    }
}

fn main() {
    let Some(fd) = std::env::var(FD_ENV_VAR).ok().and_then(|v| v.parse().ok()) else {
        eprintln!("hvf_surrogate: {FD_ENV_VAR} is not set or not a valid fd");
        std::process::exit(EXIT_PROTOCOL_ERROR);
    };
    // SAFETY: the parent spawns us with this socket fd open (created
    // without CLOEXEC so it survives `exec`).
    let socket = unsafe { UnixStream::from_raw_fd(fd) };
    let writer_socket = match socket.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hvf_surrogate: failed to clone socket: {e}");
            std::process::exit(EXIT_PROTOCOL_ERROR);
        }
    };

    // Requests (minus Cancel) flow reader -> main; responses flow
    // main -> writer.
    let (req_tx, req_rx) = channel::<Request>();
    let (resp_tx, resp_rx) = channel::<Response>();

    std::thread::spawn(move || writer_thread(writer_socket, resp_rx));

    // The current vCPU id **plus one**, shared with the reader thread so it
    // can cancel a running vCPU. 0 means "no vCPU" (HVF vCPU ids are
    // zero-based, so the raw id cannot double as the sentinel).
    let vcpu_id = Arc::new(AtomicU64::new(0));
    let reader_vcpu_id = Arc::clone(&vcpu_id);
    std::thread::spawn(move || reader_thread(socket, req_tx, reader_vcpu_id));

    vcpu_thread(req_rx, resp_tx, &vcpu_id);
}

/// Main-thread loop: owns the VM and executes every stateful request.
fn vcpu_thread(rx: Receiver<Request>, resp_tx: Sender<Response>, vcpu_id: &AtomicU64) {
    let mut vm: Option<Vm> = None;
    let mut mappings: HashMap<u32, Mapping> = HashMap::new();
    while let Ok(req) = rx.recv() {
        let resp = handle_request(req, &mut vm, &mut mappings, vcpu_id);
        if resp_tx.send(resp).is_err() {
            // The writer thread is gone; nothing useful left to do.
            std::process::exit(EXIT_PROTOCOL_ERROR);
        }
    }
    // The reader thread exits the whole process on EOF, so reaching this
    // point means the channel closed unexpectedly; leave quietly.
}

/// Reads request frames from the socket. Completes the handshake, then
/// relays requests to the vCPU thread; `Cancel` is handled locally with
/// no response.
fn reader_thread(mut socket: UnixStream, req_tx: Sender<Request>, vcpu_id: Arc<AtomicU64>) {
    handshake(&mut socket);
    loop {
        match proto::read_frame::<Request>(&mut socket) {
            Ok(Some(Request::Cancel)) => {
                let id = vcpu_id.load(Ordering::Acquire);
                if id != 0 {
                    // A stale cancel of an idle/destroyed vCPU fails
                    // harmlessly (ids are kernel-validated).
                    let _ = core::cancel(id - 1);
                }
            }
            Ok(Some(req)) => {
                if req_tx.send(req).is_err() {
                    // The vCPU thread is gone.
                    std::process::exit(0);
                }
            }
            Ok(None) => {
                // Clean EOF: the host is gone.
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("hvf_surrogate: malformed frame: {e}");
                std::process::exit(EXIT_PROTOCOL_ERROR);
            }
        }
    }
}

/// Writes response frames; the only thread that writes to the socket after
/// the handshake (which the reader thread completes before relaying any
/// request).
fn writer_thread(mut socket: UnixStream, rx: Receiver<Response>) {
    while let Ok(resp) = rx.recv() {
        if let Err(e) = proto::write_frame(&mut socket, &resp) {
            eprintln!("hvf_surrogate: failed to write response: {e}");
            std::process::exit(EXIT_PROTOCOL_ERROR);
        }
    }
}

/// The protocol handshake: the first frame must be `Hello` with a matching
/// protocol version.
fn handshake(socket: &mut UnixStream) {
    match proto::read_frame::<Request>(socket) {
        Ok(Some(Request::Hello { version })) if version == PROTO_VERSION => {
            if let Err(e) = proto::write_frame(
                socket,
                &Response::Hello {
                    version: PROTO_VERSION,
                },
            ) {
                eprintln!("hvf_surrogate: failed to write handshake response: {e}");
                std::process::exit(EXIT_PROTOCOL_ERROR);
            }
        }
        Ok(Some(Request::Hello { version })) => {
            let _ = proto::write_frame(
                socket,
                &Response::Err(format!(
                    "protocol version mismatch: client {version}, server {PROTO_VERSION}"
                )),
            );
            std::process::exit(EXIT_PROTOCOL_ERROR);
        }
        Ok(Some(_)) => {
            eprintln!("hvf_surrogate: expected Hello as the first frame");
            std::process::exit(EXIT_PROTOCOL_ERROR);
        }
        Ok(None) => {
            // The host went away before the handshake.
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("hvf_surrogate: malformed handshake frame: {e}");
            std::process::exit(EXIT_PROTOCOL_ERROR);
        }
    }
}

fn err_no_vm() -> Response {
    Response::Err("no VM (CreateVm first)".to_string())
}

/// Execute one request on the vCPU thread.
fn handle_request(
    req: Request,
    vm: &mut Option<Vm>,
    mappings: &mut HashMap<u32, Mapping>,
    vcpu_id: &AtomicU64,
) -> Response {
    match req {
        // A `Hello` after the initial handshake marks a new client session
        // (the process was returned to the pool and re-acquired): reset any
        // state left over from the previous checkout. A version mismatch
        // here is answered with `Err` but keeps the process alive — the
        // strict `exit(2)` applies to the initial handshake only.
        Request::Hello { version } => {
            if let Some(v) = vm.take() {
                drop(v);
                vcpu_id.store(0, Ordering::Release);
            }
            mappings.clear();
            if version == PROTO_VERSION {
                Response::Hello {
                    version: PROTO_VERSION,
                }
            } else {
                Response::Err(format!(
                    "protocol version mismatch: client {version}, server {PROTO_VERSION}"
                ))
            }
        }
        Request::Cancel => Response::Err("Cancel is handled out-of-band".to_string()),
        Request::CreateVm => {
            if vm.is_some() {
                return Response::Err("VM already exists".to_string());
            }
            match Vm::new() {
                Ok(v) => {
                    // +1: vCPU ids are zero-based, 0 is the "no vCPU"
                    // sentinel.
                    vcpu_id.store(v.vcpu_id() + 1, Ordering::Release);
                    *vm = Some(v);
                    Response::Ok
                }
                Err(e) => Response::Err(e.to_string()),
            }
        }
        Request::DestroyVm => {
            if let Some(v) = vm.take() {
                drop(v);
                vcpu_id.store(0, Ordering::Release);
            }
            // Guest mappings died with the VM; release the process mappings.
            mappings.clear();
            Response::Ok
        }
        Request::MapMemory {
            slot,
            gpa,
            size,
            perms,
            backing,
        } => {
            let Some(vm) = vm.as_mut() else {
                return err_no_vm();
            };
            map_memory(vm, mappings, slot, gpa, size as usize, perms, backing)
        }
        Request::UnmapMemory { slot, gpa, size } => {
            let Some(vm) = vm.as_mut() else {
                return err_no_vm();
            };
            match vm.unmap_memory(slot, gpa, size as usize) {
                Ok(()) => {
                    // Dropping the Mapping munmaps after the guest unmap.
                    mappings.remove(&slot);
                    Response::Ok
                }
                Err(e) => Response::Err(e.to_string()),
            }
        }
        Request::RunVcpu => {
            let Some(vm) = vm.as_mut() else {
                return err_no_vm();
            };
            match vm.run_vcpu() {
                Ok(exit) => Response::Exit(exit),
                Err(e) => Response::Err(e.to_string()),
            }
        }
        Request::GetRegs => {
            let Some(vm) = vm.as_ref() else {
                return err_no_vm();
            };
            vm.regs().map(Response::Regs).unwrap_or_else(err)
        }
        Request::SetRegs(regs) => {
            let Some(vm) = vm.as_ref() else {
                return err_no_vm();
            };
            vm.set_regs(&regs)
                .map(|()| Response::Ok)
                .unwrap_or_else(err)
        }
        Request::GetFpu => {
            let Some(vm) = vm.as_ref() else {
                return err_no_vm();
            };
            vm.fpu().map(Response::Fpu).unwrap_or_else(err)
        }
        Request::SetFpu(fpu) => {
            let Some(vm) = vm.as_ref() else {
                return err_no_vm();
            };
            vm.set_fpu(&fpu).map(|()| Response::Ok).unwrap_or_else(err)
        }
        Request::GetSregs => {
            let Some(vm) = vm.as_ref() else {
                return err_no_vm();
            };
            vm.sregs().map(Response::Sregs).unwrap_or_else(err)
        }
        Request::SetSregs(sregs) => {
            let Some(vm) = vm.as_ref() else {
                return err_no_vm();
            };
            vm.set_sregs(&sregs)
                .map(|()| Response::Ok)
                .unwrap_or_else(err)
        }
        Request::ResetVcpu => {
            let Some(vm) = vm.as_ref() else {
                return err_no_vm();
            };
            vm.reset_vcpu().map(|()| Response::Ok).unwrap_or_else(err)
        }
    }
}

fn err(e: core::HvfError) -> Response {
    Response::Err(e.to_string())
}

/// `mmap` the backing object and map it into the guest, replacing any
/// existing mapping for `slot`.
fn map_memory(
    vm: &mut Vm,
    mappings: &mut HashMap<u32, Mapping>,
    slot: u32,
    gpa: u64,
    size: usize,
    perms: Perms,
    backing: Backing,
) -> Response {
    let va = match mmap_backing(&backing, size) {
        Ok(va) => va,
        Err(e) => return Response::Err(format!("failed to map backing object: {e}")),
    };
    // SAFETY: [va, va + size) is a live mapping owned by this process; on
    // success it is stored in `mappings` and only munmapped after
    // `vm.unmap_memory` (or VM destruction).
    match unsafe { vm.map_memory(slot, gpa, va, size, perms) } {
        Ok(()) => {
            // On slot replacement the old Mapping is munmapped here, after
            // `map_memory` already unmapped the old slot from the guest.
            mappings.insert(slot, Mapping { va, size });
            Response::Ok
        }
        Err(e) => {
            // SAFETY: the mapping was created above and is not in use.
            unsafe {
                libc::munmap(va as *mut c_void, size);
            }
            Response::Err(e.to_string())
        }
    }
}

/// `mmap` `size` bytes of the backing object into this process and return
/// the base address.
fn mmap_backing(backing: &Backing, size: usize) -> io::Result<usize> {
    match backing {
        Backing::Shm { name, offset } => {
            let c_name = CString::new(name.as_str())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            // SAFETY: `c_name` is a valid NUL-terminated string.
            let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_RDWR, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // NOTE: the name is NOT unlinked here. The host owns the
            // object's name lifecycle (it unlinks when its own backing
            // drops) and may legitimately ask us to map the same object
            // again (e.g. snapshot restore remaps); unlinking at map time
            // would make those later `shm_open`s fail with ENOENT. Our
            // mmap keeps the object alive even after the name is gone.
            // SAFETY: `fd` is a live shm object descriptor and `offset`
            // lies within it; the result is checked against MAP_FAILED.
            let va = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    *offset as libc::off_t,
                )
            };
            // SAFETY: `fd` is a live descriptor no longer needed once the
            // mmap exists (or failed).
            unsafe {
                libc::close(fd);
            }
            if va == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            Ok(va as usize)
        }
        Backing::File { path, offset } => {
            use std::os::unix::io::AsRawFd;
            let file = std::fs::File::open(path)?;
            // MAP_PRIVATE on purpose: `hv_vm_map` rejects read-only
            // MAP_SHARED file mappings (measured: HV error 0xfae94001),
            // while MAP_PRIVATE works and matches the host's own view of
            // the file. These regions are read-only+exec, so the
            // copy-on-read private view is coherent.
            // SAFETY: `file` is a live read-only descriptor and `offset`
            // lies within it; the result is checked against MAP_FAILED.
            let va = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    file.as_raw_fd(),
                    *offset as libc::off_t,
                )
            };
            if va == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            Ok(va as usize)
        }
    }
}
