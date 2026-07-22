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

//! Surrogate-process HVF backend.
//!
//! HVF allows only one VM per process, so this backend delegates the VM to
//! an `hvf_surrogate` server process (acquired from the
//! [`HvfSurrogateProcessManager`] pool) and forwards every
//! [`VirtualMachine`] operation over the [`hyperlight_hvf::proto`] IPC
//! protocol.
//!
//! Socket discipline: the sandbox thread performs request→response cycles;
//! the interrupt thread may send `Request::Cancel` concurrently. All frames
//! (requests AND cancels) are written through one shared
//! `Arc<Mutex<UnixStream>>` writer — `proto::write_frame` serializes each
//! frame into a single buffer, so frames cannot interleave on the wire.
//! Responses are read on a separate stream clone used only by the sandbox
//! thread (`Cancel` has no response).

use std::fmt;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use hyperlight_hvf::core::Perms;
use hyperlight_hvf::proto::{self, PROTO_VERSION, Request, Response};

use crate::hypervisor::hvf_surrogate_manager::{
    HvfSurrogateProcess, get_hvf_surrogate_process_manager,
};
use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::virtual_machine::{
    CreateVmError, HypervisorError, MapMemoryError, RegisterError, ResetVcpuError, RunVcpuError,
    UnmapMemoryError, VirtualMachine, VmExit,
};
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

/// A [`VirtualMachine`] whose VM lives in a surrogate process.
pub(crate) struct HvfSurrogateVm {
    /// The pooled surrogate process; held for its `Drop`, which returns a
    /// still-running process to the pool.
    _process: HvfSurrogateProcess,
    /// Shared writer for ALL frames (requests from the sandbox thread and
    /// cancels from the interrupt thread). Also handed to the interrupt
    /// handle via [`HvfSurrogateVm::cancel_writer`].
    writer: Arc<Mutex<UnixStream>>,
    /// Reader for responses; only the sandbox thread performs
    /// request→response cycles, but the trait takes `&self` for register
    /// reads, hence the mutex.
    reader: Mutex<UnixStream>,
}

// The fields are all Send + Sync; `fmt::Debug` is implemented manually
// because `HvfSurrogateProcess` has no Debug impl.
impl fmt::Debug for HvfSurrogateVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfSurrogateVm").finish_non_exhaustive()
    }
}

impl HvfSurrogateVm {
    /// Acquire a surrogate process from the pool, complete the protocol
    /// handshake, and create its VM.
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        let process = get_hvf_surrogate_process_manager()
            .and_then(|m| m.get_surrogate_process())
            .map_err(|e| CreateVmError::SurrogateProcess(format!("{e}")))?;
        let reader = process
            .socket()
            .try_clone()
            .map_err(|e| CreateVmError::SurrogateProcess(format!("failed to clone socket: {e}")))?;
        let writer = process
            .socket()
            .try_clone()
            .map_err(|e| CreateVmError::SurrogateProcess(format!("failed to clone socket: {e}")))?;

        let vm = Self {
            _process: process,
            writer: Arc::new(Mutex::new(writer)),
            reader: Mutex::new(reader),
        };

        match vm.request(&Request::Hello {
            version: PROTO_VERSION,
        }) {
            Ok(Response::Hello { version }) if version == PROTO_VERSION => {}
            other => {
                return Err(CreateVmError::SurrogateProcess(format!(
                    "surrogate handshake failed: {other:?}"
                )));
            }
        }
        vm.request(&Request::CreateVm)
            .and_then(expect_ok)
            .map_err(CreateVmError::CreateVmFd)?;
        Ok(vm)
    }

    /// The shared frame writer, handed to the interrupt handle so it can
    /// send `Request::Cancel` concurrently with in-flight requests.
    pub(crate) fn cancel_writer(&self) -> Arc<Mutex<UnixStream>> {
        Arc::clone(&self.writer)
    }

    /// Send a request and wait for its response.
    fn request(&self, req: &Request) -> std::result::Result<Response, HypervisorError> {
        {
            let mut writer = self.writer.lock().map_err(|_| {
                HypervisorError::HvfSurrogateError("surrogate socket lock poisoned".into())
            })?;
            proto::write_frame(&mut *writer, req).map_err(|e| {
                HypervisorError::HvfSurrogateError(format!("failed to send request: {e}"))
            })?;
        }
        let mut reader = self.reader.lock().map_err(|_| {
            HypervisorError::HvfSurrogateError("surrogate socket lock poisoned".into())
        })?;
        proto::read_frame::<Response>(&mut *reader)
            .map_err(|e| {
                HypervisorError::HvfSurrogateError(format!("failed to read response: {e}"))
            })?
            .ok_or_else(|| {
                HypervisorError::HvfSurrogateError("surrogate closed the connection".into())
            })
    }
}

impl Drop for HvfSurrogateVm {
    fn drop(&mut self) {
        // Best-effort: destroy the VM so the surrogate returns to its idle
        // state and can be reused by another sandbox. The response is read
        // to keep the stream in sync for the next client of this pooled
        // process.
        let _ = self.request(&Request::DestroyVm);
    }
}

/// Extract `Response::Ok`, mapping `Err`/unexpected responses to a
/// [`HypervisorError`].
fn expect_ok(resp: Response) -> std::result::Result<(), HypervisorError> {
    match resp {
        Response::Ok => Ok(()),
        Response::Err(e) => Err(HypervisorError::HvfSurrogateError(e)),
        other => Err(HypervisorError::HvfSurrogateError(format!(
            "unexpected response: {other:?}"
        ))),
    }
}

impl VirtualMachine for HvfSurrogateVm {
    unsafe fn map_memory(
        &mut self,
        (slot, region): (u32, &crate::mem::memory_region::MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError> {
        let perms = Perms {
            read: region
                .flags
                .contains(crate::mem::memory_region::MemoryRegionFlags::READ),
            write: region
                .flags
                .contains(crate::mem::memory_region::MemoryRegionFlags::WRITE),
            exec: region
                .flags
                .contains(crate::mem::memory_region::MemoryRegionFlags::EXECUTE),
        };
        let (backing, size, gpa) = region.surrogate_backing();
        self.request(&Request::MapMemory {
            slot,
            gpa,
            size,
            perms,
            backing,
        })
        .and_then(expect_ok)
        .map_err(MapMemoryError::Hypervisor)
    }

    fn unmap_memory(
        &mut self,
        (slot, region): (u32, &crate::mem::memory_region::MemoryRegion),
    ) -> std::result::Result<(), UnmapMemoryError> {
        self.request(&Request::UnmapMemory {
            slot,
            gpa: region.guest_region.start as u64,
            size: (region.guest_region.end - region.guest_region.start) as u64,
        })
        .and_then(expect_ok)
        .map_err(UnmapMemoryError::Hypervisor)
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        #[cfg(feature = "trace_guest")]
        let _ = tc;
        match self.request(&Request::RunVcpu) {
            Ok(Response::Exit(exit)) => Ok(exit.into()),
            Ok(Response::Err(e)) => {
                Err(RunVcpuError::Unknown(HypervisorError::HvfSurrogateError(e)))
            }
            Ok(other) => Err(RunVcpuError::Unknown(HypervisorError::HvfSurrogateError(
                format!("unexpected response: {other:?}"),
            ))),
            Err(e) => Err(RunVcpuError::Unknown(e)),
        }
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        match self.request(&Request::GetRegs) {
            Ok(Response::Regs(regs)) => Ok(regs.as_ref().into()),
            Ok(Response::Err(e)) => Err(RegisterError::GetRegs(
                HypervisorError::HvfSurrogateError(e),
            )),
            Ok(other) => Err(RegisterError::GetRegs(HypervisorError::HvfSurrogateError(
                format!("unexpected response: {other:?}"),
            ))),
            Err(e) => Err(RegisterError::GetRegs(e)),
        }
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        self.request(&Request::SetRegs(Box::new(regs.into())))
            .and_then(expect_ok)
            .map_err(RegisterError::SetRegs)
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        match self.request(&Request::GetFpu) {
            Ok(Response::Fpu(fpu)) => Ok(fpu.as_ref().into()),
            Ok(Response::Err(e)) => {
                Err(RegisterError::GetFpu(HypervisorError::HvfSurrogateError(e)))
            }
            Ok(other) => Err(RegisterError::GetFpu(HypervisorError::HvfSurrogateError(
                format!("unexpected response: {other:?}"),
            ))),
            Err(e) => Err(RegisterError::GetFpu(e)),
        }
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        self.request(&Request::SetFpu(Box::new(fpu.into())))
            .and_then(expect_ok)
            .map_err(RegisterError::SetFpu)
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        match self.request(&Request::GetSregs) {
            Ok(Response::Sregs(sregs)) => Ok(sregs.into()),
            Ok(Response::Err(e)) => Err(RegisterError::GetSregs(
                HypervisorError::HvfSurrogateError(e),
            )),
            Ok(other) => Err(RegisterError::GetSregs(HypervisorError::HvfSurrogateError(
                format!("unexpected response: {other:?}"),
            ))),
            Err(e) => Err(RegisterError::GetSregs(e)),
        }
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        self.request(&Request::SetSregs(sregs.into()))
            .and_then(expect_ok)
            .map_err(RegisterError::SetSregs)
    }

    fn debug_regs(
        &self,
    ) -> std::result::Result<crate::hypervisor::regs::CommonDebugRegs, RegisterError> {
        todo!("debug registers are not supported on aarch64")
    }

    fn set_debug_regs(
        &self,
        _drs: &crate::hypervisor::regs::CommonDebugRegs,
    ) -> std::result::Result<(), RegisterError> {
        todo!("debug registers are not supported on aarch64")
    }

    fn can_reset_vcpu(&self) -> bool {
        true
    }

    fn reset_vcpu(&mut self) -> std::result::Result<(), ResetVcpuError> {
        // HVF has no "vcpu init" operation like KVM's KVM_ARM_VCPU_INIT;
        // the surrogate emulates it (`core::Vm::reset_vcpu`). Special
        // registers are applied separately by the caller (`apply_sregs`).
        self.request(&Request::ResetVcpu)
            .and_then(expect_ok)
            .map_err(ResetVcpuError::Hypervisor)
    }
}
