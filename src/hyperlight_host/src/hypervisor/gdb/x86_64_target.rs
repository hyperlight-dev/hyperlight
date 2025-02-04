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

use crossbeam_channel::TryRecvError;
use gdbstub::arch::Arch;
use gdbstub::target::ext::base::singlethread::SingleThreadBase;
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::{Target, TargetResult};
use gdbstub_arch::x86::X86_64_SSE as GdbTargetArch;

use super::{DebugMsg, DebugResponse, DebugCommChannel, GdbTargetError};

/// Gdbstub target used by the gdbstub crate to provide GDB protocol implementation
pub struct HyperlightSandboxTarget {
    /// Hypervisor communication channels
    hyp_conn: DebugCommChannel<DebugMsg, DebugResponse>,
}

impl HyperlightSandboxTarget {
    pub fn new(hyp_conn: DebugCommChannel<DebugMsg, DebugResponse>) -> Self {
        HyperlightSandboxTarget { hyp_conn }
    }

    /// Sends a command over the communication channel and waits for response
    fn send_command(&self, cmd: DebugMsg) -> Result<DebugResponse, GdbTargetError> {
        self.send(cmd)?;

        // Wait for response
        self.recv()
    }

    /// Sends a command over the communication channel
    fn send(&self, ev: DebugMsg) -> Result<(), GdbTargetError> {
        self.hyp_conn.send(ev)
    }

    /// Waits for a response over the communication channel
    pub fn recv(&self) -> Result<DebugResponse, GdbTargetError> {
        self.hyp_conn.recv()
    }

    /// Non-Blocking check for a response over the communication channel
    pub fn try_recv(&self) -> Result<DebugResponse, TryRecvError> {
        self.hyp_conn.try_recv()
    }

    /// Sends an event to the Hypervisor that tells it to resume vCPU execution
    /// Note: The method waits for a confirmation message
    pub fn resume_vcpu(&mut self) -> Result<(), GdbTargetError> {
        log::info!("Resume vCPU execution");

        match self.send_command(DebugMsg::Continue)? {
            DebugResponse::Continue => Ok(()),
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(GdbTargetError::UnexpectedMessage)
            }
        }
    }

}

impl Target for HyperlightSandboxTarget {
    type Arch = GdbTargetArch;
    type Error = GdbTargetError;

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }
}

impl SingleThreadBase for HyperlightSandboxTarget {
    fn read_addrs(
        &mut self,
        gva: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        log::debug!("Read addr: {:X} len: {:X}", gva, data.len());

        unimplemented!()
    }

    fn write_addrs(
        &mut self,
        gva: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        log::debug!("Write addr: {:X} len: {:X}", gva, data.len());

        unimplemented!()
    }

    fn read_registers(
        &mut self,
        _regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        log::debug!("Read regs");

        unimplemented!()
    }

    fn write_registers(
        &mut self,
        _regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        log::debug!("Write regs");

        unimplemented!()
    }
}
