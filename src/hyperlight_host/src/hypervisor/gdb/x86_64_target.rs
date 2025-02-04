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
use gdbstub::common::Signal;
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps, SingleThreadSingleStep,
    SingleThreadSingleStepOps,
};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps,
};
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub_arch::x86::X86_64_SSE as GdbTargetArch;

use super::{DebugMsg, DebugResponse, DebugCommChannel, GdbTargetError, X86_64Regs};

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

    /// Sends an event to the Hypervisor that tells it to disable debugging
    /// and continue executing until end
    /// Note: The method waits for a confirmation message
    pub fn disable_debug(&mut self) -> Result<(), GdbTargetError> {
        log::info!("Disable debugging and continue until end");

        match self.send_command(DebugMsg::DisableDebug)? {
            DebugResponse::DisableDebug => Ok(()),
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

    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<Self>> {
        Some(self)
    }

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
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        log::debug!("Read regs");

        match self.send_command(DebugMsg::ReadRegisters)? {
            DebugResponse::ReadRegisters(read_regs) => {
                regs.regs[0] = read_regs.rax;
                regs.regs[1] = read_regs.rbp;
                regs.regs[2] = read_regs.rcx;
                regs.regs[3] = read_regs.rdx;
                regs.regs[4] = read_regs.rsi;
                regs.regs[5] = read_regs.rdi;
                regs.regs[6] = read_regs.rbp;
                regs.regs[7] = read_regs.rsp;
                regs.regs[8] = read_regs.r8;
                regs.regs[9] = read_regs.r9;
                regs.regs[10] = read_regs.r10;
                regs.regs[11] = read_regs.r11;
                regs.regs[12] = read_regs.r12;
                regs.regs[13] = read_regs.r13;
                regs.regs[14] = read_regs.r14;
                regs.regs[15] = read_regs.r15;
                regs.rip = read_regs.rip;
                regs.eflags = read_regs.rflags as u32;

                Ok(())
            }

            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        log::debug!("Write regs");

        let regs = X86_64Regs {
            rax: regs.regs[0],
            rbx: regs.regs[1],
            rcx: regs.regs[2],
            rdx: regs.regs[3],
            rsi: regs.regs[4],
            rdi: regs.regs[5],
            rbp: regs.regs[6],
            rsp: regs.regs[7],
            r8: regs.regs[8],
            r9: regs.regs[9],
            r10: regs.regs[10],
            r11: regs.regs[11],
            r12: regs.regs[12],
            r13: regs.regs[13],
            r14: regs.regs[14],
            r15: regs.regs[15],
            rip: regs.rip,
            rflags: u64::from(regs.eflags),
        };

        match self.send_command(DebugMsg::WriteRegisters(regs))? {
            DebugResponse::WriteRegisters => Ok(()),
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
        Some(self)
    }
}

impl Breakpoints for HyperlightSandboxTarget {
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<Self>> {
        Some(self)
    }
}

impl HwBreakpoint for HyperlightSandboxTarget {
    fn add_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        log::debug!("Add hw breakpoint at address {:X}", addr);

        match self.send_command(DebugMsg::AddHwBreakpoint(addr))? {
            DebugResponse::AddHwBreakpoint(rsp) => Ok(rsp),
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn remove_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        log::debug!("Remove hw breakpoint at address {:X}", addr);

        match self.send_command(DebugMsg::RemoveHwBreakpoint(addr))? {
            DebugResponse::RemoveHwBreakpoint(rsp) => Ok(rsp),
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }
}

impl SingleThreadResume for HyperlightSandboxTarget {
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        log::debug!("Resume");
        self.resume_vcpu()
    }
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for HyperlightSandboxTarget {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        assert!(signal.is_none());

        log::debug!("Step");
        match self.send_command(DebugMsg::Step)? {
            DebugResponse::Step => Ok(()),
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(GdbTargetError::UnexpectedMessage)
            }
        }
    }
}
