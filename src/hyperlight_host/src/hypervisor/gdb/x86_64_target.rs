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
    Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps, SwBreakpoint, SwBreakpointOps,
};
use gdbstub::target::ext::section_offsets::{Offsets, SectionOffsets};
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub_arch::x86::X86_64_SSE as GdbTargetArch;

use super::{DebugCommChannel, DebugMsg, DebugResponse, GdbTargetError, X86_64Regs};

/// Gdbstub target used by the gdbstub crate to provide GDB protocol implementation
pub struct HyperlightSandboxTarget {
    /// Hypervisor communication channels
    hyp_conn: DebugCommChannel<DebugMsg, DebugResponse>,
    /// Thread ID
    thread_id: u64,
}

impl HyperlightSandboxTarget {
    pub fn new(hyp_conn: DebugCommChannel<DebugMsg, DebugResponse>, thread_id: u64) -> Self {
        HyperlightSandboxTarget {
            hyp_conn,
            thread_id,
        }
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

    /// Returns the thread ID
    pub fn get_thread_id(&self) -> u64 {
        self.thread_id
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
    /// and continue executing
    /// Note: The method waits for a confirmation message
    pub fn disable_debug(&mut self) -> Result<(), GdbTargetError> {
        log::info!("Disable debugging and resume execution");

        match self.send_command(DebugMsg::DisableDebug)? {
            DebugResponse::DisableDebug => Ok(()),
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(GdbTargetError::UnexpectedError)
            }
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

    fn support_section_offsets(
        &mut self,
    ) -> Option<gdbstub::target::ext::section_offsets::SectionOffsetsOps<Self>> {
        Some(self)
    }
}

impl SingleThreadBase for HyperlightSandboxTarget {
    fn read_addrs(
        &mut self,
        gva: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        log::debug!("Read addr: {:X} len: {:X}", gva, data.len());

        match self.send_command(DebugMsg::ReadAddr(gva, data.len()))? {
            DebugResponse::ReadAddr(v) => {
                data.copy_from_slice(&v);

                Ok(v.len())
            }
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn write_addrs(
        &mut self,
        gva: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        log::debug!("Write addr: {:X} len: {:X}", gva, data.len());
        let v = Vec::from(data);

        match self.send_command(DebugMsg::WriteAddr(gva, v))? {
            DebugResponse::WriteAddr => Ok(()),
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
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
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(TargetError::NonFatal)
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
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
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

impl SectionOffsets for HyperlightSandboxTarget {
    fn get_section_offsets(&mut self) -> Result<Offsets<<Self::Arch as Arch>::Usize>, Self::Error> {
        log::debug!("Get section offsets");

        match self.send_command(DebugMsg::GetCodeSectionOffset)? {
            DebugResponse::GetCodeSectionOffset(text) => Ok(Offsets::Segments {
                text_seg: text,
                data_seg: None,
            }),
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(GdbTargetError::UnexpectedError)
            }
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(GdbTargetError::UnexpectedMessage)
            }
        }
    }
}

impl Breakpoints for HyperlightSandboxTarget {
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<Self>> {
        Some(self)
    }
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
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
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
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
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }
}

impl SwBreakpoint for HyperlightSandboxTarget {
    fn add_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        log::debug!("Add sw breakpoint at address {:X}", addr);

        match self.send_command(DebugMsg::AddSwBreakpoint(addr))? {
            DebugResponse::AddSwBreakpoint(rsp) => Ok(rsp),
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        log::debug!("Remove sw breakpoint at address {:X}", addr);

        match self.send_command(DebugMsg::RemoveSwBreakpoint(addr))? {
            DebugResponse::RemoveSwBreakpoint(rsp) => Ok(rsp),
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }
}

impl SingleThreadResume for HyperlightSandboxTarget {
    /// Resumes the execution of the vCPU
    /// Note: We do not handle signals passed to this method
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        log::debug!("Resume");
        self.resume_vcpu()
    }
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for HyperlightSandboxTarget {
    /// Steps the vCPU execution by
    /// Note: We do not handle signals passed to this method
    fn step(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        log::debug!("Step");
        match self.send_command(DebugMsg::Step)? {
            DebugResponse::Step => Ok(()),
            DebugResponse::ErrorOccurred => {
                log::error!("Error occurred");
                Err(GdbTargetError::UnexpectedError)
            }
            msg => {
                log::error!("Unexpected message received: {:?}", msg);
                Err(GdbTargetError::UnexpectedMessage)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use gdbstub_arch::x86::reg::X86_64CoreRegs;

    use super::*;

    #[test]
    fn test_gdb_target() {
        let (gdb_conn, hyp_conn) = DebugCommChannel::unbounded();

        let mut target = HyperlightSandboxTarget::new(hyp_conn, 0);

        // Check response to read registers - send the response first to not be blocked
        // by the recv call in the target
        let msg = DebugResponse::ReadRegisters(X86_64Regs::default());
        let res = gdb_conn.send(msg);
        assert!(res.is_ok());

        let mut regs = X86_64CoreRegs::default();
        assert!(
            target.read_registers(&mut regs).is_ok(),
            "Failed to read registers"
        );

        // Check response to write registers
        let msg = DebugResponse::WriteRegisters;
        let res = gdb_conn.send(msg);
        assert!(res.is_ok());
        assert!(
            target.write_registers(&regs).is_ok(),
            "Failed to write registers"
        );

        // Check response when the channel is dropped
        drop(gdb_conn);
        assert!(
            target.read_registers(&mut regs).is_err(),
            "Succeeded to read registers when
            expected to fail"
        );
    }
}
