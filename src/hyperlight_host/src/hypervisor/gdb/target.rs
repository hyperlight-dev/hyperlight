// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::sync::Arc;

use crossbeam_channel::TryRecvError;
use gdbstub::arch::Arch;
use gdbstub::common::Signal;
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps, SingleThreadSingleStep,
    SingleThreadSingleStepOps,
};
#[cfg(target_arch = "x86_64")]
use gdbstub::target::ext::breakpoints::HwBreakpointOps;
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwBreakpoint, SwBreakpoint, SwBreakpointOps,
};
use gdbstub::target::ext::section_offsets::{Offsets, SectionOffsets};
use gdbstub::target::{Target, TargetError, TargetResult};
#[cfg(target_arch = "aarch64")]
use gdbstub_arch::aarch64::AArch64 as GdbTargetArch;
#[cfg(target_arch = "x86_64")]
use gdbstub_arch::x86::X86_64_SSE as GdbTargetArch;

use super::{DebugCommChannel, DebugMsg, DebugResponse, GdbTargetError};
use crate::hypervisor::InterruptHandle;
use crate::hypervisor::regs::{CommonFpu, CommonRegisters};

/// Gdbstub target used by the gdbstub crate to provide GDB protocol implementation
pub(crate) struct HyperlightSandboxTarget {
    /// Hypervisor communication channels
    hyp_conn: DebugCommChannel<DebugMsg, DebugResponse>,
    /// Interrupt handle for the vCPU thread
    interrupt_handle: Option<Arc<dyn InterruptHandle>>,
}

impl HyperlightSandboxTarget {
    pub(crate) fn new(hyp_conn: DebugCommChannel<DebugMsg, DebugResponse>) -> Self {
        HyperlightSandboxTarget {
            hyp_conn,
            interrupt_handle: None,
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

    /// Set the interrupt handle for the vCPU thread
    pub(crate) fn set_interrupt_handle(&mut self, handle: Arc<dyn InterruptHandle>) {
        self.interrupt_handle = Some(handle);
    }

    /// Waits for a response over the communication channel
    pub(crate) fn recv(&self) -> Result<DebugResponse, GdbTargetError> {
        self.hyp_conn.recv()
    }

    /// Sends an event to the Hypervisor that tells it to resume vCPU execution
    /// Note: The method waits for a confirmation message
    pub(crate) fn resume_vcpu(&mut self) -> Result<(), GdbTargetError> {
        tracing::info!("Resume vCPU execution");

        match self.send_command(DebugMsg::Continue)? {
            DebugResponse::Continue => Ok(()),
            DebugResponse::NotAllowed => {
                tracing::error!("Resume is not allowed in the current target state");
                Ok(())
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(GdbTargetError::UnexpectedMessage)
            }
        }
    }

    /// Non-Blocking check for a response over the communication channel
    pub(crate) fn try_recv(&self) -> Result<DebugResponse, TryRecvError> {
        self.hyp_conn.try_recv()
    }

    /// Sends an event to the Hypervisor that tells it to disable debugging
    /// and continue executing
    /// Note: The method waits for a confirmation message
    pub(crate) fn disable_debug(&mut self) -> Result<(), GdbTargetError> {
        tracing::info!("Disable debugging and resume execution");

        match self.send_command(DebugMsg::DisableDebug)? {
            DebugResponse::DisableDebug => Ok(()),
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(GdbTargetError::UnexpectedError)
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(GdbTargetError::UnexpectedMessage)
            }
        }
    }

    /// Interrupts the vCPU execution
    pub(crate) fn interrupt_vcpu(&mut self) -> bool {
        if let Some(handle) = &self.interrupt_handle {
            handle.kill_from_debugger();
            true
        } else {
            tracing::warn!("No interrupt handle set, cannot interrupt vCPU");

            false
        }
    }
}

impl Target for HyperlightSandboxTarget {
    type Arch = GdbTargetArch;
    type Error = GdbTargetError;

    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn support_section_offsets(
        &mut self,
    ) -> Option<gdbstub::target::ext::section_offsets::SectionOffsetsOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadBase for HyperlightSandboxTarget {
    fn read_addrs(
        &mut self,
        gva: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        tracing::debug!("Read addr: {:X} len: {:X}", gva, data.len());

        match self.send_command(DebugMsg::ReadAddr(gva, data.len()))? {
            DebugResponse::ReadAddr(v) => {
                data.copy_from_slice(&v);

                Ok(v.len())
            }
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn write_addrs(
        &mut self,
        gva: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        tracing::debug!("Write addr: {:X} len: {:X}", gva, data.len());
        let v = Vec::from(data);

        match self.send_command(DebugMsg::WriteAddr(gva, v))? {
            DebugResponse::WriteAddr => Ok(()),
            DebugResponse::NotAllowed => {
                tracing::error!("Action not allowed at this time, crash might have occurred");
                // This is a consequence of the target crashing or being in an invalid state
                // we cannot continue execution, but we can still read registers and memory
                Ok(())
            }
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        tracing::debug!("Read regs");

        match self.send_command(DebugMsg::ReadRegisters)? {
            DebugResponse::ReadRegisters(boxed_regs) => {
                let (read_regs, read_fpu) = boxed_regs.as_ref();
                #[cfg(target_arch = "x86_64")]
                {
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

                    regs.xmm = read_fpu.xmm.map(u128::from_le_bytes);
                    regs.mxcsr = read_fpu.mxcsr;
                }
                #[cfg(target_arch = "aarch64")]
                {
                    regs.x = read_regs.x;
                    regs.sp = read_regs.sp;
                    regs.pc = read_regs.pc;
                    regs.cpsr = read_regs.pstate as u32;
                    regs.v = read_fpu.v;
                    regs.fpcr = read_fpu.fpcr;
                    regs.fpsr = read_fpu.fpsr;
                }

                Ok(())
            }
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(TargetError::NonFatal)
            }

            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        tracing::debug!("Write regs");

        #[cfg(target_arch = "x86_64")]
        let common_regs = CommonRegisters {
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

        #[cfg(target_arch = "x86_64")]
        let mut xmm = [[0u8; 16]; 16];
        #[cfg(target_arch = "x86_64")]
        for (i, &reg) in regs.xmm.iter().enumerate() {
            xmm[i] = reg.to_le_bytes();
        }

        #[cfg(target_arch = "x86_64")]
        let common_fpu = CommonFpu {
            xmm,
            mxcsr: regs.mxcsr,
            ..Default::default()
        };

        #[cfg(target_arch = "aarch64")]
        let common_regs = CommonRegisters {
            x: regs.x,
            sp: regs.sp,
            pc: regs.pc,
            pstate: u64::from(regs.cpsr),
        };

        #[cfg(target_arch = "aarch64")]
        let common_fpu = CommonFpu {
            v: regs.v,
            fpcr: regs.fpcr,
            fpsr: regs.fpsr,
        };

        match self.send_command(DebugMsg::WriteRegisters(Box::new((
            common_regs,
            common_fpu,
        ))))? {
            DebugResponse::WriteRegisters => Ok(()),
            DebugResponse::NotAllowed => {
                tracing::error!("Action not allowed at this time, crash might have occurred");
                // This is a consequence of the target crashing or being in an invalid state
                // we cannot continue execution, but we can still read registers and memory
                Ok(())
            }
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl SectionOffsets for HyperlightSandboxTarget {
    fn get_section_offsets(&mut self) -> Result<Offsets<<Self::Arch as Arch>::Usize>, Self::Error> {
        tracing::debug!("Get section offsets");

        match self.send_command(DebugMsg::GetCodeSectionOffset)? {
            DebugResponse::GetCodeSectionOffset(text) => Ok(Offsets::Segments {
                text_seg: text,
                data_seg: None,
            }),
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(GdbTargetError::UnexpectedError)
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(GdbTargetError::UnexpectedMessage)
            }
        }
    }
}

impl Breakpoints for HyperlightSandboxTarget {
    #[cfg(target_arch = "x86_64")]
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<'_, Self>> {
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
        tracing::debug!("Add hw breakpoint at address {:X}", addr);

        match self.send_command(DebugMsg::AddHwBreakpoint(addr))? {
            DebugResponse::AddHwBreakpoint(rsp) => Ok(rsp),
            DebugResponse::NotAllowed => {
                tracing::error!("Action not allowed at this time, crash might have occurred");
                // This is a consequence of the target crashing or being in an invalid state
                // we cannot continue execution, but we can still read registers and memory
                Err(TargetError::NonFatal)
            }
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn remove_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        tracing::debug!("Remove hw breakpoint at address {:X}", addr);

        match self.send_command(DebugMsg::RemoveHwBreakpoint(addr))? {
            DebugResponse::RemoveHwBreakpoint(rsp) => Ok(rsp),
            DebugResponse::NotAllowed => {
                tracing::error!("Action not allowed at this time, crash might have occurred");
                // This is a consequence of the target crashing or being in an invalid state
                // we cannot continue execution, but we can still read registers and memory
                Err(TargetError::NonFatal)
            }
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
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
        tracing::debug!("Add sw breakpoint at address {:X}", addr);

        match self.send_command(DebugMsg::AddSwBreakpoint(addr))? {
            DebugResponse::AddSwBreakpoint(rsp) => Ok(rsp),
            DebugResponse::NotAllowed => {
                tracing::error!("Action not allowed at this time, crash might have occurred");
                // This is a consequence of the target crashing or being in an invalid state
                // we cannot continue execution, but we can still read registers and memory
                Err(TargetError::NonFatal)
            }
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        tracing::debug!("Remove sw breakpoint at address {:X}", addr);

        match self.send_command(DebugMsg::RemoveSwBreakpoint(addr))? {
            DebugResponse::RemoveSwBreakpoint(rsp) => Ok(rsp),
            DebugResponse::NotAllowed => {
                tracing::error!("Action not allowed at this time, crash might have occurred");
                // This is a consequence of the target crashing or being in an invalid state
                // we cannot continue execution, but we can still read registers and memory
                Err(TargetError::NonFatal)
            }
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(TargetError::NonFatal)
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(TargetError::Fatal(GdbTargetError::UnexpectedMessage))
            }
        }
    }
}

impl SingleThreadResume for HyperlightSandboxTarget {
    /// Resumes the execution of the vCPU
    /// Note: We do not handle signals passed to this method
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        tracing::debug!("Resume");
        self.resume_vcpu()
    }
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for HyperlightSandboxTarget {
    /// Steps the vCPU execution by
    /// Note: We do not handle signals passed to this method
    fn step(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        tracing::debug!("Step");
        match self.send_command(DebugMsg::Step)? {
            DebugResponse::Step => Ok(()),
            DebugResponse::ErrorOccurred => {
                tracing::error!("Error occurred");
                Err(GdbTargetError::UnexpectedError)
            }
            DebugResponse::NotAllowed => {
                tracing::error!("Action not allowed at this time, crash might have occurred");
                // This is a consequence of the target crashing or being in an invalid state
                // we cannot continue execution, but we can still read registers and memory
                Ok(())
            }
            msg => {
                tracing::error!("Unexpected message received: {:?}", msg);
                Err(GdbTargetError::UnexpectedMessage)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "aarch64")]
    use gdbstub_arch::aarch64::reg::AArch64CoreRegs;
    #[cfg(target_arch = "x86_64")]
    use gdbstub_arch::x86::reg::X86_64CoreRegs;

    use super::*;

    #[test]
    fn test_gdb_target() {
        let (gdb_conn, hyp_conn) = DebugCommChannel::unbounded();

        let mut target = HyperlightSandboxTarget::new(hyp_conn);

        // Check response to read registers - send the response first to not be blocked
        // by the recv call in the target
        let msg = DebugResponse::ReadRegisters(Box::default());
        let res = gdb_conn.send(msg);
        assert!(res.is_ok());

        #[cfg(target_arch = "aarch64")]
        let mut regs = AArch64CoreRegs::default();
        #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_register_conversion_round_trip() {
        let mut common_regs = CommonRegisters::default();
        for (index, value) in common_regs.x.iter_mut().enumerate() {
            *value = 0x1000 + index as u64;
        }
        common_regs.sp = 0x2000;
        common_regs.pc = 0x3000;
        common_regs.pstate = 0xa000_03c5;

        let mut common_fpu = CommonFpu::default();
        for (index, value) in common_fpu.v.iter_mut().enumerate() {
            *value = 0x4000 + index as u128;
        }
        common_fpu.fpcr = 0x5000;
        common_fpu.fpsr = 0x6000;

        let (gdb_conn, hyp_conn) = DebugCommChannel::unbounded();
        let mut target = HyperlightSandboxTarget::new(hyp_conn);
        gdb_conn
            .send(DebugResponse::ReadRegisters(Box::new((
                common_regs,
                common_fpu,
            ))))
            .unwrap();

        let mut gdb_regs = AArch64CoreRegs::default();
        assert!(target.read_registers(&mut gdb_regs).is_ok());
        assert_eq!(gdb_regs.x, common_regs.x);
        assert_eq!(gdb_regs.sp, common_regs.sp);
        assert_eq!(gdb_regs.pc, common_regs.pc);
        assert_eq!(gdb_regs.cpsr, common_regs.pstate as u32);
        assert_eq!(gdb_regs.v, common_fpu.v);
        assert_eq!(gdb_regs.fpcr, common_fpu.fpcr);
        assert_eq!(gdb_regs.fpsr, common_fpu.fpsr);
        assert!(matches!(gdb_conn.recv().unwrap(), DebugMsg::ReadRegisters));

        gdb_conn.send(DebugResponse::WriteRegisters).unwrap();
        assert!(target.write_registers(&gdb_regs).is_ok());
        let DebugMsg::WriteRegisters(written) = gdb_conn.recv().unwrap() else {
            panic!("unexpected request");
        };
        assert_eq!(written.0, common_regs);
        assert_eq!(written.1, common_fpu);
    }
}
