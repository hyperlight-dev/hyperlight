// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::collections::HashMap;

use super::{
    HandleDebugError, HyperlightVm, RecvDbgMsgError, SendDbgMsgError, VcpuStopReason, VmError,
};
use crate::hypervisor::gdb::arch::{SW_BP, SW_BP_SIZE, valid_sw_breakpoint_address};
#[cfg(target_arch = "aarch64")]
use crate::hypervisor::gdb::arch::{SoftwareStepError, software_step_targets};
use crate::hypervisor::gdb::{
    DebugError, DebugMemoryAccessError, DebugMemoryView, DebugMsg, DebugResponse,
};

#[derive(Debug, Default)]
pub(crate) struct SoftwareBreakpoints(HashMap<u64, Vec<u8>>);

impl SoftwareBreakpoints {
    pub(super) fn contains(&self, gva: u64) -> bool {
        self.0.contains_key(&gva)
    }

    pub(super) fn get(&self, gva: u64) -> Option<&[u8]> {
        self.0.get(&gva).map(Vec::as_slice)
    }

    pub(super) fn insert(&mut self, gva: u64, instruction: Vec<u8>) {
        self.0.insert(gva, instruction);
    }

    pub(super) fn remove(&mut self, gva: u64) {
        self.0.remove(&gva);
    }

    fn addresses(&self) -> Vec<u64> {
        self.0.keys().copied().collect()
    }
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Debug)]
pub(super) struct PendingSoftwareStep {
    origin: u64,
    reinsert_origin: bool,
    targets: Vec<u64>,
    temporary_breakpoints: HashMap<u64, Vec<u8>>,
    report_stop: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessDebugRequestError {
    #[error("Debug is not enabled")]
    DebugNotEnabled,
    #[error("VM operation error: {0}")]
    Vm(#[from] VmError),
    #[error("Debug operation error: {0}")]
    Debug(#[from] DebugError),
    #[error("Software breakpoint address {address:#x} is not {alignment}-byte aligned")]
    UnalignedSwBreakpoint { address: u64, alignment: usize },
    #[error("Address {0:#x} is not a software breakpoint")]
    SwBreakpointNotFound(u64),
    #[cfg(target_arch = "aarch64")]
    #[error("Failed to prepare ARM64 software single-step: {0}")]
    SoftwareStep(#[from] SoftwareStepError),
    #[error("Failed to read memory: {0}")]
    ReadMemory(#[from] DebugMemoryAccessError),
    #[error("Failed to write memory: {0}")]
    WriteMemory(DebugMemoryAccessError),
}

impl HyperlightVm {
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn has_sw_breakpoints(&self) -> bool {
        !self.sw_breakpoints.0.is_empty()
    }

    pub(super) fn handle_debug(
        &mut self,
        mem_mgr: &crate::mem::mgr::SandboxMemoryManager<crate::mem::shared_mem::HostSharedMemory>,
        stop_reason: VcpuStopReason,
    ) -> std::result::Result<(), HandleDebugError> {
        if self.gdb_conn.is_none() {
            return Err(HandleDebugError::DebugNotEnabled);
        }

        let mem_access =
            DebugMemoryView::new(mem_mgr, self.get_mapped_regions().cloned().collect());

        match stop_reason {
            VcpuStopReason::Crash => {
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))?;

                loop {
                    tracing::debug!("Debug wait for event to resume vCPU");
                    let req = self.recv_dbg_msg()?;
                    let mut deny_continue = false;
                    let mut detach = false;

                    let response = match req {
                        DebugMsg::DisableDebug => {
                            detach = true;
                            // Remove software breakpoint state so restore does not reject recovery.
                            #[cfg(target_arch = "aarch64")]
                            match self.process_dbg_request(DebugMsg::DisableDebug, &mem_access) {
                                Ok(response) => response,
                                Err(error) => {
                                    tracing::error!("Failed to clean up after detach: {error}");
                                    DebugResponse::ErrorOccurred
                                }
                            }
                            #[cfg(not(target_arch = "aarch64"))]
                            DebugResponse::DisableDebug
                        }
                        DebugMsg::Continue => {
                            deny_continue = true;
                            DebugResponse::NotAllowed
                        }
                        DebugMsg::Step => {
                            deny_continue = true;
                            DebugResponse::NotAllowed
                        }
                        DebugMsg::AddHwBreakpoint(_)
                        | DebugMsg::AddSwBreakpoint(_)
                        | DebugMsg::RemoveHwBreakpoint(_)
                        | DebugMsg::RemoveSwBreakpoint(_)
                        | DebugMsg::WriteAddr(_, _)
                        | DebugMsg::WriteRegisters(_) => DebugResponse::NotAllowed,
                        _ => match self.process_dbg_request(req, &mem_access) {
                            Ok(response) => response,
                            Err(ProcessDebugRequestError::ReadMemory(
                                DebugMemoryAccessError::TranslateGuestAddress(_),
                            ))
                            | Err(ProcessDebugRequestError::Debug(DebugError::TranslateGva(_))) => {
                                DebugResponse::ErrorOccurred
                            }
                            #[cfg(target_arch = "aarch64")]
                            Err(error @ ProcessDebugRequestError::SoftwareStep(_)) => {
                                tracing::error!("{error}");
                                DebugResponse::NotAllowed
                            }
                            Err(e) => {
                                tracing::error!("Error processing debug request: {:?}", e);
                                return Err(HandleDebugError::ProcessRequest(e));
                            }
                        },
                    };

                    self.send_dbg_msg(response)?;

                    if deny_continue {
                        self.send_dbg_msg(DebugResponse::VcpuStopped(VcpuStopReason::Crash))?;
                    }

                    if detach {
                        break;
                    }
                }
            }
            _ => {
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))?;

                loop {
                    tracing::debug!("Debug wait for event to resume vCPU");
                    let req = self.recv_dbg_msg()?;
                    let resume_requested = matches!(&req, DebugMsg::Continue);
                    let resume_requested = resume_requested || matches!(&req, DebugMsg::Step);
                    let disable_requested = matches!(&req, DebugMsg::DisableDebug);

                    let response = match self.process_dbg_request(req, &mem_access) {
                        Ok(response) => response,
                        Err(ProcessDebugRequestError::ReadMemory(
                            DebugMemoryAccessError::TranslateGuestAddress(_),
                        ))
                        | Err(ProcessDebugRequestError::Debug(DebugError::TranslateGva(_))) => {
                            DebugResponse::ErrorOccurred
                        }
                        #[cfg(target_arch = "aarch64")]
                        Err(error) if resume_requested => {
                            tracing::error!("{error}");
                            DebugResponse::NotAllowed
                        }
                        Err(error) if disable_requested => {
                            tracing::error!("{error}");
                            DebugResponse::ErrorOccurred
                        }
                        Err(e) => return Err(HandleDebugError::ProcessRequest(e)),
                    };

                    let resume = matches!(
                        response,
                        DebugResponse::Continue | DebugResponse::DisableDebug
                    );
                    let resume = resume || matches!(response, DebugResponse::Step);
                    let denied_resume =
                        resume_requested && matches!(response, DebugResponse::NotAllowed);
                    self.send_dbg_msg(response)?;

                    if denied_resume {
                        self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))?;
                    }
                    if resume {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub(super) fn handle_initial_debug_stop(
        &mut self,
        mem_mgr: &crate::mem::mgr::SandboxMemoryManager<crate::mem::shared_mem::HostSharedMemory>,
    ) -> std::result::Result<(), HandleDebugError> {
        if self.initial_debug_stop_pending {
            self.initial_debug_stop_pending = false;
            self.handle_debug(mem_mgr, VcpuStopReason::Initial)?;
        }
        Ok(())
    }

    pub(crate) fn process_dbg_request(
        &mut self,
        req: DebugMsg,
        mem_access: &DebugMemoryView<'_>,
    ) -> std::result::Result<DebugResponse, ProcessDebugRequestError> {
        if self.gdb_conn.is_none() {
            return Err(ProcessDebugRequestError::DebugNotEnabled);
        }

        match req {
            DebugMsg::AddHwBreakpoint(addr) => Ok(DebugResponse::AddHwBreakpoint(
                self.vm
                    .add_hw_breakpoint(addr)
                    .inspect_err(|e| tracing::error!("Failed to add hw breakpoint: {:?}", e))
                    .is_ok(),
            )),
            DebugMsg::AddSwBreakpoint(addr) => Ok(DebugResponse::AddSwBreakpoint(
                self.add_sw_breakpoint(addr, mem_access)
                    .inspect_err(|e| tracing::error!("Failed to add sw breakpoint: {:?}", e))
                    .is_ok(),
            )),
            DebugMsg::Continue => {
                #[cfg(target_arch = "aarch64")]
                {
                    let pc = self.vm.regs().map_err(VmError::Register)?.pc;
                    if self.sw_breakpoints.contains(pc) {
                        self.begin_software_step(false, mem_access)?;
                    }
                }
                #[cfg(target_arch = "x86_64")]
                self.vm
                    .set_single_step(false)
                    .inspect_err(|e| tracing::error!("Failed to continue execution: {:?}", e))?;
                Ok(DebugResponse::Continue)
            }
            DebugMsg::DisableDebug => {
                #[cfg(target_arch = "aarch64")]
                self.cancel_software_step(mem_access)?;
                for address in self.sw_breakpoints.addresses() {
                    self.remove_sw_breakpoint(address, mem_access)?;
                }
                self.vm
                    .set_debug(false)
                    .inspect_err(|e| tracing::error!("Failed to disable debugging: {:?}", e))?;
                Ok(DebugResponse::DisableDebug)
            }
            DebugMsg::GetCodeSectionOffset => Ok(DebugResponse::GetCodeSectionOffset(
                mem_access.code_section_offset(),
            )),
            DebugMsg::ReadAddr(addr, len) => {
                let mut data = vec![0u8; len];
                self.read_addrs(addr, &mut data, mem_access)
                    .inspect_err(|e| tracing::error!("Failed to read from address: {:?}", e))?;
                Ok(DebugResponse::ReadAddr(data))
            }
            DebugMsg::ReadRegisters => {
                let regs = self.vm.regs().map_err(VmError::Register)?;
                let fpu = self.vm.fpu().map_err(VmError::Register)?;
                Ok(DebugResponse::ReadRegisters(Box::new((regs, fpu))))
            }
            DebugMsg::RemoveHwBreakpoint(addr) => Ok(DebugResponse::RemoveHwBreakpoint(
                self.vm
                    .remove_hw_breakpoint(addr)
                    .inspect_err(|e| tracing::error!("Failed to remove hw breakpoint: {:?}", e))
                    .is_ok(),
            )),
            DebugMsg::RemoveSwBreakpoint(addr) => Ok(DebugResponse::RemoveSwBreakpoint(
                self.remove_sw_breakpoint(addr, mem_access)
                    .inspect_err(|e| tracing::error!("Failed to remove sw breakpoint: {:?}", e))
                    .is_ok(),
            )),
            DebugMsg::Step => {
                #[cfg(target_arch = "aarch64")]
                self.begin_software_step(true, mem_access)?;
                #[cfg(target_arch = "x86_64")]
                self.vm.set_single_step(true).inspect_err(|e| {
                    tracing::error!("Failed to enable step instruction: {:?}", e)
                })?;
                Ok(DebugResponse::Step)
            }
            DebugMsg::WriteAddr(addr, data) => {
                self.write_addrs(addr, &data, mem_access)
                    .inspect_err(|e| tracing::error!("Failed to write to address: {:?}", e))?;
                Ok(DebugResponse::WriteAddr)
            }
            DebugMsg::WriteRegisters(boxed_regs) => {
                let (regs, fpu) = boxed_regs.as_ref();
                self.vm.set_regs(regs).map_err(VmError::Register)?;
                self.vm.set_fpu(fpu).map_err(VmError::Register)?;
                Ok(DebugResponse::WriteRegisters)
            }
        }
    }

    pub(crate) fn recv_dbg_msg(&mut self) -> std::result::Result<DebugMsg, RecvDbgMsgError> {
        let gdb_conn = self
            .gdb_conn
            .as_mut()
            .ok_or(RecvDbgMsgError::DebugNotEnabled)?;
        Ok(gdb_conn.recv()?)
    }

    pub(crate) fn send_dbg_msg(
        &mut self,
        cmd: DebugResponse,
    ) -> std::result::Result<(), SendDbgMsgError> {
        tracing::debug!("Sending {:?}", cmd);
        let gdb_conn = self
            .gdb_conn
            .as_mut()
            .ok_or(SendDbgMsgError::DebugNotEnabled)?;
        Ok(gdb_conn.send(cmd)?)
    }

    fn read_addrs(
        &mut self,
        mut gva: u64,
        mut data: &mut [u8],
        mem_access: &DebugMemoryView<'_>,
    ) -> std::result::Result<(), ProcessDebugRequestError> {
        tracing::debug!("Read addr: {:X} len: {:X}", gva, data.len());

        while !data.is_empty() {
            let gpa = self.vm.translate_gva(gva)?;
            let read_len = std::cmp::min(
                data.len(),
                page_size::get() - (gpa as usize & (page_size::get() - 1)),
            );
            mem_access.read(&mut data[..read_len], gpa)?;
            data = &mut data[read_len..];
            gva += read_len as u64;
        }

        Ok(())
    }

    fn write_addrs(
        &mut self,
        mut gva: u64,
        mut data: &[u8],
        mem_access: &DebugMemoryView<'_>,
    ) -> std::result::Result<(), ProcessDebugRequestError> {
        tracing::debug!("Write addr: {:X} len: {:X}", gva, data.len());

        while !data.is_empty() {
            let gpa = self.vm.translate_gva(gva)?;
            let write_len = std::cmp::min(
                data.len(),
                page_size::get() - (gpa as usize & (page_size::get() - 1)),
            );
            mem_access
                .write(&data[..write_len], gpa)
                .map_err(ProcessDebugRequestError::WriteMemory)?;
            mem_access
                .flush_host_instruction_cache(gpa, write_len)
                .map_err(ProcessDebugRequestError::WriteMemory)?;
            data = &data[write_len..];
            gva += write_len as u64;
        }

        self.vm.sync_instruction_cache()?;
        Ok(())
    }

    fn add_sw_breakpoint(
        &mut self,
        gva: u64,
        mem_access: &DebugMemoryView<'_>,
    ) -> std::result::Result<(), ProcessDebugRequestError> {
        if !valid_sw_breakpoint_address(gva) {
            return Err(ProcessDebugRequestError::UnalignedSwBreakpoint {
                address: gva,
                alignment: SW_BP_SIZE,
            });
        }
        if self.sw_breakpoints.contains(gva) {
            return Ok(());
        }

        let mut saved_instruction = vec![0; SW_BP_SIZE];
        self.read_addrs(gva, &mut saved_instruction, mem_access)?;
        if let Err(error) = self
            .write_addrs(gva, &SW_BP, mem_access)
            .and_then(|()| self.vm.register_sw_breakpoint(gva).map_err(Into::into))
        {
            if let Err(rollback_error) = self.write_addrs(gva, &saved_instruction, mem_access) {
                tracing::error!(
                    "Failed to roll back software breakpoint {gva:#x}: {rollback_error}"
                );
            }
            self.vm.unregister_sw_breakpoint(gva)?;
            return Err(error);
        }
        self.sw_breakpoints.insert(gva, saved_instruction);
        Ok(())
    }

    fn remove_sw_breakpoint(
        &mut self,
        gva: u64,
        mem_access: &DebugMemoryView<'_>,
    ) -> std::result::Result<(), ProcessDebugRequestError> {
        let saved_instruction = self
            .sw_breakpoints
            .get(gva)
            .ok_or(ProcessDebugRequestError::SwBreakpointNotFound(gva))?
            .to_vec();
        if let Err(error) = self
            .write_addrs(gva, &saved_instruction, mem_access)
            .and_then(|()| self.vm.unregister_sw_breakpoint(gva).map_err(Into::into))
        {
            if let Err(rollback_error) = self.write_addrs(gva, &SW_BP, mem_access) {
                tracing::error!(
                    "Failed to roll back software breakpoint removal at {gva:#x}: {rollback_error}"
                );
            }
            self.vm.register_sw_breakpoint(gva)?;
            return Err(error);
        }
        self.sw_breakpoints.remove(gva);
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn begin_software_step(
        &mut self,
        report_stop: bool,
        mem_access: &DebugMemoryView<'_>,
    ) -> std::result::Result<(), ProcessDebugRequestError> {
        if self.pending_software_step.is_some() {
            self.cancel_software_step(mem_access)?;
        }

        let regs = self.vm.regs().map_err(VmError::Register)?;
        let pc = regs.pc;
        let saved_instruction = if let Some(instruction) = self.sw_breakpoints.get(pc) {
            instruction.to_vec()
        } else {
            let mut instruction = vec![0; SW_BP_SIZE];
            self.read_addrs(pc, &mut instruction, mem_access)?;
            instruction
        };
        let instruction = u32::from_le_bytes(
            saved_instruction
                .as_slice()
                .try_into()
                .expect("ARM64 instructions are four bytes"),
        );
        let targets = software_step_targets(pc, instruction, &regs)?;

        let mut temporary_breakpoints = HashMap::new();
        for &target in &targets {
            if self.sw_breakpoints.contains(target) {
                continue;
            }
            let mut target_instruction = vec![0; SW_BP_SIZE];
            self.read_addrs(target, &mut target_instruction, mem_access)?;
            temporary_breakpoints.insert(target, target_instruction);
        }

        let mut installed_targets = Vec::new();
        for &target in temporary_breakpoints.keys() {
            let result = self
                .write_addrs(target, &SW_BP, mem_access)
                .and_then(|()| self.vm.register_sw_breakpoint(target).map_err(Into::into));
            if let Err(error) = result {
                installed_targets.push(target);
                self.rollback_temporary_breakpoints(
                    &installed_targets,
                    &temporary_breakpoints,
                    mem_access,
                );
                return Err(error);
            }
            installed_targets.push(target);
        }

        let reinsert_origin = self.sw_breakpoints.contains(pc);
        if reinsert_origin {
            let result = self
                .write_addrs(pc, &saved_instruction, mem_access)
                .and_then(|()| self.vm.unregister_sw_breakpoint(pc).map_err(Into::into));
            if let Err(error) = result {
                if let Err(rollback_error) = self.write_addrs(pc, &SW_BP, mem_access) {
                    tracing::error!(
                        "Failed to roll back software-step origin {pc:#x}: {rollback_error}"
                    );
                }
                if let Err(rollback_error) = self.vm.register_sw_breakpoint(pc) {
                    tracing::error!(
                        "Failed to re-register software-step origin {pc:#x}: {rollback_error}"
                    );
                }
                self.rollback_temporary_breakpoints(
                    &installed_targets,
                    &temporary_breakpoints,
                    mem_access,
                );
                return Err(error);
            }
        }

        self.pending_software_step = Some(PendingSoftwareStep {
            origin: pc,
            reinsert_origin,
            targets,
            temporary_breakpoints,
            report_stop,
        });
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn rollback_temporary_breakpoints(
        &mut self,
        targets: &[u64],
        temporary_breakpoints: &HashMap<u64, Vec<u8>>,
        mem_access: &DebugMemoryView<'_>,
    ) {
        for &target in targets {
            if let Some(instruction) = temporary_breakpoints.get(&target) {
                if let Err(error) = self.write_addrs(target, instruction, mem_access) {
                    tracing::error!(
                        "Failed to roll back temporary breakpoint {target:#x}: {error}"
                    );
                }
                if let Err(error) = self.vm.unregister_sw_breakpoint(target) {
                    tracing::error!(
                        "Failed to unregister temporary breakpoint {target:#x}: {error}"
                    );
                }
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn cancel_software_step(
        &mut self,
        mem_access: &DebugMemoryView<'_>,
    ) -> std::result::Result<(), ProcessDebugRequestError> {
        let Some(pending) = self.pending_software_step.clone() else {
            return Ok(());
        };
        self.restore_software_step(&pending, mem_access)?;
        self.pending_software_step = None;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn restore_software_step(
        &mut self,
        pending: &PendingSoftwareStep,
        mem_access: &DebugMemoryView<'_>,
    ) -> std::result::Result<(), ProcessDebugRequestError> {
        for (target, instruction) in &pending.temporary_breakpoints {
            self.write_addrs(*target, instruction, mem_access)?;
            self.vm.unregister_sw_breakpoint(*target)?;
        }
        if pending.reinsert_origin {
            self.write_addrs(pending.origin, &SW_BP, mem_access)?;
            self.vm.register_sw_breakpoint(pending.origin)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub(super) fn cancel_pending_software_step(
        &mut self,
        mem_mgr: &crate::mem::mgr::SandboxMemoryManager<crate::mem::shared_mem::HostSharedMemory>,
    ) -> std::result::Result<(), ProcessDebugRequestError> {
        let mapped_regions = self.get_mapped_regions().cloned().collect();
        let mem_access = DebugMemoryView::new(mem_mgr, mapped_regions);
        self.cancel_software_step(&mem_access)
    }

    #[cfg(target_arch = "aarch64")]
    pub(super) fn finish_software_step(
        &mut self,
        mem_mgr: &crate::mem::mgr::SandboxMemoryManager<crate::mem::shared_mem::HostSharedMemory>,
    ) -> std::result::Result<Option<VcpuStopReason>, ProcessDebugRequestError> {
        let pending = self
            .pending_software_step
            .clone()
            .expect("software-step completion requires pending state");
        let pc = self.vm.regs().map_err(VmError::Register)?.pc;
        if !pending.targets.contains(&pc) {
            return Ok(Some(VcpuStopReason::SwBp));
        }

        let mapped_regions = self.get_mapped_regions().cloned().collect();
        let mem_access = DebugMemoryView::new(mem_mgr, mapped_regions);
        self.restore_software_step(&pending, &mem_access)?;
        self.pending_software_step = None;

        if self.sw_breakpoints.contains(pc) {
            Ok(Some(VcpuStopReason::SwBp))
        } else if pending.report_stop {
            Ok(Some(VcpuStopReason::DoneStep))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SoftwareBreakpoints;

    #[test]
    fn software_breakpoint_storage_preserves_full_instruction() {
        let mut breakpoints = SoftwareBreakpoints::default();
        breakpoints.insert(0x4000, vec![0x11, 0x22, 0x33, 0x44]);

        assert_eq!(
            breakpoints.get(0x4000),
            Some([0x11, 0x22, 0x33, 0x44].as_slice())
        );
    }
}
