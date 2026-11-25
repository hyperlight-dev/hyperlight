// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::collections::HashMap;

use hyperlight_common::vmem::PAGE_SIZE;

use super::{
    HandleDebugError, HyperlightVm, RecvDbgMsgError, SendDbgMsgError, VcpuStopReason, VmError,
};
use crate::hypervisor::gdb::arch::{SW_BP, SW_BP_SIZE, valid_sw_breakpoint_address};
use crate::hypervisor::gdb::{
    DebugError, DebugMemoryAccessError, DebugMemoryView, DebugMsg, DebugResponse,
};

#[derive(Debug, Default)]
pub(crate) struct SoftwareBreakpoints(HashMap<u64, Vec<u8>>);

impl SoftwareBreakpoints {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn clear(&mut self) {
        self.0.clear();
    }

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
    #[error("Failed to read memory: {0}")]
    ReadMemory(#[from] DebugMemoryAccessError),
    #[error("Failed to write memory: {0}")]
    WriteMemory(DebugMemoryAccessError),
}

impl HyperlightVm {
    pub(crate) fn has_sw_breakpoints(&self) -> bool {
        !self.sw_breakpoints.is_empty()
    }

    /// Discard software debug state when poisoned guest memory will be replaced.
    pub(crate) fn discard_software_breakpoints(&mut self) {
        self.sw_breakpoints.clear();
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
                            #[cfg(target_arch = "aarch64")]
                            match self.process_dbg_request(DebugMsg::DisableDebug, &mem_access) {
                                Ok(response) => response,
                                Err(error) => {
                                    tracing::error!("Failed to clean up after detach: {error}");
                                    self.vm
                                        .set_debug(false)
                                        .map_err(ProcessDebugRequestError::from)?;
                                    self.discard_software_breakpoints();
                                    DebugResponse::DisableDebug
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
                        #[cfg(target_arch = "aarch64")]
                        Err(error) if resume_requested => {
                            tracing::error!("{error}");
                            DebugResponse::NotAllowed
                        }
                        Err(ProcessDebugRequestError::ReadMemory(
                            DebugMemoryAccessError::TranslateGuestAddress(_),
                        ))
                        | Err(ProcessDebugRequestError::Debug(DebugError::TranslateGva(_))) => {
                            DebugResponse::ErrorOccurred
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
                self.vm
                    .set_single_step(false)
                    .inspect_err(|e| tracing::error!("Failed to continue execution: {:?}", e))?;
                Ok(DebugResponse::Continue)
            }
            DebugMsg::DisableDebug => {
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
            let gpa = self.vm.translate_gva(gva, mem_access)?;
            let read_len = std::cmp::min(data.len(), PAGE_SIZE - (gva as usize & (PAGE_SIZE - 1)));
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

        let mut written = false;
        let result = (|| {
            while !data.is_empty() {
                let gpa = self.vm.translate_gva(gva, mem_access)?;
                let write_len =
                    std::cmp::min(data.len(), PAGE_SIZE - (gva as usize & (PAGE_SIZE - 1)));
                mem_access
                    .write(&data[..write_len], gpa)
                    .map_err(ProcessDebugRequestError::WriteMemory)?;
                written = true;
                mem_access
                    .flush_host_instruction_cache(gpa, write_len)
                    .map_err(ProcessDebugRequestError::WriteMemory)?;
                data = &data[write_len..];
                gva += write_len as u64;
            }
            Ok(())
        })();
        if written {
            self.vm.sync_instruction_cache()?;
        }
        result
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
        if let Err(error) = self.write_addrs(gva, &SW_BP, mem_access) {
            if let Err(rollback_error) = self.write_addrs(gva, &saved_instruction, mem_access) {
                tracing::error!(
                    "Failed to roll back software breakpoint {gva:#x}: {rollback_error}"
                );
            }
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
        if let Err(error) = self.write_addrs(gva, &saved_instruction, mem_access) {
            if let Err(rollback_error) = self.write_addrs(gva, &SW_BP, mem_access) {
                tracing::error!(
                    "Failed to roll back software breakpoint removal at {gva:#x}: {rollback_error}"
                );
            }
            return Err(error);
        }
        self.sw_breakpoints.remove(gva);
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub(super) fn clear_single_step(
        &mut self,
    ) -> std::result::Result<(), ProcessDebugRequestError> {
        if self.gdb_conn.is_none() {
            return Ok(());
        }
        self.vm.set_single_step(false)?;
        Ok(())
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

    #[cfg(all(any(kvm, mshv3), target_arch = "aarch64"))]
    mod memory_access_tests {
        use hyperlight_common::vmem::PAGE_SIZE;

        use super::super::*;
        use crate::hypervisor::gdb::DebugCommChannel;
        use crate::mem::layout::SandboxMemoryLayout;
        use crate::mem::mgr::SandboxMemoryManager;
        use crate::mem::shared_mem::{ExclusiveSharedMemory, HostSharedMemory};
        use crate::sandbox::SandboxConfiguration;
        use crate::sandbox::snapshot::{NextAction, SnapshotMemoryBacking};

        fn noncontiguous_pages() -> (HyperlightVm, SandboxMemoryManager<HostSharedMemory>, u64) {
            let mut config = SandboxConfiguration::default();
            config.set_scratch_size(config.get_scratch_size().next_multiple_of(page_size::get()));
            let layout = SandboxMemoryLayout::new(config, PAGE_SIZE).unwrap();
            let snapshot = crate::sandbox::snapshot::memory::tests::flat_memory(
                &vec![0; page_size::get()],
                &[0; PAGE_SIZE],
                SandboxMemoryLayout::BASE_ADDRESS.next_multiple_of(page_size::get()) as u64,
                hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size()),
            );
            let memory = SandboxMemoryManager::new(
                layout,
                SnapshotMemoryBacking::from_snapshot(std::sync::Arc::new(snapshot)).unwrap(),
                ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap(),
                NextAction::None,
            );
            let (memory, guest_memory) = memory.build().unwrap();
            let (_debugger, connection) = DebugCommChannel::unbounded();
            let mut vm = HyperlightVm::new(
                guest_memory.shared_mem,
                guest_memory.scratch_mem,
                guest_memory.layout.get_pt_base_gpa(),
                guest_memory.next_action,
                0,
                page_size::get(),
                &config,
                Some(connection),
                #[cfg(feature = "mem_profile")]
                crate::sandbox::trace::MemTraceInfo::new(crate::mem::exe::LoadInfo::dummy().info)
                    .unwrap(),
            )
            .unwrap();
            let root = memory.first_free_scratch_gpa();
            let access = DebugMemoryView::new(&memory, Vec::new());
            let mut tables = [0; 4 * PAGE_SIZE];
            for level in 0..3 {
                let entry = (root + (level as u64 + 1) * PAGE_SIZE as u64) | 3;
                tables[level * PAGE_SIZE..level * PAGE_SIZE + 8]
                    .copy_from_slice(&entry.to_le_bytes());
            }
            for page in 0..3 {
                let entry = (root + (4 + 2 * page) as u64 * PAGE_SIZE as u64) | 3;
                let offset = 3 * PAGE_SIZE + (page + 1) * 8;
                tables[offset..offset + 8].copy_from_slice(&entry.to_le_bytes());
                access
                    .write(&vec![page as u8 + 1; PAGE_SIZE], entry & !0xfff)
                    .unwrap();
            }
            for page in [5, 7] {
                access
                    .write(&[0xee; PAGE_SIZE], root + page * PAGE_SIZE as u64)
                    .unwrap();
            }
            access.write(&tables, root).unwrap();
            let registers = vm.get_snapshot_sregs().unwrap();
            vm.apply_sregs(root, &registers).unwrap();
            (vm, memory, root)
        }

        #[test]
        fn reads_translate_each_noncontiguous_guest_page() {
            let (mut vm, memory, _) = noncontiguous_pages();
            let access = DebugMemoryView::new(&memory, Vec::new());
            let address = (2 * PAGE_SIZE - 3) as u64;
            let DebugResponse::ReadAddr(data) = vm
                .process_dbg_request(DebugMsg::ReadAddr(address, PAGE_SIZE + 8), &access)
                .unwrap()
            else {
                panic!("missing memory read response");
            };
            assert_eq!(&data[..3], &[1; 3]);
            assert!(data[3..3 + PAGE_SIZE].iter().all(|&byte| byte == 2));
            assert_eq!(&data[3 + PAGE_SIZE..], &[3; 5]);
        }

        #[test]
        fn writes_preserve_gaps_between_noncontiguous_guest_pages() {
            let (mut vm, memory, root) = noncontiguous_pages();
            let access = DebugMemoryView::new(&memory, Vec::new());
            let address = (2 * PAGE_SIZE - 3) as u64;
            assert!(matches!(
                vm.process_dbg_request(
                    DebugMsg::WriteAddr(address, vec![0xab; PAGE_SIZE + 8]),
                    &access,
                )
                .unwrap(),
                DebugResponse::WriteAddr
            ));
            let mut data = [0; PAGE_SIZE];
            for page in [5, 7] {
                access
                    .read(&mut data, root + page * PAGE_SIZE as u64)
                    .unwrap();
                assert!(data.iter().all(|&byte| byte == 0xee));
            }
            for (page, prefix, suffix) in [(4, PAGE_SIZE - 3, 0), (6, 0, 0), (8, 0, PAGE_SIZE - 5)]
            {
                access
                    .read(&mut data, root + page * PAGE_SIZE as u64)
                    .unwrap();
                let original = ((page - 4) / 2 + 1) as u8;
                assert!(data[..prefix].iter().all(|&byte| byte == original));
                assert!(
                    data[prefix..PAGE_SIZE - suffix]
                        .iter()
                        .all(|&byte| byte == 0xab)
                );
                assert!(
                    data[PAGE_SIZE - suffix..]
                        .iter()
                        .all(|&byte| byte == original)
                );
            }
        }

        #[test]
        fn resume_leaves_breakpoint_removal_to_the_client() {
            let (mut vm, memory, root) = noncontiguous_pages();
            let access = DebugMemoryView::new(&memory, Vec::new());
            let mut regs = vm.vm.regs().unwrap();
            regs.pc = PAGE_SIZE as u64;
            vm.vm.set_regs(&regs).unwrap();
            assert!(matches!(
                vm.process_dbg_request(DebugMsg::AddSwBreakpoint(regs.pc), &access)
                    .unwrap(),
                DebugResponse::AddSwBreakpoint(true)
            ));
            for message in [DebugMsg::Continue, DebugMsg::Step] {
                vm.process_dbg_request(message, &access).unwrap();
                let mut instruction = [0; SW_BP_SIZE];
                access
                    .read(&mut instruction, root + 4 * PAGE_SIZE as u64)
                    .unwrap();
                assert_eq!(instruction, SW_BP);
            }
            assert!(matches!(
                vm.process_dbg_request(DebugMsg::RemoveSwBreakpoint(regs.pc), &access)
                    .unwrap(),
                DebugResponse::RemoveSwBreakpoint(true)
            ));
            let mut instruction = [0; SW_BP_SIZE];
            access
                .read(&mut instruction, root + 4 * PAGE_SIZE as u64)
                .unwrap();
            assert_eq!(instruction, [1; SW_BP_SIZE]);
        }
    }
}
