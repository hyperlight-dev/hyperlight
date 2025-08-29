/*
Copyright 2025  The Hyperlight Authors.

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

use std::sync::{Arc, Mutex};

#[cfg(feature = "mem_profile")]
use {
    crate::hypervisor::regs::CommonRegisters,
    crate::mem::layout::SandboxMemoryLayout,
    crate::mem::mgr::SandboxMemoryManager,
    crate::mem::shared_mem::HostSharedMemory,
    crate::{Result, new_error},
    fallible_iterator::FallibleIterator,
    framehop::Unwinder,
    std::io::Write,
};

/// The information that trace collection requires in order to write
/// an accurate trace.
#[derive(Clone)]
pub(crate) struct TraceInfo {
    /// The epoch against which trace events are timed; at least as
    /// early as the creation of the sandbox being traced.
    pub epoch: std::time::Instant,
    /// The frequency of the timestamp counter.
    pub tsc_freq: Option<u64>,
    /// The epoch at which the guest started, if it has started.
    /// This is used to calculate the time spent in the guest relative to the
    /// time when the host started.
    pub guest_start_epoch: Option<std::time::Instant>,
    /// The start guest time, in TSC cycles, for the current guest has a double purpose.
    /// This field is used in two ways:
    /// 1. It contains the TSC value recorded on the host when the guest started.
    ///    This is used to calculate the TSC frequency which is the same on the host and guest.
    ///    The TSC frequency is used to convert TSC values to timestamps in the trace.
    ///    **NOTE**: This is only used until the TSC frequency is calculated, when the first
    ///    records are received.
    /// 2. To store the TSC value at recorded on the guest when the guest started (first record
    ///    received)
    ///    This is used to calculate the records timestamps relative to when guest started.
    pub guest_start_tsc: Option<u64>,
    /// The file to which the trace is being written
    #[allow(dead_code)]
    pub file: Arc<Mutex<std::fs::File>>,
    /// The unwind information for the current guest
    #[allow(dead_code)]
    #[cfg(feature = "mem_profile")]
    pub unwind_module: Arc<dyn crate::mem::exe::UnwindInfo>,
    /// The framehop unwinder for the current guest
    #[cfg(feature = "mem_profile")]
    pub unwinder: framehop::x86_64::UnwinderX86_64<Vec<u8>>,
    /// The framehop cache
    #[cfg(feature = "mem_profile")]
    pub unwind_cache: Arc<Mutex<framehop::x86_64::CacheX86_64>>,
}

impl TraceInfo {
    /// Create a new TraceInfo by saving the current time as the epoch
    /// and generating a random filename.
    pub fn new(
        #[cfg(feature = "mem_profile")] unwind_module: Arc<dyn crate::mem::exe::UnwindInfo>,
    ) -> crate::Result<Self> {
        let mut path = std::env::current_dir()?;
        path.push("trace");

        // create directory if it does not exist
        if !path.exists() {
            std::fs::create_dir(&path)?;
        }
        path.push(uuid::Uuid::new_v4().to_string());
        path.set_extension("trace");

        log::info!("Creating trace file at: {}", path.display());
        println!("Creating trace file at: {}", path.display());

        #[cfg(feature = "mem_profile")]
        let hash = unwind_module.hash();
        #[cfg(feature = "mem_profile")]
        let (unwinder, unwind_cache) = {
            let mut unwinder = framehop::x86_64::UnwinderX86_64::new();
            unwinder.add_module(unwind_module.clone().as_module());
            let cache = framehop::x86_64::CacheX86_64::new();
            (unwinder, Arc::new(Mutex::new(cache)))
        };
        if !hyperlight_guest_tracing::invariant_tsc::has_invariant_tsc() {
            // If the platform does not support invariant TSC, warn the user.
            // On Azure nested virtualization, the TSC invariant bit is not correctly reported, this is a known issue.
            log::warn!(
                "Invariant TSC is not supported on this platform, trace timestamps may be inaccurate"
            );
        }

        let ret = Self {
            epoch: std::time::Instant::now(),
            tsc_freq: None,
            guest_start_epoch: None,
            guest_start_tsc: None,
            file: Arc::new(Mutex::new(std::fs::File::create_new(path)?)),
            #[cfg(feature = "mem_profile")]
            unwind_module,
            #[cfg(feature = "mem_profile")]
            unwinder,
            #[cfg(feature = "mem_profile")]
            unwind_cache,
        };
        /* write a frame identifying the binary */
        #[cfg(feature = "mem_profile")]
        record_trace_frame(&ret, 0, |f| {
            let _ = f.write_all(hash.as_bytes());
        })?;
        Ok(ret)
    }

    /// Calculate the TSC frequency based on the RDTSC instruction on the host.
    pub(crate) fn calculate_tsc_freq(&mut self) -> crate::Result<()> {
        let (start, start_time) = match (
            self.guest_start_tsc.as_ref(),
            self.guest_start_epoch.as_ref(),
        ) {
            (Some(start), Some(start_time)) => (*start, *start_time),
            _ => {
                // If the guest start TSC and time are not set, we use the current time and TSC.
                // This is not ideal, but it allows us to calculate the TSC frequency without
                // failing.
                // This is a fallback mechanism to ensure that we can still calculate, however it
                // should be noted that this may lead to inaccuracies in the TSC frequency.
                // The start time should be already set before running the guest for each sandbox.
                log::error!(
                    "Guest start TSC and time are not set. Calculating TSC frequency will use current time and TSC."
                );
                (
                    hyperlight_guest_tracing::invariant_tsc::read_tsc(),
                    std::time::Instant::now(),
                )
            }
        };

        let end_time = std::time::Instant::now();
        let end = hyperlight_guest_tracing::invariant_tsc::read_tsc();

        let elapsed = end_time.duration_since(start_time).as_secs_f64();
        let tsc_freq = ((end - start) as f64 / elapsed) as u64;

        log::info!("Calculated TSC frequency: {} Hz", tsc_freq);
        self.tsc_freq = Some(tsc_freq);

        Ok(())
    }
}

#[cfg(feature = "mem_profile")]
fn unwind(
    regs: &CommonRegisters,
    mem: &SandboxMemoryManager<HostSharedMemory>,
    trace_info: &TraceInfo,
) -> Result<Vec<u64>> {
    let mut read_stack = |addr| {
        mem.shared_mem
            .read::<u64>((addr - SandboxMemoryLayout::BASE_ADDRESS as u64) as usize)
            .map_err(|_| ())
    };
    let mut cache = trace_info
        .unwind_cache
        .try_lock()
        .map_err(|e| new_error!("could not lock unwinder cache {}\n", e))?;
    let iter = trace_info.unwinder.iter_frames(
        regs.rip,
        framehop::x86_64::UnwindRegsX86_64::new(regs.rip, regs.rsp, regs.rbp),
        &mut *cache,
        &mut read_stack,
    );
    iter.map(|f| Ok(f.address() - mem.layout.get_guest_code_address() as u64))
        .collect()
        .map_err(|e| new_error!("couldn't unwind: {}", e))
}

#[cfg(feature = "mem_profile")]
fn write_stack(out: &mut std::fs::File, stack: &[u64]) {
    let _ = out.write_all(&stack.len().to_ne_bytes());
    for frame in stack {
        let _ = out.write_all(&frame.to_ne_bytes());
    }
}

#[cfg(feature = "mem_profile")]
fn record_trace_frame<F: FnOnce(&mut std::fs::File)>(
    trace_info: &TraceInfo,
    frame_id: u64,
    write_frame: F,
) -> Result<()> {
    let Ok(mut out) = trace_info.file.lock() else {
        return Ok(());
    };
    // frame structure:
    // 16 bytes timestamp
    let now = std::time::Instant::now().saturating_duration_since(trace_info.epoch);
    let _ = out.write_all(&now.as_micros().to_ne_bytes());
    // 8 bytes frame type id
    let _ = out.write_all(&frame_id.to_ne_bytes());
    // frame data
    write_frame(&mut out);
    Ok(())
}

#[cfg(feature = "mem_profile")]
pub(crate) fn handle_trace_memory_alloc(
    regs: &CommonRegisters,
    mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    trace_info: &TraceInfo,
) -> Result<()> {
    let Ok(stack) = unwind(regs, mem_mgr, trace_info) else {
        return Ok(());
    };
    let amt = regs.rax;
    let ptr = regs.rcx;

    record_trace_frame(trace_info, 2u64, |f| {
        let _ = f.write_all(&ptr.to_ne_bytes());
        let _ = f.write_all(&amt.to_ne_bytes());
        write_stack(f, &stack);
    })
}

#[cfg(feature = "mem_profile")]
pub(crate) fn handle_trace_memory_free(
    regs: &CommonRegisters,
    mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    trace_info: &TraceInfo,
) -> Result<()> {
    let Ok(stack) = unwind(regs, mem_mgr, trace_info) else {
        return Ok(());
    };
    let ptr = regs.rcx;

    record_trace_frame(trace_info, 3u64, |f| {
        let _ = f.write_all(&ptr.to_ne_bytes());
        write_stack(f, &stack);
    })
}
