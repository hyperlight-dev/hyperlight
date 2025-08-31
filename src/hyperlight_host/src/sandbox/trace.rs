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

use std::collections::HashMap;
use std::time::SystemTime;

use hyperlight_common::outb::OutBAction;
use hyperlight_guest_tracing::{Spans, TraceLevel};
use opentelemetry::global::BoxedSpan;
use opentelemetry::trace::{Span as _, TraceContextExt, Tracer as _};
use opentelemetry::{Context, KeyValue, global};
use tracing::span::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;
#[cfg(feature = "mem_profile")]
use {
    crate::mem::mgr::SandboxMemoryManager,
    fallible_iterator::FallibleIterator,
    framehop::Unwinder,
    std::io::Write,
    std::sync::{Arc, Mutex},
};

use super::mem_mgr::MemMgrWrapper;
use crate::hypervisor::arch::X86_64Regs;
use crate::mem::layout::SandboxMemoryLayout;
use crate::sandbox::HostSharedMemory;
use crate::{Result, new_error};

/// The type of trace frame being recorded.
/// This is used to identify the type of frame being recorded in the trace file.
#[cfg(feature = "mem_profile")]
enum TraceFrameType {
    /// A frame that records a memory allocation.
    MemAlloc = 2,
    /// A frame that records a memory free.
    MemFree = 3,
}
/// This structure handles the memory profiling trace information.
#[cfg(feature = "mem_profile")]
struct GuestMemProfileProcessor {
    /// The file to which the trace is being written
    pub file: Arc<Mutex<std::fs::File>>,
    /// The unwind information for the current guest
    #[allow(dead_code)]
    pub unwind_module: Arc<dyn crate::mem::exe::UnwindInfo>,
    /// The framehop unwinder for the current guest
    pub unwinder: framehop::x86_64::UnwinderX86_64<Vec<u8>>,
    /// The framehop cache
    pub unwind_cache: Arc<Mutex<framehop::x86_64::CacheX86_64>>,
}

#[cfg(feature = "mem_profile")]
impl GuestMemProfileProcessor {
    fn new(
        unwind_module: Arc<dyn crate::mem::exe::UnwindInfo>,
        start_instant: std::time::Instant,
    ) -> Result<Self> {
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

        let hash = unwind_module.hash();
        let (unwinder, unwind_cache) = {
            let mut unwinder = framehop::x86_64::UnwinderX86_64::new();
            unwinder.add_module(unwind_module.clone().as_module());
            let cache = framehop::x86_64::CacheX86_64::new();
            (unwinder, Arc::new(Mutex::new(cache)))
        };

        let ret = Self {
            file: Arc::new(Mutex::new(std::fs::File::create_new(path)?)),
            unwind_module,
            unwinder,
            unwind_cache,
        };

        /* write a frame identifying the binary */
        ret.record_trace_frame(start_instant, 0, |f| {
            let _ = f.write_all(hash.as_bytes());
        })?;

        Ok(ret)
    }

    fn unwind(
        &self,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<Vec<u64>> {
        let mut read_stack = |addr| {
            mem_mgr
                .shared_mem
                .read::<u64>((addr - SandboxMemoryLayout::BASE_ADDRESS as u64) as usize)
                .map_err(|_| ())
        };
        let mut cache = self
            .unwind_cache
            .try_lock()
            .map_err(|e| new_error!("could not lock unwinder cache {}\n", e))?;
        let iter = self.unwinder.iter_frames(
            regs.rip,
            framehop::x86_64::UnwindRegsX86_64::new(regs.rip, regs.rsp, regs.rbp),
            &mut *cache,
            &mut read_stack,
        );
        iter.map(|f| Ok(f.address() - mem_mgr.layout.get_guest_code_address() as u64))
            .collect()
            .map_err(|e| new_error!("couldn't unwind: {}", e))
    }

    fn write_stack(&self, out: &mut std::fs::File, stack: &[u64]) {
        let _ = out.write_all(&stack.len().to_ne_bytes());
        for frame in stack {
            let _ = out.write_all(&frame.to_ne_bytes());
        }
    }

    fn record_trace_frame<F: FnOnce(&mut std::fs::File)>(
        &self,
        start_instant: std::time::Instant,
        frame_id: u64,
        write_frame: F,
    ) -> Result<()> {
        let Ok(mut out) = self.file.lock() else {
            return Ok(());
        };
        // frame structure:
        // 16 bytes timestamp
        let now = std::time::Instant::now().saturating_duration_since(start_instant);
        let _ = out.write_all(&now.as_micros().to_ne_bytes());
        // 8 bytes frame type id
        let _ = out.write_all(&frame_id.to_ne_bytes());
        // frame data
        write_frame(&mut out);
        Ok(())
    }

    fn handle_trace(
        &self,
        start_instant: std::time::Instant,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
        trace_identifier: TraceFrameType,
    ) -> Result<()> {
        let Ok(stack) = self.unwind(regs, mem_mgr) else {
            return Ok(());
        };

        let amt = regs.rax;
        let ptr = regs.rcx;

        self.record_trace_frame(start_instant, trace_identifier as u64, |f| {
            let _ = f.write_all(&ptr.to_ne_bytes());
            let _ = f.write_all(&amt.to_ne_bytes());
            self.write_stack(f, &stack);
        })
    }

    fn handle_trace_mem_alloc(
        &self,
        start_instant: std::time::Instant,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        self.handle_trace(start_instant, regs, mem_mgr, TraceFrameType::MemAlloc)
    }

    fn handle_trace_mem_free(
        &self,
        start_instant: std::time::Instant,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        self.handle_trace(start_instant, regs, mem_mgr, TraceFrameType::MemFree)
    }
}

/// This structure handles the guest tracing information.
struct GuestTraceProcessor {
    spans: HashMap<u64, BoxedSpan>,
    /// The frequency of the timestamp counter.
    #[allow(dead_code)]
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
}

impl GuestTraceProcessor {
    pub fn new() -> Self {
        if !hyperlight_guest_tracing::invariant_tsc::has_invariant_tsc() {
            // If the platform does not support invariant TSC, warn the user.
            // On Azure nested virtualization, the TSC invariant bit is not correctly reported, this is a known issue.
            log::warn!(
                "Invariant TSC is not supported on this platform, trace timestamps may be inaccurate"
            );
        }

        Self {
            spans: HashMap::new(),
            tsc_freq: None,
            guest_start_epoch: None,
            guest_start_tsc: None,
        }
    }

    /// Calculate the TSC frequency based on the RDTSC instruction on the host.
    #[allow(dead_code)]
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

    fn guest_info(regs: &X86_64Regs, mem_mgr: &MemMgrWrapper<HostSharedMemory>) -> Result<Spans> {
        let magic_no = regs.r8;
        let spans_ptr = regs.r9 as usize;
        if magic_no != OutBAction::TraceBatch as u64 {
            return Err(new_error!("A TraceBatch is not present"));
        }
        let mut spans = vec![0u8; std::mem::size_of::<hyperlight_guest_tracing::Spans>()];
        mem_mgr
            .as_ref()
            .shared_mem
            .copy_to_slice(&mut spans, spans_ptr - SandboxMemoryLayout::BASE_ADDRESS)
            .map_err(|e| {
                new_error!(
                    "Failed to copy guest trace batch from guest memory to host: {:?}",
                    e
                )
            })?;

        let spans: hyperlight_guest_tracing::Spans = unsafe {
            let raw = spans.as_slice() as *const _ as *const hyperlight_guest_tracing::Spans;
            raw.read_unaligned()
        };

        Ok(spans)
    }

    fn calculate_guest_time_relative_to_host(
        &self,
        start_instant: std::time::Instant,
        start_wall: std::time::SystemTime,
        tsc: u64,
    ) -> SystemTime {
        // Should never fail as it is extracted after it is set
        let tsc_freq = self.tsc_freq.expect("tsc_freq field not set");
        let guest_start_tsc = self.guest_start_tsc.unwrap_or(0);

        // Number of cycles relative to guest start
        let rel_cycles = tsc.saturating_sub(guest_start_tsc);

        // Number of micro seconds from guest start to `tsc` argument
        let rel_start_us = rel_cycles as f64 / tsc_freq as f64 * 1_000_000f64;

        // Time it took from sandbox creation to guest start
        let base = self
            .guest_start_epoch
            .as_ref()
            .unwrap_or(&start_instant)
            .saturating_duration_since(start_instant);

        // Final timestamp is calculated by:
        // - starting from the wall time when the sandbox was created
        // - adding the Duration to the guest start
        // - adding the Duration from the guest start to the provided `tsc`
        start_wall + base + std::time::Duration::from_micros(rel_start_us as u64)
    }

    pub(crate) fn setup_guest_trace(&mut self) {
        if self.guest_start_epoch.is_none() {
            // Store the guest start epoch and cycles to trace the guest execution time
            crate::debug!("KVM - Guest Start Epoch set");
            self.guest_start_epoch = Some(std::time::Instant::now());
            self.guest_start_tsc = Some(hyperlight_guest_tracing::invariant_tsc::read_tsc());
        }
    }

    pub(crate) fn handle_trace_batch(
        &mut self,
        start_instant: std::time::Instant,
        start_wall: std::time::SystemTime,
        regs: &X86_64Regs,
        mem: &MemMgrWrapper<HostSharedMemory>,
    ) -> crate::Result<()> {
        // Check if the TSC frequency was already calculated
        if self.tsc_freq.is_none() {
            self.calculate_tsc_freq()?;

            // After the TSC freq is calculated we no longer need the value of the guest_start_tsc
            // taken on the host, so we'll overwrite it with the guest start time reported by the guest
            self.guest_start_tsc = Some(regs.r10);
        }

        let spans = GuestTraceProcessor::guest_info(regs, mem)?;
        let tracer = global::tracer("guest-tracer");
        let mut spans_to_remove = vec![];

        // Update the spans map
        for s in spans.iter() {
            let start_ts =
                self.calculate_guest_time_relative_to_host(start_instant, start_wall, s.start_tsc);
            let end_ts = s.end_tsc.map(|tsc| {
                self.calculate_guest_time_relative_to_host(start_instant, start_wall, tsc)
            });
            let parent_id = s.parent_id;
            let parent_ctx = if let Some(parent_id) = parent_id {
                if let Some(span) = self.spans.get(&parent_id) {
                    Context::new().with_remote_span_context(span.span_context().clone())
                } else {
                    Span::current().context().clone()
                }
            } else {
                Span::current().context().clone()
            };

            // Get the saved span, modify it and set it back to avoid borrow checker
            let mut span = self.spans.remove(&s.id).unwrap_or_else(|| {
                let mut sb = tracer
                    .span_builder(s.name.to_string())
                    .with_start_time(start_ts);
                sb.attributes = Some(vec![KeyValue::new("target", s.target.to_string())]);
                let mut span = sb.start_with_context(&tracer, &parent_ctx);

                for (k, v) in s.fields.iter() {
                    span.set_attribute(KeyValue::new(
                        k.as_str().to_string(),
                        v.as_str().to_string(),
                    ));
                }

                span
            });

            // Create the events
            for ev in s.events.iter() {
                let ts =
                    self.calculate_guest_time_relative_to_host(start_instant, start_wall, ev.tsc);
                let mut attributes: Vec<KeyValue> = ev
                    .fields
                    .iter()
                    .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
                    .collect();

                attributes.push(KeyValue::new(
                    "level",
                    <TraceLevel as Into<tracing::Level>>::into(ev.level.clone()).to_string(),
                ));

                span.add_event_with_timestamp(ev.name.to_string(), ts, attributes);
            }

            // If we find an end timestamp it means the span has been closed
            // otherwise store it for later
            if let Some(ts) = end_ts {
                span.end_with_timestamp(ts);
                spans_to_remove.push(s.id);
            }

            self.spans.insert(s.id, span);
        }

        // Remove the spans that have been closed
        for id in spans_to_remove.into_iter() {
            self.spans.remove(&id);
        }

        Ok(())
    }
}

/// The information that trace collection requires in order to write
/// an accurate trace.
pub(crate) struct TraceInfo {
    /// The wall time at which the sandbox being traced was created.
    wall: std::time::SystemTime,
    /// The epoch against which trace events are timed; at least as
    /// early as the creation of the sandbox being traced.
    epoch: std::time::Instant,
    trace: GuestTraceProcessor,
    #[cfg(feature = "mem_profile")]
    mem_profile: GuestMemProfileProcessor,
}

impl TraceInfo {
    /// Create a new TraceInfo by saving the current time as the epoch
    /// and generating a random filename.
    pub(crate) fn new(
        #[cfg(feature = "mem_profile")] unwind_module: Arc<dyn crate::mem::exe::UnwindInfo>,
    ) -> crate::Result<Self> {
        let epoch = std::time::Instant::now();
        Ok(Self {
            wall: std::time::SystemTime::now(),
            epoch,
            trace: GuestTraceProcessor::new(),
            #[cfg(feature = "mem_profile")]
            mem_profile: GuestMemProfileProcessor::new(unwind_module, epoch)?,
        })
    }

    /// Setup the guest trace by recording the start epoch and TSC.
    #[inline(always)]
    pub(crate) fn setup_guest_trace(&mut self) {
        self.trace.setup_guest_trace();
    }

    #[inline(always)]
    pub(crate) fn handle_trace_batch(
        &mut self,
        regs: &X86_64Regs,
        mem_mgr: &MemMgrWrapper<HostSharedMemory>,
    ) -> crate::Result<()> {
        self.trace
            .handle_trace_batch(self.epoch, self.wall, regs, mem_mgr)
    }

    #[inline(always)]
    #[cfg(feature = "mem_profile")]
    pub(crate) fn handle_trace_mem_alloc(
        &self,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        self.mem_profile
            .handle_trace_mem_alloc(self.epoch, regs, mem_mgr)
    }

    #[inline(always)]
    #[cfg(feature = "mem_profile")]
    pub(crate) fn handle_trace_mem_free(
        &self,
        regs: &X86_64Regs,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        self.mem_profile
            .handle_trace_mem_free(self.epoch, regs, mem_mgr)
    }
}
