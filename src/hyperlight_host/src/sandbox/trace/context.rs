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
use std::time::{Duration, Instant, SystemTime};

use hyperlight_common::outb::OutBAction;
use hyperlight_guest_tracing::{Events, Spans};
use opentelemetry::global::BoxedSpan;
use opentelemetry::trace::{Span as _, TraceContextExt, Tracer as _};
use opentelemetry::{Context, KeyValue, global};
use tracing::span::{EnteredSpan, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::hypervisor::regs::CommonRegisters;
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
use crate::{HyperlightError, Result, new_error};

/// Type that helps get the data from the guest provided the registers and memory access
struct TraceBatch {
    pub guest_start_tsc: u64,
    pub spans: Spans,
    pub events: Events,
}

impl TryFrom<(&CommonRegisters, &SandboxMemoryManager<HostSharedMemory>)> for TraceBatch {
    type Error = HyperlightError;
    fn try_from(
        (regs, mem_mgr): (&CommonRegisters, &SandboxMemoryManager<HostSharedMemory>),
    ) -> Result<Self> {
        let magic_no = regs.r8;
        let guest_start_tsc = regs.r9;
        let spans_ptr = regs.r10 as usize;
        let events_ptr = regs.r11 as usize;

        if magic_no != OutBAction::TraceBatch as u64 {
            return Err(new_error!("A TraceBatch is not present"));
        }

        // Transmute spans_ptr to Spans type
        let mut spans = vec![0u8; std::mem::size_of::<Spans>()];
        mem_mgr
            .shared_mem
            .copy_to_slice(&mut spans, spans_ptr - SandboxMemoryLayout::BASE_ADDRESS)
            .map_err(|e| {
                new_error!(
                    "Failed to copy guest trace batch from guest memory to host: {:?}",
                    e
                )
            })?;

        let spans: Spans = unsafe {
            let raw = spans.as_slice() as *const _ as *const Spans;
            raw.read_unaligned()
        };

        // Transmute events_ptr to Events type
        let mut events = vec![0u8; std::mem::size_of::<Events>()];
        mem_mgr
            .shared_mem
            .copy_to_slice(&mut events, events_ptr - SandboxMemoryLayout::BASE_ADDRESS)
            .map_err(|e| {
                new_error!(
                    "Failed to copy guest trace batch from guest memory to host: {:?}",
                    e
                )
            })?;

        let events: Events = unsafe {
            let raw = events.as_slice() as *const _ as *const Events;
            raw.read_unaligned()
        };

        Ok(TraceBatch {
            guest_start_tsc,
            spans,
            events,
        })
    }
}

/// This structure handles the guest tracing information.
pub struct TraceContext {
    host_spans: Vec<EnteredSpan>,
    guest_spans: HashMap<u64, BoxedSpan>,
    in_host_call: bool,

    // Lazily initialized members
    start_wall: Option<SystemTime>,
    /// The epoch at which the call into the guest started, if it has started.
    /// This is used to calculate the time spent in the guest relative to the
    /// time when the call into the guest was first made.
    start_instant: Option<Instant>,
    /// The start guest time, in TSC cycles, for the current guest measured on the host.
    /// It contains the TSC value recorded on the host before a call is made into the guest.
    /// This is used to calculate the TSC frequency which is the same on the host and guest.
    /// The TSC frequency is used to convert TSC values to timestamps in the trace.
    /// **NOTE**: This is only used until the TSC frequency is calculated, when the first
    /// records are received.
    start_tsc: Option<u64>,
    /// The frequency of the timestamp counter.
    tsc_freq: Option<u64>,
    current_parent_ctx: Option<Context>,
}

impl TraceContext {
    /// Initialize with current context
    pub fn new() -> Self {
        if !hyperlight_guest_tracing::invariant_tsc::has_invariant_tsc() {
            // If the platform does not support invariant TSC, warn the user.
            // On Azure nested virtualization, the TSC invariant bit is not correctly reported, this is a known issue.
            log::warn!(
                "Invariant TSC is not supported on this platform, trace timestamps may be inaccurate"
            );
        }

        let current_ctx = Span::current().context();

        let span = tracing::trace_span!("call-to-guest");
        let _ = span.set_parent(current_ctx);
        let entered = span.entered();

        Self {
            host_spans: vec![entered],
            guest_spans: HashMap::new(),
            in_host_call: false,

            start_wall: None,
            start_instant: None,
            start_tsc: None,
            tsc_freq: None,
            current_parent_ctx: None,
        }
    }

    /// Calculate the frequency of the TimeStamp Counter.
    /// This is done by:
    /// - first reading a timestamp and an `Instant`
    /// - secondly reading another timestamp and `Instant`
    /// - calculate the frequency based on the `Duration` between
    ///   the two `Instant`s read.
    fn calculate_tsc_freq(&mut self) -> Result<()> {
        let (start, start_time) = match (self.start_tsc.as_ref(), self.start_instant.as_ref()) {
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

    /// Calculate timestamp relative to wall time stored on host
    fn calculate_guest_time_relative_to_host(
        &self,
        guest_start_tsc: u64,
        tsc: u64,
    ) -> Result<SystemTime> {
        // Should never fail as it is extracted after it is set
        let tsc_freq = self.tsc_freq.ok_or(new_error!("TSC frequency not set"))?;

        // Number of cycles relative to guest start
        let rel_cycles = tsc.saturating_sub(guest_start_tsc);

        // Number of micro seconds from guest start to `tsc` argument
        let rel_start_us = rel_cycles as f64 / tsc_freq as f64 * 1_000_000f64;

        // Final timestamp is calculated by:
        // - starting from the wall time when the sandbox was created
        // - adding the Duration to the guest start
        // - adding the Duration from the guest start to the provided `tsc`
        Ok(self.start_wall.ok_or(new_error!("start_wall not set"))?
            + Duration::from_micros(rel_start_us as u64))
    }

    pub fn handle_trace(
        &mut self,
        regs: &CommonRegisters,
        mem_mgr: &SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        if self.tsc_freq.is_none() {
            self.calculate_tsc_freq()?;
        }

        // Get the guest sent info
        let trace_batch = TraceBatch::try_from((regs, mem_mgr))?;

        let tracer = global::tracer("guest-tracer");
        let mut spans_to_remove = vec![];

        let mut current_active_span = None;

        // Update the spans map
        for s in trace_batch.spans.iter() {
            let start_ts = self
                .calculate_guest_time_relative_to_host(trace_batch.guest_start_tsc, s.start_tsc)?;
            let end_ts = s.end_tsc.map(|tsc| {
                self.calculate_guest_time_relative_to_host(trace_batch.guest_start_tsc, tsc)
            });
            let parent_id = s.parent_id;
            let parent_ctx = if let Some(parent_id) = parent_id {
                if let Some(span) = self.guest_spans.get(&parent_id) {
                    Context::new().with_remote_span_context(span.span_context().clone())
                } else if let Some(parent_ctx) = self.current_parent_ctx.as_ref() {
                    parent_ctx.clone()
                } else {
                    Span::current().context().clone()
                }
            } else if let Some(parent_ctx) = self.current_parent_ctx.as_ref() {
                parent_ctx.clone()
            } else {
                Span::current().context().clone()
            };

            // Get the saved span, modify it and set it back to avoid borrow checker
            let mut span = self.guest_spans.remove(&s.id).unwrap_or_else(|| {
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

            // If we find an end timestamp it means the span has been closed
            // otherwise store it for later
            if let Some(ts) = end_ts {
                span.end_with_timestamp(ts?);
                spans_to_remove.push(s.id);
            } else {
                current_active_span =
                    Some(Context::current().with_remote_span_context(span.span_context().clone()));
            }

            self.guest_spans.insert(s.id, span);
        }

        // Create the events
        for ev in trace_batch.events.iter() {
            let ts =
                self.calculate_guest_time_relative_to_host(trace_batch.guest_start_tsc, ev.tsc)?;
            let mut attributes: Vec<KeyValue> = ev
                .fields
                .iter()
                .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
                .collect();

            attributes.push(KeyValue::new(
                "level",
                tracing::Level::from(ev.level).to_string(),
            ));

            // Add the event to the parent span
            // It should always have a parent span
            if let Some(span) = self.guest_spans.get_mut(&ev.parent_id) {
                span.add_event_with_timestamp(ev.name.to_string(), ts, attributes);
            }
        }

        // Remove the spans that have been closed
        for id in spans_to_remove.into_iter() {
            self.guest_spans.remove(&id);
        }

        if let Some(ctx) = current_active_span {
            self.new_host_trace(ctx);
        };

        Ok(())
    }

    pub(crate) fn setup_guest_trace(&mut self, ctx: Context) {
        if self.start_instant.is_none() {
            crate::debug!("Guest Start Epoch set");
            self.start_wall = Some(SystemTime::now());
            self.start_tsc = Some(hyperlight_guest_tracing::invariant_tsc::read_tsc());
            self.start_instant = Some(std::time::Instant::now());
        }
        self.current_parent_ctx = Some(ctx);
    }

    pub fn new_host_trace(&mut self, ctx: Context) {
        let span = tracing::trace_span!("call-to-host");
        let _ = span.set_parent(ctx);
        let entered = span.entered();
        self.host_spans.push(entered);
        self.in_host_call = true;
    }

    pub fn end_host_trace(&mut self) {
        if self.in_host_call
            && let Some(entered) = self.host_spans.pop()
        {
            entered.exit();
        }
    }
}

impl Drop for TraceContext {
    fn drop(&mut self) {
        for (k, mut v) in self.guest_spans.drain() {
            v.end();
            log::debug!("Dropped guest span with id {}", k);
        }
        while let Some(entered) = self.host_spans.pop() {
            entered.exit();
        }
    }
}
