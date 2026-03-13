/*
Copyright 2025 The Hyperlight Authors.

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

use core::convert::TryFrom;

use anyhow::{Error, anyhow};

/// Exception codes for the x86 architecture.
/// These are helpful to identify the type of exception that occurred
/// together with OutBAction::Abort.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Exception {
    DivideByZero = 0,
    Debug = 1,
    NonMaskableInterrupt = 2,
    Breakpoint = 3,
    Overflow = 4,
    BoundRangeExceeded = 5,
    InvalidOpcode = 6,
    DeviceNotAvailable = 7,
    DoubleFault = 8,
    CoprocessorSegmentOverrun = 9,
    InvalidTSS = 10,
    SegmentNotPresent = 11,
    StackSegmentFault = 12,
    GeneralProtectionFault = 13,
    PageFault = 14,
    Reserved = 15,
    X87FloatingPointException = 16,
    AlignmentCheck = 17,
    MachineCheck = 18,
    SIMDFloatingPointException = 19,
    VirtualizationException = 20,
    SecurityException = 30,
    NoException = 0xFF,
}

impl TryFrom<u8> for Exception {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use Exception::*;
        let exception = match value {
            0 => DivideByZero,
            1 => Debug,
            2 => NonMaskableInterrupt,
            3 => Breakpoint,
            4 => Overflow,
            5 => BoundRangeExceeded,
            6 => InvalidOpcode,
            7 => DeviceNotAvailable,
            8 => DoubleFault,
            9 => CoprocessorSegmentOverrun,
            10 => InvalidTSS,
            11 => SegmentNotPresent,
            12 => StackSegmentFault,
            13 => GeneralProtectionFault,
            14 => PageFault,
            15 => Reserved,
            16 => X87FloatingPointException,
            17 => AlignmentCheck,
            18 => MachineCheck,
            19 => SIMDFloatingPointException,
            20 => VirtualizationException,
            30 => SecurityException,
            0xFF => NoException,
            _ => return Err(anyhow!("Unknown exception code: {:#x}", value)),
        };

        Ok(exception)
    }
}

/// Supported actions when issuing an OUTB actions by Hyperlight.
/// These are handled by the sandbox-level outb dispatcher.
/// - Log: for logging,
/// - CallFunction: makes a call to a host function,
/// - Abort: aborts the execution of the guest,
/// - DebugPrint: prints a message to the host
/// - TraceBatch: reports a batch of spans and events from the guest
/// - TraceMemoryAlloc: records memory allocation events
/// - TraceMemoryFree: records memory deallocation events
pub enum OutBAction {
    Log = 99,
    CallFunction = 101,
    Abort = 102,
    DebugPrint = 103,
    #[cfg(feature = "trace_guest")]
    TraceBatch = 104,
    #[cfg(feature = "mem_profile")]
    TraceMemoryAlloc = 105,
    #[cfg(feature = "mem_profile")]
    TraceMemoryFree = 106,
}

/// IO-port actions intercepted at the hypervisor level (in `run_vcpu`)
/// before they ever reach the sandbox outb handler.  These are split
/// from [`OutBAction`] so the outb handler does not need unreachable
/// match arms for ports it can never see.
pub enum VmAction {
    /// IO port for PV timer configuration. The guest writes a 32-bit
    /// LE value representing the desired timer period in microseconds.
    /// A value of 0 disables the timer.
    PvTimerConfig = 107,
    /// IO port the guest writes to signal "I'm done" to the host.
    /// This replaces the `hlt` instruction for halt signaling so that
    /// KVM's in-kernel LAPIC (which absorbs HLT exits) does not interfere
    /// with hyperlight's halt-based guest-host protocol.
    Halt = 108,
}

impl TryFrom<u16> for OutBAction {
    type Error = anyhow::Error;
    fn try_from(val: u16) -> anyhow::Result<Self> {
        match val {
            99 => Ok(OutBAction::Log),
            101 => Ok(OutBAction::CallFunction),
            102 => Ok(OutBAction::Abort),
            103 => Ok(OutBAction::DebugPrint),
            #[cfg(feature = "trace_guest")]
            104 => Ok(OutBAction::TraceBatch),
            #[cfg(feature = "mem_profile")]
            105 => Ok(OutBAction::TraceMemoryAlloc),
            #[cfg(feature = "mem_profile")]
            106 => Ok(OutBAction::TraceMemoryFree),
            _ => Err(anyhow::anyhow!("Invalid OutBAction value: {}", val)),
        }
    }
}

impl TryFrom<u16> for VmAction {
    type Error = anyhow::Error;
    fn try_from(val: u16) -> anyhow::Result<Self> {
        match val {
            107 => Ok(VmAction::PvTimerConfig),
            108 => Ok(VmAction::Halt),
            _ => Err(anyhow::anyhow!("Invalid VmAction value: {}", val)),
        }
    }
}
