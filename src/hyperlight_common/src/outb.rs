use core::convert::TryFrom;

use anyhow::{anyhow, Error};

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
            0x7F => NoException,
            _ => return Err(anyhow!("Unknown exception code: {:#x}", value)),
        };

        Ok(exception)
    }
}

/// Supported actions when issuing an OUTB actions by Hyperlight.
/// - Log: for logging,
/// - CallFunction: makes a call to a host function,
/// - Abort: aborts the execution of the guest,
/// - DebugPrint: prints a message to the host
pub enum OutBAction {
    Log = 99,
    CallFunction = 101,
    Abort = 102,
    DebugPrint = 103,
}

impl TryFrom<u16> for OutBAction {
    type Error = anyhow::Error;
    fn try_from(val: u16) -> anyhow::Result<Self> {
        match val {
            99 => Ok(OutBAction::Log),
            101 => Ok(OutBAction::CallFunction),
            102 => Ok(OutBAction::Abort),
            103 => Ok(OutBAction::DebugPrint),
            _ => Err(anyhow::anyhow!("Invalid OutBAction value: {}", val)),
        }
    }
}
