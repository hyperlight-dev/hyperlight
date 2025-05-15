mod fpu;
mod special_regs;
mod standard_regs;

#[cfg(target_os = "windows")]
use std::collections::HashSet;

pub(crate) use fpu::*;
pub(crate) use special_regs::*;
pub(crate) use standard_regs::*;

#[cfg(target_os = "windows")]
#[derive(Debug, PartialEq)]
pub(crate) enum FromWhpRegisterError {
    MissingRegister(HashSet<i32>),
    InvalidLength(usize),
    InvalidEncoding,
    DuplicateRegister(i32),
    InvalidRegister(i32),
}
