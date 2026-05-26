#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonRegisters {
    pub(crate) x: [u64; 31],
    pub(crate) sp: u64,
    pub(crate) pc: u64,
    pub(crate) pstate: u64,
}
