#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonFpu {
    pub(crate) v: [u128; 32],
    pub(crate) fpsr: u32,
    pub(crate) fpcr: u32,
}
