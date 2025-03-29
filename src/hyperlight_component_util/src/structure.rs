/// core:sort in the specification
#[derive(Debug, Clone, Copy)]
pub enum CoreSort {
    Func,
    Table,
    Memory,
    Global,
    Type,
    Module,
    Instance,
}

/// sort in the specification
#[derive(Debug, Clone, Copy)]
pub enum Sort {
    Core(CoreSort),
    Func,
    Value,
    Type,
    Component,
    Instance,
}

/// sortidx in the specification
#[derive(Debug, Clone, Copy)]
pub struct SortIdx {
    pub sort: Sort,
    pub idx: u32,
}

/// funcidx in the specification
pub type FuncIdx = u32;
