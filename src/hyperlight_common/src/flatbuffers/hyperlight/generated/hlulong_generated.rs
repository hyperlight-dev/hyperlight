// automatically generated by the FlatBuffers compiler, do not modify
// @generated
extern crate alloc;
extern crate flatbuffers;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::mem;

use self::flatbuffers::{EndianScalar, Follow};
use super::*;
pub enum hlulongOffset {}
#[derive(Copy, Clone, PartialEq)]

pub struct hlulong<'a> {
    pub _tab: flatbuffers::Table<'a>,
}

impl<'a> flatbuffers::Follow<'a> for hlulong<'a> {
    type Inner = hlulong<'a>;
    #[inline]
    unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
        unsafe {
            Self {
                _tab: flatbuffers::Table::new(buf, loc),
            }
        }
    }
}

impl<'a> hlulong<'a> {
    pub const VT_VALUE: flatbuffers::VOffsetT = 4;

    #[inline]
    pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
        hlulong { _tab: table }
    }
    #[allow(unused_mut)]
    pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr, A: flatbuffers::Allocator + 'bldr>(
        _fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
        args: &'args hlulongArgs,
    ) -> flatbuffers::WIPOffset<hlulong<'bldr>> {
        let mut builder = hlulongBuilder::new(_fbb);
        builder.add_value(args.value);
        builder.finish()
    }

    #[inline]
    pub fn value(&self) -> u64 {
        // Safety:
        // Created from valid Table for this object
        // which contains a valid value in this slot
        unsafe { self._tab.get::<u64>(hlulong::VT_VALUE, Some(0)).unwrap() }
    }
}

impl flatbuffers::Verifiable for hlulong<'_> {
    #[inline]
    fn run_verifier(
        v: &mut flatbuffers::Verifier,
        pos: usize,
    ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
        use self::flatbuffers::Verifiable;
        v.visit_table(pos)?
            .visit_field::<u64>("value", Self::VT_VALUE, false)?
            .finish();
        Ok(())
    }
}
pub struct hlulongArgs {
    pub value: u64,
}
impl<'a> Default for hlulongArgs {
    #[inline]
    fn default() -> Self {
        hlulongArgs { value: 0 }
    }
}

pub struct hlulongBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
    fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
    start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
}
impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> hlulongBuilder<'a, 'b, A> {
    #[inline]
    pub fn add_value(&mut self, value: u64) {
        self.fbb_.push_slot::<u64>(hlulong::VT_VALUE, value, 0);
    }
    #[inline]
    pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>) -> hlulongBuilder<'a, 'b, A> {
        let start = _fbb.start_table();
        hlulongBuilder {
            fbb_: _fbb,
            start_: start,
        }
    }
    #[inline]
    pub fn finish(self) -> flatbuffers::WIPOffset<hlulong<'a>> {
        let o = self.fbb_.end_table(self.start_);
        flatbuffers::WIPOffset::new(o.value())
    }
}

impl core::fmt::Debug for hlulong<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut ds = f.debug_struct("hlulong");
        ds.field("value", &self.value());
        ds.finish()
    }
}
