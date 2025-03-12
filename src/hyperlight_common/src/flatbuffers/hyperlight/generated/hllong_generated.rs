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
pub enum hllongOffset {}
#[derive(Copy, Clone, PartialEq)]

pub struct hllong<'a> {
    pub _tab: flatbuffers::Table<'a>,
}

impl<'a> flatbuffers::Follow<'a> for hllong<'a> {
    type Inner = hllong<'a>;
    #[inline]
    unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
        unsafe {
            Self {
                _tab: flatbuffers::Table::new(buf, loc),
            }
        }
    }
}

impl<'a> hllong<'a> {
    pub const VT_VALUE: flatbuffers::VOffsetT = 4;

    #[inline]
    pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
        hllong { _tab: table }
    }
    #[allow(unused_mut)]
    pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr, A: flatbuffers::Allocator + 'bldr>(
        _fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
        args: &'args hllongArgs,
    ) -> flatbuffers::WIPOffset<hllong<'bldr>> {
        let mut builder = hllongBuilder::new(_fbb);
        builder.add_value(args.value);
        builder.finish()
    }

    #[inline]
    pub fn value(&self) -> i64 {
        // Safety:
        // Created from valid Table for this object
        // which contains a valid value in this slot
        unsafe { self._tab.get::<i64>(hllong::VT_VALUE, Some(0)).unwrap() }
    }
}

impl flatbuffers::Verifiable for hllong<'_> {
    #[inline]
    fn run_verifier(
        v: &mut flatbuffers::Verifier,
        pos: usize,
    ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
        use self::flatbuffers::Verifiable;
        v.visit_table(pos)?
            .visit_field::<i64>("value", Self::VT_VALUE, false)?
            .finish();
        Ok(())
    }
}
pub struct hllongArgs {
    pub value: i64,
}
impl<'a> Default for hllongArgs {
    #[inline]
    fn default() -> Self {
        hllongArgs { value: 0 }
    }
}

pub struct hllongBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
    fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
    start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
}
impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> hllongBuilder<'a, 'b, A> {
    #[inline]
    pub fn add_value(&mut self, value: i64) {
        self.fbb_.push_slot::<i64>(hllong::VT_VALUE, value, 0);
    }
    #[inline]
    pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>) -> hllongBuilder<'a, 'b, A> {
        let start = _fbb.start_table();
        hllongBuilder {
            fbb_: _fbb,
            start_: start,
        }
    }
    #[inline]
    pub fn finish(self) -> flatbuffers::WIPOffset<hllong<'a>> {
        let o = self.fbb_.end_table(self.start_);
        flatbuffers::WIPOffset::new(o.value())
    }
}

impl core::fmt::Debug for hllong<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut ds = f.debug_struct("hllong");
        ds.field("value", &self.value());
        ds.finish()
    }
}
