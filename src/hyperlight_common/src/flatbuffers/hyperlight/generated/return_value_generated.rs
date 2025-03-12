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
#[deprecated(
    since = "2.0.0",
    note = "Use associated constants instead. This will no longer be generated in 2021."
)]
pub const ENUM_MIN_RETURN_VALUE: u8 = 0;
#[deprecated(
    since = "2.0.0",
    note = "Use associated constants instead. This will no longer be generated in 2021."
)]
pub const ENUM_MAX_RETURN_VALUE: u8 = 10;
#[deprecated(
    since = "2.0.0",
    note = "Use associated constants instead. This will no longer be generated in 2021."
)]
#[allow(non_camel_case_types)]
pub const ENUM_VALUES_RETURN_VALUE: [ReturnValue; 11] = [
    ReturnValue::NONE,
    ReturnValue::hlint,
    ReturnValue::hluint,
    ReturnValue::hllong,
    ReturnValue::hlulong,
    ReturnValue::hlfloat,
    ReturnValue::hldouble,
    ReturnValue::hlstring,
    ReturnValue::hlbool,
    ReturnValue::hlvoid,
    ReturnValue::hlsizeprefixedbuffer,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct ReturnValue(pub u8);
#[allow(non_upper_case_globals)]
impl ReturnValue {
    pub const NONE: Self = Self(0);
    pub const hlint: Self = Self(1);
    pub const hluint: Self = Self(2);
    pub const hllong: Self = Self(3);
    pub const hlulong: Self = Self(4);
    pub const hlfloat: Self = Self(5);
    pub const hldouble: Self = Self(6);
    pub const hlstring: Self = Self(7);
    pub const hlbool: Self = Self(8);
    pub const hlvoid: Self = Self(9);
    pub const hlsizeprefixedbuffer: Self = Self(10);

    pub const ENUM_MIN: u8 = 0;
    pub const ENUM_MAX: u8 = 10;
    pub const ENUM_VALUES: &'static [Self] = &[
        Self::NONE,
        Self::hlint,
        Self::hluint,
        Self::hllong,
        Self::hlulong,
        Self::hlfloat,
        Self::hldouble,
        Self::hlstring,
        Self::hlbool,
        Self::hlvoid,
        Self::hlsizeprefixedbuffer,
    ];
    /// Returns the variant's name or "" if unknown.
    pub fn variant_name(self) -> Option<&'static str> {
        match self {
            Self::NONE => Some("NONE"),
            Self::hlint => Some("hlint"),
            Self::hluint => Some("hluint"),
            Self::hllong => Some("hllong"),
            Self::hlulong => Some("hlulong"),
            Self::hlfloat => Some("hlfloat"),
            Self::hldouble => Some("hldouble"),
            Self::hlstring => Some("hlstring"),
            Self::hlbool => Some("hlbool"),
            Self::hlvoid => Some("hlvoid"),
            Self::hlsizeprefixedbuffer => Some("hlsizeprefixedbuffer"),
            _ => None,
        }
    }
}
impl core::fmt::Debug for ReturnValue {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if let Some(name) = self.variant_name() {
            f.write_str(name)
        } else {
            f.write_fmt(format_args!("<UNKNOWN {:?}>", self.0))
        }
    }
}
impl<'a> flatbuffers::Follow<'a> for ReturnValue {
    type Inner = Self;
    #[inline]
    unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
        unsafe {
            let b = flatbuffers::read_scalar_at::<u8>(buf, loc);
            Self(b)
        }
    }
}

impl flatbuffers::Push for ReturnValue {
    type Output = ReturnValue;
    #[inline]
    unsafe fn push(&self, dst: &mut [u8], _written_len: usize) {
        unsafe {
            flatbuffers::emplace_scalar::<u8>(dst, self.0);
        }
    }
}

impl flatbuffers::EndianScalar for ReturnValue {
    type Scalar = u8;
    #[inline]
    fn to_little_endian(self) -> u8 {
        self.0.to_le()
    }
    #[inline]
    #[allow(clippy::wrong_self_convention)]
    fn from_little_endian(v: u8) -> Self {
        let b = u8::from_le(v);
        Self(b)
    }
}

impl<'a> flatbuffers::Verifiable for ReturnValue {
    #[inline]
    fn run_verifier(
        v: &mut flatbuffers::Verifier,
        pos: usize,
    ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
        use self::flatbuffers::Verifiable;
        u8::run_verifier(v, pos)
    }
}

impl flatbuffers::SimpleToVerifyInSlice for ReturnValue {}
pub struct ReturnValueUnionTableOffset {}
