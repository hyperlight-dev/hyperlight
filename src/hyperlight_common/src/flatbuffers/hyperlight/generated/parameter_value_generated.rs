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
pub const ENUM_MIN_PARAMETER_VALUE: u8 = 0;
#[deprecated(
    since = "2.0.0",
    note = "Use associated constants instead. This will no longer be generated in 2021."
)]
pub const ENUM_MAX_PARAMETER_VALUE: u8 = 7;
#[deprecated(
    since = "2.0.0",
    note = "Use associated constants instead. This will no longer be generated in 2021."
)]
#[allow(non_camel_case_types)]
pub const ENUM_VALUES_PARAMETER_VALUE: [ParameterValue; 8] = [
    ParameterValue::NONE,
    ParameterValue::hlint,
    ParameterValue::hluint,
    ParameterValue::hllong,
    ParameterValue::hlulong,
    ParameterValue::hlstring,
    ParameterValue::hlbool,
    ParameterValue::hlvecbytes,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct ParameterValue(pub u8);
#[allow(non_upper_case_globals)]
impl ParameterValue {
    pub const NONE: Self = Self(0);
    pub const hlint: Self = Self(1);
    pub const hluint: Self = Self(2);
    pub const hllong: Self = Self(3);
    pub const hlulong: Self = Self(4);
    pub const hlstring: Self = Self(5);
    pub const hlbool: Self = Self(6);
    pub const hlvecbytes: Self = Self(7);

    pub const ENUM_MIN: u8 = 0;
    pub const ENUM_MAX: u8 = 7;
    pub const ENUM_VALUES: &'static [Self] = &[
        Self::NONE,
        Self::hlint,
        Self::hluint,
        Self::hllong,
        Self::hlulong,
        Self::hlstring,
        Self::hlbool,
        Self::hlvecbytes,
    ];
    /// Returns the variant's name or "" if unknown.
    pub fn variant_name(self) -> Option<&'static str> {
        match self {
            Self::NONE => Some("NONE"),
            Self::hlint => Some("hlint"),
            Self::hluint => Some("hluint"),
            Self::hllong => Some("hllong"),
            Self::hlulong => Some("hlulong"),
            Self::hlstring => Some("hlstring"),
            Self::hlbool => Some("hlbool"),
            Self::hlvecbytes => Some("hlvecbytes"),
            _ => None,
        }
    }
}
impl core::fmt::Debug for ParameterValue {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if let Some(name) = self.variant_name() {
            f.write_str(name)
        } else {
            f.write_fmt(format_args!("<UNKNOWN {:?}>", self.0))
        }
    }
}
impl<'a> flatbuffers::Follow<'a> for ParameterValue {
    type Inner = Self;
    #[inline]
    unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
        let b = flatbuffers::read_scalar_at::<u8>(buf, loc);
        Self(b)
    }
}

impl flatbuffers::Push for ParameterValue {
    type Output = ParameterValue;
    #[inline]
    unsafe fn push(&self, dst: &mut [u8], _written_len: usize) {
        flatbuffers::emplace_scalar::<u8>(dst, self.0);
    }
}

impl flatbuffers::EndianScalar for ParameterValue {
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

impl<'a> flatbuffers::Verifiable for ParameterValue {
    #[inline]
    fn run_verifier(
        v: &mut flatbuffers::Verifier,
        pos: usize,
    ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
        use self::flatbuffers::Verifiable;
        u8::run_verifier(v, pos)
    }
}

impl flatbuffers::SimpleToVerifyInSlice for ParameterValue {}
pub struct ParameterValueUnionTableOffset {}
