/*
Copyright 2024 The Hyperlight Authors.

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

use alloc::vec::Vec;

use flatbuffers::FlatBufferBuilder;

use crate::flatbuffers::hyperlight::generated::{
    hlbool as Fbhlbool, hlboolArgs as FbhlboolArgs, hldouble as Fbhldouble,
    hldoubleArgs as FbhldoubleArgs, hlfloat as Fbhlfloat, hlfloatArgs as FbhlfloatArgs,
    hlint as Fbhlint, hlintArgs as FbhlintArgs, hllong as Fbhllong, hllongArgs as FbhllongArgs,
    hlsizeprefixedbuffer as Fbhlsizeprefixedbuffer,
    hlsizeprefixedbufferArgs as FbhlsizeprefixedbufferArgs, hlstring as Fbhlstring,
    hlstringArgs as FbhlstringArgs, hluint as Fbhluint, hluintArgs as FbhluintArgs,
    hlulong as Fbhlulong, hlulongArgs as FbhlulongArgs, hlvoid as Fbhlvoid,
    hlvoidArgs as FbhlvoidArgs, FunctionCallResult as FbFunctionCallResult,
    FunctionCallResultArgs as FbFunctionCallResultArgs, ReturnValue as FbReturnValue,
};

/// Flatbuffer-encodes the given value
pub fn get_flatbuffer_result<T: FlatbufferSerializable>(val: T) -> Vec<u8> {
    let mut builder = FlatBufferBuilder::new();
    let res = &T::serialize(&val, &mut builder);
    let result_offset = FbFunctionCallResult::create(&mut builder, res);

    builder.finish_size_prefixed(result_offset, None);

    builder.finished_data().to_vec()
}

pub trait FlatbufferSerializable {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs;
}

/// Implementations for basic types below

impl FlatbufferSerializable for () {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(Fbhlvoid::create(builder, &FbhlvoidArgs {}).as_union_value()),
            return_value_type: FbReturnValue::hlvoid,
        }
    }
}

impl FlatbufferSerializable for &str {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let string_offset = builder.create_string(self);
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlstring::create(
                    builder,
                    &FbhlstringArgs {
                        value: Some(string_offset),
                    },
                )
                .as_union_value(),
            ),
            return_value_type: FbReturnValue::hlstring,
        }
    }
}

impl FlatbufferSerializable for &[u8] {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let vec_offset = builder.create_vector(self);
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlsizeprefixedbuffer::create(
                    builder,
                    &FbhlsizeprefixedbufferArgs {
                        size: self.len() as i32,
                        value: Some(vec_offset),
                    },
                )
                .as_union_value(),
            ),
            return_value_type: FbReturnValue::hlsizeprefixedbuffer,
        }
    }
}

impl FlatbufferSerializable for f32 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlfloat::create(builder, &FbhlfloatArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hlfloat,
        }
    }
}

impl FlatbufferSerializable for f64 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhldouble::create(builder, &FbhldoubleArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hldouble,
        }
    }
}

impl FlatbufferSerializable for i32 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlint::create(builder, &FbhlintArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hlint,
        }
    }
}

impl FlatbufferSerializable for i64 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhllong::create(builder, &FbhllongArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hllong,
        }
    }
}

impl FlatbufferSerializable for u32 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhluint::create(builder, &FbhluintArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hluint,
        }
    }
}

impl FlatbufferSerializable for u64 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlulong::create(builder, &FbhlulongArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hlulong,
        }
    }
}

impl FlatbufferSerializable for bool {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlbool::create(builder, &FbhlboolArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hlbool,
        }
    }
}
