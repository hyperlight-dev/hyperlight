/*
Copyright 2025  The Hyperlight Authors.

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

use crate::flatbuffer_wrappers::function_types::ParameterValue;
use crate::flatbuffers::hyperlight::generated::{
    FunctionCallResult as FbFunctionCallResult, FunctionCallResultArgs as FbFunctionCallResultArgs,
    FunctionCallResultType as FbFunctionCallResultType, ReturnValue as FbReturnValue,
    ReturnValueBox, ReturnValueBoxArgs, hlbool as Fbhlbool, hlboolArgs as FbhlboolArgs,
    hldouble as Fbhldouble, hldoubleArgs as FbhldoubleArgs, hlfloat as Fbhlfloat,
    hlfloatArgs as FbhlfloatArgs, hlint as Fbhlint, hlintArgs as FbhlintArgs, hllong as Fbhllong,
    hllongArgs as FbhllongArgs, hlsizeprefixedbuffer as Fbhlsizeprefixedbuffer,
    hlsizeprefixedbufferArgs as FbhlsizeprefixedbufferArgs, hlstring as Fbhlstring,
    hlstringArgs as FbhlstringArgs, hluint as Fbhluint, hluintArgs as FbhluintArgs,
    hlulong as Fbhlulong, hlulongArgs as FbhlulongArgs, hlvoid as Fbhlvoid,
    hlvoidArgs as FbhlvoidArgs,
};

/// Flatbuffer-encodes the given value
pub fn get_flatbuffer_result<T: FlatbufferSerializable>(val: T) -> Vec<u8> {
    let mut builder = FlatBufferBuilder::new();
    let res = T::serialize(&val, &mut builder);
    let result_offset = FbFunctionCallResult::create(&mut builder, &res);

    builder.finish_size_prefixed(result_offset, None);

    builder.finished_data().to_vec()
}

pub trait FlatbufferSerializable {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs;
}

// Implementations for basic types below

impl FlatbufferSerializable for () {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let void_off = Fbhlvoid::create(builder, &FbhlvoidArgs {});
        let rv_box = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value_type: FbReturnValue::hlvoid,
                value: Some(void_off.as_union_value()),
            },
        );
        FbFunctionCallResultArgs {
            result_type: FbFunctionCallResultType::ReturnValueBox,
            result: Some(rv_box.as_union_value()),
        }
    }
}

impl FlatbufferSerializable for &str {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let string_offset = builder.create_string(self);
        let str_off = Fbhlstring::create(
            builder,
            &FbhlstringArgs {
                value: Some(string_offset),
            },
        );
        let rv_box = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value_type: FbReturnValue::hlstring,
                value: Some(str_off.as_union_value()),
            },
        );
        FbFunctionCallResultArgs {
            result_type: FbFunctionCallResultType::ReturnValueBox,
            result: Some(rv_box.as_union_value()),
        }
    }
}

impl FlatbufferSerializable for &[u8] {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let vec_off = builder.create_vector(self);
        let buf_off = Fbhlsizeprefixedbuffer::create(
            builder,
            &FbhlsizeprefixedbufferArgs {
                size: self.len() as i32,
                value: Some(vec_off),
            },
        );
        let rv_box = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value_type: FbReturnValue::hlsizeprefixedbuffer,
                value: Some(buf_off.as_union_value()),
            },
        );
        FbFunctionCallResultArgs {
            result_type: FbFunctionCallResultType::ReturnValueBox,
            result: Some(rv_box.as_union_value()),
        }
    }
}

impl FlatbufferSerializable for f32 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let off = Fbhlfloat::create(builder, &FbhlfloatArgs { value: *self });
        let rv_box = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value_type: FbReturnValue::hlfloat,
                value: Some(off.as_union_value()),
            },
        );
        FbFunctionCallResultArgs {
            result_type: FbFunctionCallResultType::ReturnValueBox,
            result: Some(rv_box.as_union_value()),
        }
    }
}

impl FlatbufferSerializable for f64 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let off = Fbhldouble::create(builder, &FbhldoubleArgs { value: *self });
        let rv_box = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value_type: FbReturnValue::hldouble,
                value: Some(off.as_union_value()),
            },
        );
        FbFunctionCallResultArgs {
            result_type: FbFunctionCallResultType::ReturnValueBox,
            result: Some(rv_box.as_union_value()),
        }
    }
}

impl FlatbufferSerializable for i32 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let off = Fbhlint::create(builder, &FbhlintArgs { value: *self });
        let rv_box = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value_type: FbReturnValue::hlint,
                value: Some(off.as_union_value()),
            },
        );
        FbFunctionCallResultArgs {
            result_type: FbFunctionCallResultType::ReturnValueBox,
            result: Some(rv_box.as_union_value()),
        }
    }
}

impl FlatbufferSerializable for i64 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let off = Fbhllong::create(builder, &FbhllongArgs { value: *self });
        let rv_box = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value_type: FbReturnValue::hllong,
                value: Some(off.as_union_value()),
            },
        );
        FbFunctionCallResultArgs {
            result_type: FbFunctionCallResultType::ReturnValueBox,
            result: Some(rv_box.as_union_value()),
        }
    }
}

impl FlatbufferSerializable for u32 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let off = Fbhluint::create(builder, &FbhluintArgs { value: *self });
        let rv_box = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value_type: FbReturnValue::hluint,
                value: Some(off.as_union_value()),
            },
        );
        FbFunctionCallResultArgs {
            result_type: FbFunctionCallResultType::ReturnValueBox,
            result: Some(rv_box.as_union_value()),
        }
    }
}

impl FlatbufferSerializable for u64 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let off = Fbhlulong::create(builder, &FbhlulongArgs { value: *self });
        let rv_box = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value_type: FbReturnValue::hlulong,
                value: Some(off.as_union_value()),
            },
        );
        FbFunctionCallResultArgs {
            result_type: FbFunctionCallResultType::ReturnValueBox,
            result: Some(rv_box.as_union_value()),
        }
    }
}

impl FlatbufferSerializable for bool {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let off = Fbhlbool::create(builder, &FbhlboolArgs { value: *self });
        let rv_box = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value_type: FbReturnValue::hlbool,
                value: Some(off.as_union_value()),
            },
        );
        FbFunctionCallResultArgs {
            result_type: FbFunctionCallResultType::ReturnValueBox,
            result: Some(rv_box.as_union_value()),
        }
    }
}

/// Estimates the required buffer capacity for encoding a FunctionCall with the given parameters.
/// This helps avoid reallocation during FlatBuffer encoding when passing large slices and strings.
///
/// The function aims to be lightweight and fast and run in O(1) as long as the number of parameters is limited
/// (which it is since hyperlight only currently supports up to 12).
///
/// Note: This estimates the capacity needed for the inner vec inside a FlatBufferBuilder. It does not
/// necessarily match the size of the final encoded buffer. The estimation always rounds up to the
/// nearest power of two to match FlatBufferBuilder's allocation strategy.
///
/// The estimations are numbers used are empirically derived based on the tests below and vaguely based
/// on https://flatbuffers.dev/internals/ and https://github.com/dvidelabs/flatcc/blob/f064cefb2034d1e7407407ce32a6085c322212a7/doc/binary-format.md#flatbuffers-binary-format
#[inline] // allow cross-crate inlining (for hyperlight-host calls)
pub fn estimate_flatbuffer_capacity(function_name: &str, args: &[ParameterValue]) -> usize {
    let mut estimated_capacity = 20;

    // Function name overhead
    estimated_capacity += function_name.len() + 12;

    // Parameters vector overhead
    estimated_capacity += 12 + args.len() * 6;

    // Per-parameter overhead
    for arg in args {
        estimated_capacity += 16; // Base parameter structure
        estimated_capacity += match arg {
            ParameterValue::String(s) => s.len() + 20,
            ParameterValue::VecBytes(v) => v.len() + 20,
            ParameterValue::Int(_) | ParameterValue::UInt(_) => 16,
            ParameterValue::Long(_) | ParameterValue::ULong(_) => 20,
            ParameterValue::Float(_) => 16,
            ParameterValue::Double(_) => 20,
            ParameterValue::Bool(_) => 12,
        };
    }

    // match how vec grows
    estimated_capacity.next_power_of_two()
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
    use crate::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};

    /// Helper function to check that estimation is within reasonable bounds (±25%)
    fn assert_estimation_accuracy(
        function_name: &str,
        args: Vec<ParameterValue>,
        call_type: FunctionCallType,
        return_type: ReturnType,
    ) {
        let estimated = estimate_flatbuffer_capacity(function_name, &args);

        let fc = FunctionCall::new(
            function_name.to_string(),
            Some(args),
            call_type.clone(),
            return_type,
        );
        // Important that this FlatBufferBuilder is created with capacity 0 so it grows to its needed capacity
        let mut builder = FlatBufferBuilder::new();
        let _buffer = fc.encode(&mut builder);
        let actual = builder.collapse().0.capacity();

        let lower_bound = (actual as f64 * 0.75) as usize;
        let upper_bound = (actual as f64 * 1.25) as usize;

        assert!(
            estimated >= lower_bound && estimated <= upper_bound,
            "Estimation {} outside bounds [{}, {}] for actual size {} (function: {}, call_type: {:?}, return_type: {:?})",
            estimated,
            lower_bound,
            upper_bound,
            actual,
            function_name,
            call_type,
            return_type
        );
    }

    #[test]
    fn test_estimate_no_parameters() {
        assert_estimation_accuracy(
            "simple_function",
            vec![],
            FunctionCallType::Guest,
            ReturnType::Void,
        );
    }

    #[test]
    fn test_estimate_single_int_parameter() {
        assert_estimation_accuracy(
            "add_one",
            vec![ParameterValue::Int(42)],
            FunctionCallType::Guest,
            ReturnType::Int,
        );
    }

    #[test]
    fn test_estimate_multiple_scalar_parameters() {
        assert_estimation_accuracy(
            "calculate",
            vec![
                ParameterValue::Int(10),
                ParameterValue::UInt(20),
                ParameterValue::Long(30),
                ParameterValue::ULong(40),
                ParameterValue::Float(1.5),
                ParameterValue::Double(2.5),
                ParameterValue::Bool(true),
            ],
            FunctionCallType::Guest,
            ReturnType::Double,
        );
    }

    #[test]
    fn test_estimate_string_parameters() {
        assert_estimation_accuracy(
            "process_strings",
            vec![
                ParameterValue::String("hello".to_string()),
                ParameterValue::String("world".to_string()),
                ParameterValue::String("this is a longer string for testing".to_string()),
            ],
            FunctionCallType::Host,
            ReturnType::String,
        );
    }

    #[test]
    fn test_estimate_very_long_string() {
        let long_string = "a".repeat(1000);
        assert_estimation_accuracy(
            "process_long_string",
            vec![ParameterValue::String(long_string)],
            FunctionCallType::Guest,
            ReturnType::String,
        );
    }

    #[test]
    fn test_estimate_vector_parameters() {
        assert_estimation_accuracy(
            "process_vectors",
            vec![
                ParameterValue::VecBytes(vec![1, 2, 3, 4, 5]),
                ParameterValue::VecBytes(vec![]),
                ParameterValue::VecBytes(vec![0; 100]),
            ],
            FunctionCallType::Host,
            ReturnType::VecBytes,
        );
    }

    #[test]
    fn test_estimate_mixed_parameters() {
        assert_estimation_accuracy(
            "complex_function",
            vec![
                ParameterValue::String("test".to_string()),
                ParameterValue::Int(42),
                ParameterValue::VecBytes(vec![1, 2, 3, 4, 5]),
                ParameterValue::Bool(true),
                ParameterValue::Double(553.14159),
                ParameterValue::String("another string".to_string()),
                ParameterValue::Long(9223372036854775807),
            ],
            FunctionCallType::Guest,
            ReturnType::VecBytes,
        );
    }

    #[test]
    fn test_estimate_large_function_name() {
        let long_name = "very_long_function_name_that_exceeds_normal_lengths_for_testing_purposes";
        assert_estimation_accuracy(
            long_name,
            vec![ParameterValue::Int(1)],
            FunctionCallType::Host,
            ReturnType::Long,
        );
    }

    #[test]
    fn test_estimate_large_vector() {
        let large_vector = vec![42u8; 10000];
        assert_estimation_accuracy(
            "process_large_data",
            vec![ParameterValue::VecBytes(large_vector)],
            FunctionCallType::Guest,
            ReturnType::Bool,
        );
    }

    #[test]
    fn test_estimate_all_parameter_types() {
        assert_estimation_accuracy(
            "comprehensive_test",
            vec![
                ParameterValue::Int(i32::MIN),
                ParameterValue::UInt(u32::MAX),
                ParameterValue::Long(i64::MIN),
                ParameterValue::ULong(u64::MAX),
                ParameterValue::Float(f32::MIN),
                ParameterValue::Double(f64::MAX),
                ParameterValue::Bool(false),
                ParameterValue::String("test string".to_string()),
                ParameterValue::VecBytes(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            ],
            FunctionCallType::Host,
            ReturnType::ULong,
        );
    }

    #[test]
    fn test_different_function_call_types() {
        assert_estimation_accuracy(
            "guest_function",
            vec![ParameterValue::String("guest call".to_string())],
            FunctionCallType::Guest,
            ReturnType::String,
        );

        assert_estimation_accuracy(
            "host_function",
            vec![ParameterValue::String("host call".to_string())],
            FunctionCallType::Host,
            ReturnType::String,
        );
    }

    #[test]
    fn test_different_return_types() {
        let args = vec![
            ParameterValue::Int(42),
            ParameterValue::String("test".to_string()),
        ];

        let void_est = estimate_flatbuffer_capacity("test_void", &args);
        let int_est = estimate_flatbuffer_capacity("test_int", &args);
        let string_est = estimate_flatbuffer_capacity("test_string", &args);

        assert!((void_est as i32 - int_est as i32).abs() < 10);
        assert!((int_est as i32 - string_est as i32).abs() < 10);

        assert_estimation_accuracy(
            "test_void",
            args.clone(),
            FunctionCallType::Guest,
            ReturnType::Void,
        );
        assert_estimation_accuracy(
            "test_int",
            args.clone(),
            FunctionCallType::Guest,
            ReturnType::Int,
        );
        assert_estimation_accuracy(
            "test_string",
            args,
            FunctionCallType::Guest,
            ReturnType::String,
        );
    }

    #[test]
    fn test_estimate_many_large_vectors_and_strings() {
        assert_estimation_accuracy(
            "process_bulk_data",
            vec![
                ParameterValue::String("Large string data: ".to_string() + &"x".repeat(2000)),
                ParameterValue::VecBytes(vec![1u8; 5000]),
                ParameterValue::String(
                    "Another large string with lots of content ".to_string() + &"y".repeat(3000),
                ),
                ParameterValue::VecBytes(vec![255u8; 7500]),
                ParameterValue::String(
                    "Third massive string parameter ".to_string() + &"z".repeat(1500),
                ),
                ParameterValue::VecBytes(vec![128u8; 10000]),
                ParameterValue::Int(42),
                ParameterValue::String("Final large string ".to_string() + &"a".repeat(4000)),
                ParameterValue::VecBytes(vec![64u8; 2500]),
                ParameterValue::Bool(true),
            ],
            FunctionCallType::Host,
            ReturnType::VecBytes,
        );
    }

    #[test]
    fn test_estimate_twenty_parameters() {
        assert_estimation_accuracy(
            "function_with_many_parameters",
            vec![
                ParameterValue::Int(1),
                ParameterValue::String("param2".to_string()),
                ParameterValue::Bool(true),
                ParameterValue::Float(3213.14),
                ParameterValue::VecBytes(vec![1, 2, 3]),
                ParameterValue::Long(1000000),
                ParameterValue::Double(322.718),
                ParameterValue::UInt(42),
                ParameterValue::String("param9".to_string()),
                ParameterValue::Bool(false),
                ParameterValue::ULong(9999999999),
                ParameterValue::VecBytes(vec![4, 5, 6, 7, 8]),
                ParameterValue::Int(-100),
                ParameterValue::Float(1.414),
                ParameterValue::String("param15".to_string()),
                ParameterValue::Double(1.732),
                ParameterValue::Bool(true),
                ParameterValue::VecBytes(vec![9, 10]),
                ParameterValue::Long(-5000000),
                ParameterValue::UInt(12345),
            ],
            FunctionCallType::Guest,
            ReturnType::Int,
        );
    }

    /// When running under Miri, this test takes too long due to large allocations
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_estimate_megabyte_parameters() {
        assert_estimation_accuracy(
            "process_megabyte_data",
            vec![
                ParameterValue::String("MB String 1: ".to_string() + &"x".repeat(1_048_576)), // 1MB string
                ParameterValue::VecBytes(vec![42u8; 2_097_152]), // 2MB vector
                ParameterValue::String("MB String 2: ".to_string() + &"y".repeat(1_572_864)), // 1.5MB string
                ParameterValue::VecBytes(vec![128u8; 3_145_728]), // 3MB vector
                ParameterValue::String("MB String 3: ".to_string() + &"z".repeat(2_097_152)), // 2MB string
            ],
            FunctionCallType::Host,
            ReturnType::VecBytes,
        );
    }
}
