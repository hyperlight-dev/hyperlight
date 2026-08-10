// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::vec;
use alloc::vec::Vec;

use bytes::Bytes;

use crate::flatbuffer_wrappers::function_types::ParameterValue;

/// Estimate the control-buffer capacity for encoding a function call.
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
#[inline]
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
            ParameterValue::VecBytes(_) | ParameterValue::ByteChunks(_) => 20,
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

/// Wrap contiguous bytes as one chunk without copying.
pub fn byte_chunks_from_bytes(value: Bytes) -> Vec<Bytes> {
    if value.is_empty() {
        Vec::new()
    } else {
        vec![value]
    }
}

/// Wrap a contiguous vector as one chunk without copying.
pub fn byte_chunks_from_vec(value: Vec<u8>) -> Vec<Bytes> {
    byte_chunks_from_bytes(Bytes::from(value))
}

/// Return the complete logical length of a chunked byte value.
pub(crate) fn byte_chunks_len(value: &[Bytes]) -> usize {
    value.iter().map(Bytes::len).sum()
}

/// Return the complete logical length, or `None` if the sum overflows.
pub(crate) fn try_byte_chunks_len(value: &[Bytes]) -> Option<usize> {
    value
        .iter()
        .try_fold(0usize, |length, chunk| length.checked_add(chunk.len()))
}

/// Materialize byte chunks as contiguous [`Bytes`].
///
/// This is O(1) for zero or one chunk and copies once for multiple chunks.
pub fn byte_chunks_to_bytes(value: &[Bytes]) -> Bytes {
    match value {
        [] => Bytes::new(),
        [chunk] => chunk.clone(),
        chunks => Bytes::from(byte_chunks_to_vec(chunks)),
    }
}

/// Materialize byte chunks as one contiguous vector.
///
/// This always allocates a new vector and copies the complete logical value.
pub fn byte_chunks_to_vec(value: &[Bytes]) -> Vec<u8> {
    let mut output = Vec::with_capacity(byte_chunks_len(value));
    for chunk in value {
        output.extend_from_slice(chunk);
    }
    output
}

#[cfg(feature = "fuzzing")]
pub(crate) fn arbitrary_byte_chunks(
    input: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<Vec<Bytes>> {
    <Vec<u8> as arbitrary::Arbitrary>::arbitrary(input).map(byte_chunks_from_vec)
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use flatbuffers::FlatBufferBuilder;

    use super::*;
    use crate::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
    use crate::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
    use crate::transport::ExternalValueRefs;

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
        let mut external_values = ExternalValueRefs::new();
        let _buffer = fc.encode(&mut builder, &mut external_values).unwrap();
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
    fn capacity_ignores_external_byte_payload_length() {
        let small = [ParameterValue::VecBytes(vec![0])];
        let large = [ParameterValue::VecBytes(vec![0; 1024 * 1024])];

        assert_eq!(
            estimate_flatbuffer_capacity("call", &small),
            estimate_flatbuffer_capacity("call", &large)
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
