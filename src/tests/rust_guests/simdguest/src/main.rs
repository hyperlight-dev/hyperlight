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

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::ReturnType;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_guest::error::Result;
use hyperlight_guest_bin::guest_function::definition::GuestFunctionDefinition;
use hyperlight_guest_bin::guest_function::register::register_function;

// SSE - Base Streaming SIMD Extensions
fn test_sse(_function_call: &FunctionCall) -> Result<Vec<u8>> {
    #[cfg(target_feature = "sse")]
    {
        // Test with both raw assembly and intrinsics

        // Raw assembly - addss (add scalar single precision)
        let mut asm_result: f32 = 1.0;
        unsafe {
            core::arch::asm!(
                "addss {result}, {input}",
                result = inout(xmm_reg) asm_result,
                input = in(xmm_reg) 2.0f32,
            );
        }

        // Intrinsic equivalent - _mm_add_ss
        let intrinsic_result = unsafe {
            use core::arch::x86_64::*;
            let a = _mm_set_ss(1.0);
            let b = _mm_set_ss(2.0);
            let result = _mm_add_ss(a, b);
            _mm_cvtss_f32(result)
        };

        // Both should result in 3.0, return true if both are correct
        let asm_ok = (asm_result - 3.0).abs() < f32::EPSILON;
        let intrinsic_ok = (intrinsic_result - 3.0).abs() < f32::EPSILON;

        if asm_ok && intrinsic_ok {
            Ok(get_flatbuffer_result(true))
        } else {
            Ok(get_flatbuffer_result(false))
        }
    }
    #[cfg(not(target_feature = "sse"))]
    {
        Ok(get_flatbuffer_result(false)) // SSE feature not enabled
    }
}

// SSE2 - Streaming SIMD Extensions 2
fn test_sse2(_function_call: &FunctionCall) -> Result<Vec<u8>> {
    #[cfg(target_feature = "sse2")]
    {
        // Test with both raw assembly and intrinsics

        // Raw assembly - addsd (add scalar double precision)
        let mut asm_result: f64 = 1.0;
        unsafe {
            core::arch::asm!(
                "addsd {result}, {input}",
                result = inout(xmm_reg) asm_result,
                input = in(xmm_reg) 2.0f64,
            );
        }

        // Intrinsic equivalent - _mm_add_sd
        let intrinsic_result = unsafe {
            use core::arch::x86_64::*;
            let a = _mm_set_sd(1.0);
            let b = _mm_set_sd(2.0);
            let result = _mm_add_sd(a, b);
            _mm_cvtsd_f64(result)
        };

        // Both should result in 3.0, return true if both are correct
        let asm_ok = (asm_result - 3.0).abs() < f64::EPSILON;
        let intrinsic_ok = (intrinsic_result - 3.0).abs() < f64::EPSILON;

        if asm_ok && intrinsic_ok {
            Ok(get_flatbuffer_result(true))
        } else {
            Ok(get_flatbuffer_result(false))
        }
    }
    #[cfg(not(target_feature = "sse2"))]
    {
        Ok(get_flatbuffer_result(false)) // SSE2 feature not enabled
    }
}

// SSE3 - Streaming SIMD Extensions 3
fn test_sse3(_function_call: &FunctionCall) -> Result<Vec<u8>> {
    #[cfg(target_feature = "sse3")]
    {
        // Test with both raw assembly and intrinsics

        // Raw assembly - haddps (horizontal add packed single precision)
        let val_array = [1.0f32, 2.0f32, 3.0f32, 4.0f32];
        let asm_result: i32;
        unsafe {
            core::arch::asm!(
                "movups {tmp}, [{val_ptr}]",    // Load [1.0, 2.0, 3.0, 4.0]
                "haddps {tmp}, {tmp}",          // SSE3 horizontal add: [3.0, 7.0, 3.0, 7.0]
                "movd {result:e}, {tmp}",       // Extract first element as int32
                val_ptr = in(reg) val_array.as_ptr(),
                tmp = out(xmm_reg) _,
                result = out(reg) asm_result,
            );
        }

        // Intrinsic equivalent - _mm_hadd_ps
        let intrinsic_result = unsafe {
            use core::arch::x86_64::*;
            let a = _mm_set_ps(4.0, 3.0, 2.0, 1.0); // Reversed due to little-endian
            let result = _mm_hadd_ps(a, a);
            _mm_cvtss_f32(result)
        };

        // Check if both results make sense (3.0 as expected from 1.0 + 2.0)
        let asm_result_float = f32::from_bits(asm_result as u32);
        let asm_ok = (asm_result_float - 3.0).abs() < f32::EPSILON;
        let intrinsic_ok = (intrinsic_result - 3.0).abs() < f32::EPSILON;

        if asm_ok && intrinsic_ok {
            Ok(get_flatbuffer_result(true))
        } else {
            Ok(get_flatbuffer_result(false))
        }
    }
    #[cfg(not(target_feature = "sse3"))]
    {
        Ok(get_flatbuffer_result(false)) // SSE3 feature not enabled
    }
}

// SSSE3 - Supplemental Streaming SIMD Extensions 3
fn test_ssse3(_function_call: &FunctionCall) -> Result<Vec<u8>> {
    #[cfg(target_feature = "ssse3")]
    {
        // Test with both raw assembly and intrinsics

        // Raw assembly - pabsb (packed absolute value of bytes)
        let input_data = [
            -1i8, 2, -3, 4, -5, 6, -7, 8, -9, 10, -11, 12, -13, 14, -15, 16,
        ];
        let asm_result: i32;
        unsafe {
            core::arch::asm!(
                "movdqu {tmp}, [{input_ptr}]", // Load input vector from memory
                "pabsb {tmp}, {tmp}",          // SSSE3 absolute value of packed bytes
                "pextrb {result:e}, {tmp}, 15",  // Extract byte 15 (should be 16)
                input_ptr = in(reg) input_data.as_ptr(),
                tmp = out(xmm_reg) _,
                result = out(reg) asm_result,
            );
        }

        // Intrinsic equivalent - _mm_abs_epi8
        let intrinsic_result = unsafe {
            use core::arch::x86_64::*;
            let input = _mm_set_epi8(
                16, -15, 14, -13, 12, -11, 10, -9, 8, -7, 6, -5, 4, -3, 2, -1,
            );
            let abs_result = _mm_abs_epi8(input);
            _mm_extract_epi8(abs_result, 0) as u8 // Extract first byte (abs(-1) = 1)
        };

        // Check both results
        let asm_ok = (asm_result & 0xFF) == 16; // abs(-16) = 16 from byte 15
        let intrinsic_ok = intrinsic_result == 1; // abs(-1) = 1 from byte 0

        if asm_ok && intrinsic_ok {
            Ok(get_flatbuffer_result(true))
        } else {
            Ok(get_flatbuffer_result(false))
        }
    }
    #[cfg(not(target_feature = "ssse3"))]
    {
        Ok(get_flatbuffer_result(false)) // SSSE3 feature not enabled
    }
}

// SSE4.1 - Streaming SIMD Extensions 4.1
fn test_sse4_1(_function_call: &FunctionCall) -> Result<Vec<u8>> {
    #[cfg(target_feature = "sse4.1")]
    {
        // Test with both raw assembly and intrinsics

        // Raw assembly - pblendvb (variable blend packed bytes)
        let val_a = [1i8; 16]; // All 1s
        let val_b = [2i8; 16]; // All 2s
        let val_mask = [-1i8; 16]; // All 0xFF (select from b)
        let asm_result: i32;
        unsafe {
            core::arch::asm!(
                "movdqu {a}, [{val_a_ptr}]",    // Load vector of 1s
                "movdqu {b}, [{val_b_ptr}]",    // Load vector of 2s
                "movdqu xmm0, [{val_mask_ptr}]", // Load mask into xmm0 (pblendvb implicit operand)
                "pblendvb {a}, {b}",            // SSE4.1 blend: xmm0=mask, a=src1, b=src2
                "pextrb {result:e}, {a}, 0",      // Extract first byte
                val_a_ptr = in(reg) val_a.as_ptr(),
                val_b_ptr = in(reg) val_b.as_ptr(),
                val_mask_ptr = in(reg) val_mask.as_ptr(),
                a = out(xmm_reg) _,
                b = out(xmm_reg) _,
                result = out(reg) asm_result,
                out("xmm0") _,                  // xmm0 is clobbered
            );
        }

        // Intrinsic equivalent - _mm_blendv_epi8
        let intrinsic_result = unsafe {
            use core::arch::x86_64::*;
            let a = _mm_set1_epi8(1); // All 1s
            let b = _mm_set1_epi8(2); // All 2s
            let mask = _mm_set1_epi8(-1); // All 0xFF (select from b)
            let blended = _mm_blendv_epi8(a, b, mask);
            _mm_extract_epi8(blended, 0) as u8
        };

        // Both should result in 2 (blend selects b), return true if both are correct
        let asm_ok = (asm_result & 0xFF) == 2;
        let intrinsic_ok = intrinsic_result == 2;

        if asm_ok && intrinsic_ok {
            Ok(get_flatbuffer_result(true))
        } else {
            Ok(get_flatbuffer_result(false))
        }
    }
    #[cfg(not(target_feature = "sse4.1"))]
    {
        Ok(get_flatbuffer_result(false)) // SSE4.1 feature not enabled
    }
}

// SSE4.2 - Streaming SIMD Extensions 4.2
fn test_sse4_2(_function_call: &FunctionCall) -> Result<Vec<u8>> {
    #[cfg(target_feature = "sse4.2")]
    {
        // Test with both raw assembly and intrinsics

        // Raw assembly - pcmpgtq (compare packed 64-bit integers)
        let val_a = [1i64, 3i64]; // [1, 3] as 64-bit values
        let val_b = [0i64, 2i64]; // [0, 2] as 64-bit values
        let asm_result: u64;
        unsafe {
            core::arch::asm!(
                "movdqu {a}, [{val_a_ptr}]",   // Load [1, 3]
                "movdqu {b}, [{val_b_ptr}]",   // Load [0, 2]
                "pcmpgtq {a}, {b}",            // SSE4.2 compare: a > b
                "pextrq {result}, {a}, 0",     // Extract first 64-bit element
                val_a_ptr = in(reg) val_a.as_ptr(),
                val_b_ptr = in(reg) val_b.as_ptr(),
                a = out(xmm_reg) _,
                b = out(xmm_reg) _,
                result = out(reg) asm_result,
            );
        }

        // Intrinsic equivalent - _mm_cmpgt_epi64
        let intrinsic_result = unsafe {
            use core::arch::x86_64::*;
            let a = _mm_set_epi64x(3, 1); // [1, 3] (reversed due to little-endian)
            let b = _mm_set_epi64x(2, 0); // [0, 2]
            let cmp_result = _mm_cmpgt_epi64(a, b);
            _mm_extract_epi64(cmp_result, 0) as u64
        };

        // Both should result in all bits set (0xFFFFFFFFFFFFFFFF), return true if both are correct
        let asm_ok = asm_result == u64::MAX;
        let intrinsic_ok = intrinsic_result == u64::MAX;

        if asm_ok && intrinsic_ok {
            Ok(get_flatbuffer_result(true))
        } else {
            Ok(get_flatbuffer_result(false))
        }
    }
    #[cfg(not(target_feature = "sse4.2"))]
    {
        Ok(get_flatbuffer_result(false)) // SSE4.2 feature not enabled
    }
}

// AVX - Advanced Vector Extensions
fn test_avx(_function_call: &FunctionCall) -> Result<Vec<u8>> {
    #[cfg(target_feature = "avx")]
    {
        // Test with both raw assembly and intrinsics

        // Raw assembly - vaddps (add packed single precision)
        let val1 = 1.0f32;
        let val2 = 2.0f32;
        let asm_result: i32;
        unsafe {
            core::arch::asm!(
                "vmovd {xmm1}, {val1:e}",             // Load 1.0 into xmm register
                "vbroadcastss {input1}, {xmm1}",      // Broadcast to all 8 elements of ymm
                "vmovd {xmm2}, {val2:e}",             // Load 2.0 into xmm register
                "vbroadcastss {input2}, {xmm2}",      // Broadcast to all 8 elements of ymm
                "vaddps {input1}, {input1}, {input2}", // AVX addition: [3.0; 8]
                "vextractf128 {xmm_result}, {input1}, 0", // Extract lower 128 bits
                "vmovd {result:e}, {xmm_result}",     // Extract first element as int32
                val1 = in(reg) val1.to_bits(),
                val2 = in(reg) val2.to_bits(),
                xmm1 = out(xmm_reg) _,
                xmm2 = out(xmm_reg) _,
                xmm_result = out(xmm_reg) _,
                input1 = out(ymm_reg) _,
                input2 = out(ymm_reg) _,
                result = out(reg) asm_result,
            );
        }

        // Intrinsic equivalent - _mm256_add_ps
        let intrinsic_result = unsafe {
            use core::arch::x86_64::*;
            let a = _mm256_set1_ps(1.0); // Broadcast 1.0 to all 8 elements
            let b = _mm256_set1_ps(2.0); // Broadcast 2.0 to all 8 elements
            let result = _mm256_add_ps(a, b); // AVX addition: [3.0; 8]
            let extracted = _mm256_extractf128_ps(result, 0); // Extract lower 128 bits
            _mm_cvtss_f32(extracted) // Extract first element
        };

        // Check if both results make sense (3.0 as expected)
        let asm_result_float = f32::from_bits(asm_result as u32);
        let asm_ok = (asm_result_float - 3.0).abs() < f32::EPSILON;
        let intrinsic_ok = (intrinsic_result - 3.0).abs() < f32::EPSILON;

        if asm_ok && intrinsic_ok {
            Ok(get_flatbuffer_result(true))
        } else {
            Ok(get_flatbuffer_result(false))
        }
    }
    #[cfg(not(target_feature = "avx"))]
    {
        Ok(get_flatbuffer_result(false)) // AVX feature not enabled
    }
}

// AVX2 - Advanced Vector Extensions 2
fn test_avx2(_function_call: &FunctionCall) -> Result<Vec<u8>> {
    #[cfg(target_feature = "avx2")]
    {
        // Test with both raw assembly and intrinsics

        // Raw assembly - vpaddq (add packed 64-bit integers)
        let val1 = 1i64;
        let val2 = 2i64;
        let asm_result: i64;
        unsafe {
            core::arch::asm!(
                "vmovq {xmm1}, {val1}",               // Load 1 into xmm register
                "vpbroadcastq {input1}, {xmm1}",      // Broadcast to all 4 elements of ymm
                "vmovq {xmm2}, {val2}",               // Load 2 into xmm register
                "vpbroadcastq {input2}, {xmm2}",      // Broadcast to all 4 elements of ymm
                "vpaddq {input1}, {input1}, {input2}", // AVX2 addition: [3; 4]
                "vextracti128 {xmm_result}, {input1}, 0", // Extract lower 128 bits
                "vmovq {result}, {xmm_result}",       // Extract first 64-bit element
                val1 = in(reg) val1,
                val2 = in(reg) val2,
                xmm1 = out(xmm_reg) _,
                xmm2 = out(xmm_reg) _,
                xmm_result = out(xmm_reg) _,
                input1 = out(ymm_reg) _,
                input2 = out(ymm_reg) _,
                result = out(reg) asm_result,
            );
        }

        // Intrinsic equivalent - _mm256_add_epi64
        let intrinsic_result = unsafe {
            use core::arch::x86_64::*;
            let a = _mm256_set1_epi64x(1); // Broadcast 1 to all 4 elements
            let b = _mm256_set1_epi64x(2); // Broadcast 2 to all 4 elements
            let result = _mm256_add_epi64(a, b); // AVX2 addition: [3; 4]
            let extracted = _mm256_extracti128_si256(result, 0); // Extract lower 128 bits
            _mm_extract_epi64(extracted, 0) // Extract first 64-bit element
        };

        // Both should result in 3, return true if both are correct
        let asm_ok = asm_result == 3;
        let intrinsic_ok = intrinsic_result == 3;

        if asm_ok && intrinsic_ok {
            Ok(get_flatbuffer_result(true))
        } else {
            Ok(get_flatbuffer_result(false))
        }
    }
    #[cfg(not(target_feature = "avx2"))]
    {
        Ok(get_flatbuffer_result(false)) // AVX2 feature not enabled
    }
}

#[no_mangle]
pub extern "C" fn hyperlight_main() {
    // Register individual test functions in order
    let test_sse_def = GuestFunctionDefinition::new(
        "test_sse".to_string(),
        Vec::new(),
        ReturnType::Bool,
        test_sse as usize,
    );
    register_function(test_sse_def);

    let test_sse2_def = GuestFunctionDefinition::new(
        "test_sse2".to_string(),
        Vec::new(),
        ReturnType::Bool,
        test_sse2 as usize,
    );
    register_function(test_sse2_def);

    let test_sse3_def = GuestFunctionDefinition::new(
        "test_sse3".to_string(),
        Vec::new(),
        ReturnType::Bool,
        test_sse3 as usize,
    );
    register_function(test_sse3_def);

    let test_ssse3_def = GuestFunctionDefinition::new(
        "test_ssse3".to_string(),
        Vec::new(),
        ReturnType::Bool,
        test_ssse3 as usize,
    );
    register_function(test_ssse3_def);

    let test_sse4_1_def = GuestFunctionDefinition::new(
        "test_sse4_1".to_string(),
        Vec::new(),
        ReturnType::Bool,
        test_sse4_1 as usize,
    );
    register_function(test_sse4_1_def);

    let test_sse4_2_def = GuestFunctionDefinition::new(
        "test_sse4_2".to_string(),
        Vec::new(),
        ReturnType::Bool,
        test_sse4_2 as usize,
    );
    register_function(test_sse4_2_def);

    let test_avx_def = GuestFunctionDefinition::new(
        "test_avx".to_string(),
        Vec::new(),
        ReturnType::Bool,
        test_avx as usize,
    );
    register_function(test_avx_def);

    let test_avx2_def = GuestFunctionDefinition::new(
        "test_avx2".to_string(),
        Vec::new(),
        ReturnType::Bool,
        test_avx2 as usize,
    );
    register_function(test_avx2_def);
}

#[no_mangle]
pub fn guest_dispatch_function() {
    // Simple dispatch - not used in this test
}
