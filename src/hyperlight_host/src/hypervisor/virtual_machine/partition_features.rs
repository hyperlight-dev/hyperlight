// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

//! Processor features that MSHV and WHP guests see. See `docs/guest-cpu.md`.
//!
//! Bit positions follow `hv_partition_processor_features` and
//! `hv_partition_processor_xsave_features` in Linux `include/hyperv/hvhdk.h`. They match
//! `WHV_PROCESSOR_FEATURES_BANKS` and `WHV_PROCESSOR_XSAVE_FEATURES`. Every bit is part of the
//! 21H2 compatibility version and of the mask WHP accepts.

const fn bits(list: &[u32]) -> u64 {
    let mut mask = 0;
    let mut i = 0;
    while i < list.len() {
        mask |= 1 << list[i];
        i += 1;
    }
    mask
}

const BANK0: &[u32] = &[
    0,  // SSE3
    1,  // LAHF/SAHF
    2,  // SSSE3
    3,  // SSE4.1
    4,  // SSE4.2
    5,  // SSE4A
    6,  // XOP
    7,  // POPCNT
    8,  // CMPXCHG16B
    9,  // ALTMOVCR8
    10, // LZCNT
    11, // MisalignSSE
    12, // MMX extensions
    13, // 3DNow!
    14, // Extended 3DNow!
    15, // 1 GB pages
    16, // AES
    17, // PCLMULQDQ
    18, // PCID
    19, // FMA4
    20, // F16C
    21, // RDRAND
    22, // RDFSBASE/WRFSBASE
    23, // SMEP
    24, // Enhanced fast strings
    25, // BMI1
    26, // BMI2
    29, // MOVBE
    30, // NPIEP1
    31, // Deprecated x87 FPU CS/DS
    32, // RDSEED
    33, // ADX
    34, // PREFETCHW
    35, // SMAP
    38, // RDTSCP
    39, // CLFLUSHOPT
    43, // INVPCID
    47, // Unrestricted guest
    49, // Fast short REP MOV
    51, // RDCL_NO
    54, // SSB_NO
    55, // RSBA_NO
    57, // RDPID
    58, // UMIP
    59, // MDS_NO
    60, // MD_CLEAR
    61, // TAA_NO
];

const BANK1: &[u32] = &[
    1,  // Invariant TSC
    5,  // MBEC
    10, // VMX exception inject
    28, // FB_CLEAR
    29, // BTC_NO
    48, // RFDS_NO
    49, // RFDS_CLEAR
];

const XSAVE: &[u32] = &[
    0,  // XSAVE
    1,  // XSAVEOPT
    2,  // AVX
    3,  // AVX2
    4,  // FMA
    6,  // AVX512F
    7,  // AVX512DQ
    8,  // AVX512CD
    9,  // AVX512BW
    10, // AVX512VL
    11, // Compacted XSAVE
    14, // AVX512_BITALG
    15, // AVX512_IFMA
    16, // AVX512_VBMI
    17, // AVX512_VBMI2
    18, // AVX512_VNNI
    19, // GFNI
    20, // VAES
    21, // AVX512_VPOPCNTDQ
    22, // VPCLMULQDQ
    23, // AVX512_BF16
    24, // AVX512_VP2INTERSECT
    25, // AVX512_FP16
    30, // AVX_VNNI
];

/// Enabled processor feature banks 0 and 1.
pub(crate) const PROCESSOR_FEATURES: [u64; 2] = [bits(BANK0), bits(BANK1)];

/// Enabled processor XSAVE features.
pub(crate) const XSAVE_FEATURES: u64 = bits(XSAVE);
