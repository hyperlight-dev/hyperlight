// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#include <Hypervisor/Hypervisor.h>

hv_return_t
hv_vcpu_get_simd_fp_reg_rsabi(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg, char *val);
hv_return_t
hv_vcpu_set_simd_fp_reg_rsabi(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg, const char *val);
