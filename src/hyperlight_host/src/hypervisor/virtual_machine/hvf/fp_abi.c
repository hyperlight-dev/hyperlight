// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#include "bindings.h"

hv_return_t
hv_vcpu_get_simd_fp_reg_rsabi(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg, char *val) {
  hv_simd_fp_uchar16_t simd = {0};
  hv_return_t ret = hv_vcpu_get_simd_fp_reg(vcpu, reg, &simd);
  for (int i = 0; i < 16; ++i) {
    val[i] = simd[i];
  }
  return ret;
}

hv_return_t
hv_vcpu_set_simd_fp_reg_rsabi(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg, const char *val) {
  hv_simd_fp_uchar16_t simd;
  for (int i = 0; i < 16; ++i) {
    simd[i] = val[i];
  }
  return hv_vcpu_set_simd_fp_reg(vcpu, reg, simd);
}
