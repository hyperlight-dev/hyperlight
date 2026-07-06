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
