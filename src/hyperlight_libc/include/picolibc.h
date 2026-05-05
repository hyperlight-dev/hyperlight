/*
Copyright 2026  The Hyperlight Authors.

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

#pragma once

// version information
#define _NEWLIB_VERSION "4.3.0"
#define __NEWLIB_VERSION__ "4.3.0"
#define __NEWLIB__ 4
#define __NEWLIB_MINOR__ 3
#define __NEWLIB_PATCHLEVEL__ 0
#define __PICOLIBC_VERSION__ "1.8.11"
#define __PICOLIBC__ 1
#define __PICOLIBC_MINOR__ 8
#define __PICOLIBC_PATCHLEVEL__ 11

// static configuration - enabled features
#define __ASSERT_VERBOSE
#define __SINGLE_THREAD // -Dsingle-thread=true
#define __GLOBAL_ERRNO // -Dnewlib-global-errno=true
#define __INIT_FINI_ARRAY // -Dinitfini-array=true
#define __TINY_STDIO // tinystdio is now the only stdio
#define __IO_DEFAULT 'd' // -Dformat-default=double
#define __IO_FLOAT_EXACT // default
#define __IO_WCHAR // -Dio-wchar=true
#define __IEEE_LIBM // math library without errno
#define __FAST_STRCMP // default optimization
#define __FAST_BUFIO // -Dfast-bufio=true
#define __IO_SMALL_ULTOA // avoid division in conversion

// static configuration - disabled features
#undef __ARM_SEMIHOST // -Dsemihost=false
#undef __SEMIHOST // -Dsemihost=false
#undef __THREAD_LOCAL_STORAGE // -Dthread-local-storage=false
#undef __THREAD_LOCAL_STORAGE_API
#undef __THREAD_LOCAL_STORAGE_RP2040
#undef __THREAD_LOCAL_STORAGE_STACK_GUARD
#undef __ENABLE_MALLOC // -Denable-malloc=false
#undef __MALLOC_CLEAR_FREED
#undef __MB_CAPABLE // no multibyte support
#undef __HAVE_FCNTL // freestanding environment
#undef __STDIO_LOCKING // single-thread
#undef __IO_C99_FORMATS // -Dio-c99-formats=false
#undef __IO_LONG_DOUBLE // not enabled
#undef __IO_LONG_LONG // minimal format
#undef __IO_MINIMAL_LONG_LONG
#undef __IO_PERCENT_B // not enabled
#undef __IO_PERCENT_N // not enabled
#undef __IO_POS_ARGS // not enabled
#undef __MATH_ERRNO // IEEE math only
#undef __OBSOLETE_MATH
#undef __OBSOLETE_MATH_DOUBLE
#undef __OBSOLETE_MATH_FLOAT
#undef __PREFER_SIZE_OVER_SPEED // release build
#undef __ATOMIC_UNGETC // single-thread
#undef __IEEEFP_FUNCS
#undef __INIT_FINI_FUNCS // using INIT_FINI_ARRAY instead
#undef __HAVE_BITFIELDS_IN_PACKED_STRUCTS

// compiler feature detection
#ifndef __has_builtin
#define picolibc_has_builtin(x) 0
#else
#define picolibc_has_builtin(x) __has_builtin(x)
#endif

#if picolibc_has_builtin(__builtin_alloca)
#define __HAVE_BUILTIN_ALLOCA 1
#endif
#if picolibc_has_builtin(__builtin_ffs)
#define __HAVE_BUILTIN_FFS 1
#endif
#if picolibc_has_builtin(__builtin_ffsl)
#define __HAVE_BUILTIN_FFSL 1
#endif
#if picolibc_has_builtin(__builtin_ffsll)
#define __HAVE_BUILTIN_FFSLL 1
#endif
#if picolibc_has_builtin(__builtin_ctz)
#define __HAVE_BUILTIN_CTZ 1
#endif
#if picolibc_has_builtin(__builtin_ctzl)
#define __HAVE_BUILTIN_CTZL 1
#endif
#if picolibc_has_builtin(__builtin_ctzll)
#define __HAVE_BUILTIN_CTZLL 1
#endif
#if picolibc_has_builtin(__builtin_copysign)
#define __HAVE_BUILTIN_COPYSIGN 1
#endif
#if picolibc_has_builtin(__builtin_copysignl)
#define __HAVE_BUILTIN_COPYSIGNL 1
#endif
#if picolibc_has_builtin(__builtin_isinf)
#define __HAVE_BUILTIN_ISINF 1
#endif
#if picolibc_has_builtin(__builtin_isinfl)
#define __HAVE_BUILTIN_ISINFL 1
#endif
#if picolibc_has_builtin(__builtin_isnan)
#define __HAVE_BUILTIN_ISNAN 1
#endif
#if picolibc_has_builtin(__builtin_isnanl)
#define __HAVE_BUILTIN_ISNANL 1
#endif
#if picolibc_has_builtin(__builtin_isfinite)
#define __HAVE_BUILTIN_ISFINITE 1
#endif
#if picolibc_has_builtin(__builtin_finitel)
#define __HAVE_BUILTIN_FINITEL 1
#endif
#if picolibc_has_builtin(__builtin_issignalingl)
#define __HAVE_BUILTIN_ISSIGNALINGL 1
#endif
#if picolibc_has_builtin(__builtin_expect)
#define __HAVE_BUILTIN_EXPECT 1
#endif
#if picolibc_has_builtin(__builtin_complex)
#define __HAVE_BUILTIN_COMPLEX 1
#endif
#if picolibc_has_builtin(__builtin_add_overflow)
#define __HAVE_BUILTIN_ADD_OVERFLOW 1
#endif
#if picolibc_has_builtin(__builtin_mul_overflow)
#define __HAVE_BUILTIN_MUL_OVERFLOW 1
#endif

#if !defined(__STDC_NO_COMPLEX__)
#define __HAVE_COMPLEX 1
#endif

#undef picolibc_has_builtin
