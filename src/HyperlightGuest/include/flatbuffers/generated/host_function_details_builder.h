#ifndef HOST_FUNCTION_DETAILS_BUILDER_H
#define HOST_FUNCTION_DETAILS_BUILDER_H

/* Generated by flatcc 0.6.2 FlatBuffers schema compiler for C by dvide.com */

#ifndef HOST_FUNCTION_DETAILS_READER_H
#include "host_function_details_reader.h"
#endif
#ifndef FLATBUFFERS_COMMON_BUILDER_H
#include "flatbuffers_common_builder.h"
#endif
#ifndef HOST_FUNCTION_DEFINITION_BUILDER_H
#include "host_function_definition_builder.h"
#endif
#include "flatcc/flatcc_prologue.h"
#ifndef flatbuffers_identifier
#define flatbuffers_identifier 0
#endif
#ifndef flatbuffers_extension
#define flatbuffers_extension "bin"
#endif

static const flatbuffers_voffset_t __Hyperlight_Generated_HostFunctionDetails_required[] = { 0 };
typedef flatbuffers_ref_t Hyperlight_Generated_HostFunctionDetails_ref_t;
static Hyperlight_Generated_HostFunctionDetails_ref_t Hyperlight_Generated_HostFunctionDetails_clone(flatbuffers_builder_t *B, Hyperlight_Generated_HostFunctionDetails_table_t t);
__flatbuffers_build_table(flatbuffers_, Hyperlight_Generated_HostFunctionDetails, 1)

#define __Hyperlight_Generated_HostFunctionDetails_formal_args , Hyperlight_Generated_HostFunctionDefinition_vec_ref_t v0
#define __Hyperlight_Generated_HostFunctionDetails_call_args , v0
static inline Hyperlight_Generated_HostFunctionDetails_ref_t Hyperlight_Generated_HostFunctionDetails_create(flatbuffers_builder_t *B __Hyperlight_Generated_HostFunctionDetails_formal_args);
__flatbuffers_build_table_prolog(flatbuffers_, Hyperlight_Generated_HostFunctionDetails, Hyperlight_Generated_HostFunctionDetails_file_identifier, Hyperlight_Generated_HostFunctionDetails_type_identifier)

/* vector has keyed elements */
__flatbuffers_build_table_vector_field(0, flatbuffers_, Hyperlight_Generated_HostFunctionDetails_functions, Hyperlight_Generated_HostFunctionDefinition, Hyperlight_Generated_HostFunctionDetails)

static inline Hyperlight_Generated_HostFunctionDetails_ref_t Hyperlight_Generated_HostFunctionDetails_create(flatbuffers_builder_t *B __Hyperlight_Generated_HostFunctionDetails_formal_args)
{
    if (Hyperlight_Generated_HostFunctionDetails_start(B)
        || Hyperlight_Generated_HostFunctionDetails_functions_add(B, v0)) {
        return 0;
    }
    return Hyperlight_Generated_HostFunctionDetails_end(B);
}

static Hyperlight_Generated_HostFunctionDetails_ref_t Hyperlight_Generated_HostFunctionDetails_clone(flatbuffers_builder_t *B, Hyperlight_Generated_HostFunctionDetails_table_t t)
{
    __flatbuffers_memoize_begin(B, t);
    if (Hyperlight_Generated_HostFunctionDetails_start(B)
        || Hyperlight_Generated_HostFunctionDetails_functions_pick(B, t)) {
        return 0;
    }
    __flatbuffers_memoize_end(B, t, Hyperlight_Generated_HostFunctionDetails_end(B));
}

#include "flatcc/flatcc_epilogue.h"
#endif /* HOST_FUNCTION_DETAILS_BUILDER_H */
