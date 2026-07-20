#ifndef HYPERLIGHT_GUEST_MACRO_H
#define HYPERLIGHT_GUEST_MACRO_H

#include "hyperlight_guest.h"

// Generates a wrapper function called _call_<function_name> that
// unwraps the argument from the hl_FunctionCall struct then calls the function
//
// Parameters: 1. A function name
//             2. The return type of the function. This must be one of the variant names in hl_ReturnType
//                  Note: This macro does not work for functions that return VecBytes or ByteChunks. Instead,
//                  use `hl_register_function_definition` directly. You'll also need to return
//                  a flatbuffer-encoded hl_Vec* using the various hl_flatbuffer_result_from_* functions.
//                  See c_simpleguest/main.c for an example.
//             3. The number of parameters the function takes
//             4+ The types of the parameters the function takes. The must be one of the variant names
//                in hl_ParameterType, for example i32, f64, boolean, string, vecbytes
#define HYPERLIGHT_WRAP_FUNCTION(function, return_type, paramsc, ... ) HYPERLIGHT_WRAP_FUNCTION_##paramsc(function, return_type, __VA_ARGS__)

#define HYPERLIGHT_WRAP_FUNCTION_0(function, return_type, ...) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return hl_flatbuffer_result_from_##return_type( function() \
    ); \
} \
uintptr_t _##function##_parameter_count = 0; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { 0 }; \


#define HYPERLIGHT_WRAP_FUNCTION_1(function, return_type, arg1) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1 \
    )); \
} \
uintptr_t _##function##_parameter_count = 1; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1 }; \

#define HYPERLIGHT_WRAP_FUNCTION_2(function, return_type, arg1, arg2) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return  hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1, \
        function_call->parameters[1].value.arg2 \
    )); \
} \
uintptr_t _##function##_parameter_count = 2; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1, \
    hl_ParameterType_##arg2 \
}; \


#define HYPERLIGHT_WRAP_FUNCTION_3(function, return_type, arg1, arg2, arg3) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return  hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1, \
        function_call->parameters[1].value.arg2, \
        function_call->parameters[2].value.arg3 \
    )); \
} \
uintptr_t _##function##_parameter_count = 3; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1, \
    hl_ParameterType_##arg2, \
    hl_ParameterType_##arg3, \
}; \


#define HYPERLIGHT_WRAP_FUNCTION_4(function, return_type, arg1, arg2, arg3, arg4) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return  hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1, \
        function_call->parameters[1].value.arg2, \
        function_call->parameters[2].value.arg3, \
        function_call->parameters[3].value.arg4 \
    )); \
} \
uintptr_t _##function##_parameter_count = 4; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1, \
    hl_ParameterType_##arg2, \
    hl_ParameterType_##arg3, \
    hl_ParameterType_##arg4, \
}; \

#define HYPERLIGHT_WRAP_FUNCTION_5(function, return_type, arg1, arg2, arg3, arg4, arg5) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return  hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1, \
        function_call->parameters[1].value.arg2, \
        function_call->parameters[2].value.arg3, \
        function_call->parameters[3].value.arg4, \
        function_call->parameters[4].value.arg5 \
    )); \
} \
uintptr_t _##function##_parameter_count = 5; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1, \
    hl_ParameterType_##arg2, \
    hl_ParameterType_##arg3, \
    hl_ParameterType_##arg4, \
    hl_ParameterType_##arg5, \
}; \

#define HYPERLIGHT_WRAP_FUNCTION_6(function, return_type, arg1, arg2, arg3, arg4, arg5, arg6) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return  hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1, \
        function_call->parameters[1].value.arg2, \
        function_call->parameters[2].value.arg3, \
        function_call->parameters[3].value.arg4, \
        function_call->parameters[4].value.arg5, \
        function_call->parameters[5].value.arg6 \
    )); \
} \
uintptr_t _##function##_parameter_count = 6; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1, \
    hl_ParameterType_##arg2, \
    hl_ParameterType_##arg3, \
    hl_ParameterType_##arg4, \
    hl_ParameterType_##arg5, \
    hl_ParameterType_##arg6, \
}; \

#define HYPERLIGHT_WRAP_FUNCTION_7(function, return_type, arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return  hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1, \
        function_call->parameters[1].value.arg2, \
        function_call->parameters[2].value.arg3, \
        function_call->parameters[3].value.arg4, \
        function_call->parameters[4].value.arg5, \
        function_call->parameters[5].value.arg6, \
        function_call->parameters[6].value.arg7 \
    )); \
} \
uintptr_t _##function##_parameter_count = 7; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1, \
    hl_ParameterType_##arg2, \
    hl_ParameterType_##arg3, \
    hl_ParameterType_##arg4, \
    hl_ParameterType_##arg5, \
    hl_ParameterType_##arg6, \
    hl_ParameterType_##arg7, \
}; \

#define HYPERLIGHT_WRAP_FUNCTION_8(function, return_type, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return  hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1, \
        function_call->parameters[1].value.arg2, \
        function_call->parameters[2].value.arg3, \
        function_call->parameters[3].value.arg4, \
        function_call->parameters[4].value.arg5, \
        function_call->parameters[5].value.arg6, \
        function_call->parameters[6].value.arg7, \
        function_call->parameters[7].value.arg8 \
    )); \
} \
uintptr_t _##function##_parameter_count = 8; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1, \
    hl_ParameterType_##arg2, \
    hl_ParameterType_##arg3, \
    hl_ParameterType_##arg4, \
    hl_ParameterType_##arg5, \
    hl_ParameterType_##arg6, \
    hl_ParameterType_##arg7, \
    hl_ParameterType_##arg8, \
}; \

#define HYPERLIGHT_WRAP_FUNCTION_9(function, return_type, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return  hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1, \
        function_call->parameters[1].value.arg2, \
        function_call->parameters[2].value.arg3, \
        function_call->parameters[3].value.arg4, \
        function_call->parameters[4].value.arg5, \
        function_call->parameters[5].value.arg6, \
        function_call->parameters[6].value.arg7, \
        function_call->parameters[7].value.arg8, \
        function_call->parameters[8].value.arg9 \
    )); \
} \
uintptr_t _##function##_parameter_count = 9; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1, \
    hl_ParameterType_##arg2, \
    hl_ParameterType_##arg3, \
    hl_ParameterType_##arg4, \
    hl_ParameterType_##arg5, \
    hl_ParameterType_##arg6, \
    hl_ParameterType_##arg7, \
    hl_ParameterType_##arg8, \
    hl_ParameterType_##arg9, \
}; \

#define HYPERLIGHT_WRAP_FUNCTION_10(function, return_type, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return  hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1, \
        function_call->parameters[1].value.arg2, \
        function_call->parameters[2].value.arg3, \
        function_call->parameters[3].value.arg4, \
        function_call->parameters[4].value.arg5, \
        function_call->parameters[5].value.arg6, \
        function_call->parameters[6].value.arg7, \
        function_call->parameters[7].value.arg8, \
        function_call->parameters[8].value.arg9, \
        function_call->parameters[9].value.arg10 \
    )); \
} \
uintptr_t _##function##_parameter_count = 10; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1, \
    hl_ParameterType_##arg2, \
    hl_ParameterType_##arg3, \
    hl_ParameterType_##arg4, \
    hl_ParameterType_##arg5, \
    hl_ParameterType_##arg6, \
    hl_ParameterType_##arg7, \
    hl_ParameterType_##arg8, \
    hl_ParameterType_##arg9, \
    hl_ParameterType_##arg10, \
}; \

#define HYPERLIGHT_WRAP_FUNCTION_11(function, return_type, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11) \
hl_Vec  *_call_##function(const hl_FunctionCall *function_call) \
{ \
    return  hl_flatbuffer_result_from_##return_type( function( \
        function_call->parameters[0].value.arg1, \
        function_call->parameters[1].value.arg2, \
        function_call->parameters[2].value.arg3, \
        function_call->parameters[3].value.arg4, \
        function_call->parameters[4].value.arg5, \
        function_call->parameters[5].value.arg6, \
        function_call->parameters[6].value.arg7, \
        function_call->parameters[7].value.arg8, \
        function_call->parameters[8].value.arg9, \
        function_call->parameters[9].value.arg10, \
        function_call->parameters[10].value.arg11 \
    )); \
} \
uintptr_t _##function##_parameter_count = 11; \
hl_ReturnType _##function##_return_type = hl_ReturnType_##return_type; \
hl_ParameterType _##function##_parameter_types[] = { hl_ParameterType_##arg1, \
    hl_ParameterType_##arg2, \
    hl_ParameterType_##arg3, \
    hl_ParameterType_##arg4, \
    hl_ParameterType_##arg5, \
    hl_ParameterType_##arg6, \
    hl_ParameterType_##arg7, \
    hl_ParameterType_##arg8, \
    hl_ParameterType_##arg9, \
    hl_ParameterType_##arg10, \
    hl_ParameterType_##arg11, \
}; \

// Registers a guest function.
// Note that the function must first have been defined using the HYPERLIGHT_WRAP_FUNCTION macro
#define HYPERLIGHT_REGISTER_FUNCTION(name, function)   hl_register_function_definition( name, &_call_##function, _##function##_parameter_count, _##function##_parameter_types, _##function##_return_type )

#endif  /* HYPERLIGHT_GUEST_MACRO_H */
