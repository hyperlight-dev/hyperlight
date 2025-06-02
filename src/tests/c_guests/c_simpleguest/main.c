// Included from hyperlight_guest_capi/include
#include "hyperlight_guest.h"
// Included from hyperlight_guest_bin/third_party/libc
#include "stdint.h"
#include "string.h"
#include "stdlib.h"
// Included from hyperlight_guest_bin/third_party/printf
#include "printf.h"

#define GUEST_STACK_SIZE (65536) // default stack size
#define MAX_BUFFER_SIZE (1024)

static char big_array[1024 * 1024] = {0};

const char *echo(const char *str) { return str; }

float echo_float(float f) { return f; }

double echo_double(double d) { return d; }

hl_Vec *set_byte_array_to_zero(const hl_FunctionCall* params) {
  hl_Vec input = params->parameters[0].value.VecBytes;
  uint8_t *x = malloc(input.len);
  for (uintptr_t i = 0; i < input.len; i++) {
    x[i] = 0;
  }
  return hl_flatbuffer_result_from_Bytes(x, input.len);
}

int print_output(const char *message) {
  int res = printf("%s", message);
  return res;
}

__attribute__((optnone)) 
int stack_allocate(int32_t length) {
  void *buffer = alloca(length);
  (void)buffer;

  return length;
}

__attribute__((optnone)) 
void stack_overflow_helper(int32_t i) {
  if (i == 0) {
    return;
  }
  char nums[16384] = {i};
  (void)nums;

  stack_overflow_helper(i - 1);
}

__attribute__((optnone)) 
int stack_overflow(int32_t i) {
  stack_overflow_helper(i);

  return i;
}

int buffer_overrun(const char *String) {
  char buffer[17];
  (void)buffer;
  int length = strlen(String);

  if (length > 0) {
    strncpy(buffer, String, length);
  }
  int result = (int)(17 - length);

  return result;
}

__attribute__((optnone)) 
int large_var(void) {
  char buffer[GUEST_STACK_SIZE + 1] = {0};
  (void)buffer;

  return GUEST_STACK_SIZE;
}

int small_var(void) {
  char buffer[1024] = {0};
  (void)buffer;

  return 1024;
}

int call_malloc(int32_t size) {
  void *heap_memory = malloc(size);
  if (NULL == heap_memory) {
    hl_set_error(hl_ErrorCode_GuestError, "Malloc Failed");
  }

  return size;
}

int malloc_and_free(int32_t size) {
  void *heap_memory = malloc(size);
  if (NULL == heap_memory) {
    hl_set_error(hl_ErrorCode_GuestError, "Malloc Failed");
  }

  free(heap_memory);

  return size;
}

int print_two_args(const char *arg1, int32_t arg2) {
  int result = printf("Message: arg1:%s arg2:%d.", arg1, arg2);

  return result;
}

int print_three_args(const char *arg1, int32_t arg2, int64_t arg3) {
  int result = printf("Message: arg1:%s arg2:%d arg3:%d.", arg1, arg2, arg3);

  return result;
}

 int print_four_args(const char *arg1, int32_t arg2, int64_t arg3,
                        const char *arg4) {
  int result = printf("Message: arg1:%s arg2:%d arg3:%d arg4:%s.", arg1, arg2,
                      arg3, arg4);

  return result;
}

 int print_five_args(const char *arg1, int32_t arg2, int64_t arg3,
                        const char *arg4, const char *arg5) {
  int result = printf("Message: arg1:%s arg2:%d arg3:%d arg4:%s arg5:%s.", arg1,
                      arg2, arg3, arg4, arg5);

  return result;
}

 int print_six_args(const char *arg1, int32_t arg2, int64_t arg3,
                       const char *arg4, const char *arg5, bool arg6) {
  int result =
      printf("Message: arg1:%s arg2:%d arg3:%d arg4:%s arg5:%s arg6:%s.", arg1,
             arg2, arg3, arg4, arg5, arg6 ? "true" : "false");

  return result;
}

 int print_seven_args(const char *arg1, int32_t arg2, int64_t arg3,
                         const char *arg4, const char *arg5, bool arg6,
                         bool arg7) {
  int result = printf(
      "Message: arg1:%s arg2:%d arg3:%d arg4:%s arg5:%s arg6:%s arg7:%s.", arg1,
      arg2, arg3, arg4, arg5, arg6 ? "true" : "false", arg7 ? "true" : "false");

  return result;
}

 int print_eight_args(const char *arg1, int32_t arg2, int64_t arg3,
                         const char *arg4, const char *arg5, bool arg6,
                         bool arg7, uint32_t arg8) {
  int result = printf("Message: arg1:%s arg2:%d arg3:%d arg4:%s arg5:%s "
                      "arg6:%s arg7:%s arg8:%d.",
                      arg1, arg2, arg3, arg4, arg5, arg6 ? "true" : "false",
                      arg7 ? "true" : "false", arg8);

  return result;
}

 int print_nine_args(const char *arg1, int32_t arg2, int64_t arg3,
                        const char *arg4, const char *arg5, bool arg6,
                        bool arg7, uint32_t arg8, uint64_t arg9) {
  int result = printf("Message: arg1:%s arg2:%d arg3:%d arg4:%s arg5:%s "
                      "arg6:%s arg7:%s arg8:%d arg9:%d.",
                      arg1, arg2, arg3, arg4, arg5, arg6 ? "true" : "false",
                      arg7 ? "true" : "false", arg8, arg9);

  return result;
}

 int print_ten_args(const char *arg1, int32_t arg2, int64_t arg3,
                       const char *arg4, const char *arg5, bool arg6, bool arg7,
                       uint32_t arg8, uint64_t arg9, int32_t arg10) {
  int result = printf("Message: arg1:%s arg2:%d arg3:%d arg4:%s arg5:%s "
                      "arg6:%s arg7:%s arg8:%d arg9:%d arg10:%d.",
                      arg1, arg2, arg3, arg4, arg5, arg6 ? "true" : "false",
                      arg7 ? "true" : "false", arg8, arg9, arg10);

  return result;
}

 int print_eleven_args(const char *arg1, int32_t arg2, int64_t arg3,
                          const char *arg4, const char *arg5, bool arg6,
                          bool arg7, uint32_t arg8, uint64_t arg9,
                          int32_t arg10, float arg11) {
  int result = printf("Message: arg1:%s arg2:%d arg3:%d arg4:%s arg5:%s "
                      "arg6:%s arg7:%s arg8:%d arg9:%d arg10:%d arg11:%.3f.",
                      arg1, arg2, arg3, arg4, arg5, arg6 ? "true" : "false",
                      arg7 ? "true" : "false", arg8, arg9, arg10, arg11);

  return result;
}

int set_static(void) {
  int length = sizeof(big_array);
  for (int l = 0; l < length; l++) {
    big_array[l] = l;
  }
  return length;
}

hl_Vec *get_size_prefixed_buffer(const hl_FunctionCall* params) {
  hl_Vec input = params->parameters[0].value.VecBytes;
  return hl_flatbuffer_result_from_Bytes(input.data, input.len);
}

int guest_abort_with_code(int32_t code) {
  hl_abort_with_code(code);
  return -1;
}

int guest_abort_with_msg(int32_t code, const char *message) {
  hl_abort_with_code_and_message(code, message);
  return -1;
}

int execute_on_stack(void) {
  uint8_t hlt = 0xF4;
  ((void (*)()) & hlt)();
  return -1;
}

int log_message(const char *message, int64_t level) {
  LOG((hl_Level)level, message);
  return -1;
}

HYPERLIGHT_WRAP_FUNCTION(echo, String, 1, String)
// HYPERLIGHT_WRAP_FUNCTION(set_byte_array_to_zero, 1, VecBytes) is not valid for functions that return VecBytes
HYPERLIGHT_WRAP_FUNCTION(print_output, Int, 1, String)
HYPERLIGHT_WRAP_FUNCTION(stack_allocate, Int, 1, Int)
HYPERLIGHT_WRAP_FUNCTION(stack_overflow, Int, 1, Int)
HYPERLIGHT_WRAP_FUNCTION(buffer_overrun, Int, 1, String)
HYPERLIGHT_WRAP_FUNCTION(large_var, Int, 0)
HYPERLIGHT_WRAP_FUNCTION(small_var, Int, 0) 
HYPERLIGHT_WRAP_FUNCTION(call_malloc, Int, 1, Int)
HYPERLIGHT_WRAP_FUNCTION(malloc_and_free, Int, 1, Int)
HYPERLIGHT_WRAP_FUNCTION(print_two_args, Int, 2, String, Int)
HYPERLIGHT_WRAP_FUNCTION(print_three_args, Int, 3, String, Int, Long)
HYPERLIGHT_WRAP_FUNCTION(print_four_args, Int, 4, String, Int, Long, String)
HYPERLIGHT_WRAP_FUNCTION(print_five_args, Int, 5, String, Int, Long, String, String)
HYPERLIGHT_WRAP_FUNCTION(print_six_args, Int, 6, String, Int, Long, String, String, Bool)
HYPERLIGHT_WRAP_FUNCTION(print_seven_args, Int, 7, String, Int, Long, String, String, Bool, Bool)
HYPERLIGHT_WRAP_FUNCTION(print_eight_args, Int, 8, String, Int, Long, String, String, Bool, Bool, UInt)
HYPERLIGHT_WRAP_FUNCTION(print_nine_args, Int, 9, String, Int, Long, String, String, Bool, Bool, UInt, ULong)
HYPERLIGHT_WRAP_FUNCTION(print_ten_args, Int, 10, String, Int, Long, String, String, Bool, Bool, UInt, ULong, Int)
HYPERLIGHT_WRAP_FUNCTION(print_eleven_args, Int, 11, String, Int, Long, String, String, Bool, Bool, UInt, ULong, Int, Float)
HYPERLIGHT_WRAP_FUNCTION(echo_float, Float, 1, Float)
HYPERLIGHT_WRAP_FUNCTION(echo_double, Double, 1, Double)
HYPERLIGHT_WRAP_FUNCTION(set_static, Int, 0)
// HYPERLIGHT_WRAP_FUNCTION(get_size_prefixed_buffer, Int, 1, VecBytes) is not valid for functions that return VecBytes
HYPERLIGHT_WRAP_FUNCTION(guest_abort_with_msg, Int, 2, Int, String)
HYPERLIGHT_WRAP_FUNCTION(guest_abort_with_code, Int, 1, Int)
HYPERLIGHT_WRAP_FUNCTION(execute_on_stack, Int, 0)
HYPERLIGHT_WRAP_FUNCTION(log_message, Int, 2, String, Long)

void hyperlight_main(void)
{
    HYPERLIGHT_REGISTER_FUNCTION("Echo", echo);
    // HYPERLIGHT_REGISTER_FUNCTION macro does not work for functions that return VecBytes,
    // so we use hl_register_function_definition directly
    hl_register_function_definition("SetByteArrayToZero", set_byte_array_to_zero, 1, (hl_ParameterType[]){hl_ParameterType_VecBytes}, hl_ReturnType_VecBytes);
    HYPERLIGHT_REGISTER_FUNCTION("PrintOutput", print_output);
    HYPERLIGHT_REGISTER_FUNCTION("StackAllocate", stack_allocate);
    HYPERLIGHT_REGISTER_FUNCTION("StackOverflow", stack_overflow);
    HYPERLIGHT_REGISTER_FUNCTION("BufferOverrun", buffer_overrun);
    HYPERLIGHT_REGISTER_FUNCTION("LargeVar", large_var);
    HYPERLIGHT_REGISTER_FUNCTION("SmallVar", small_var);
    HYPERLIGHT_REGISTER_FUNCTION("CallMalloc", call_malloc);
    HYPERLIGHT_REGISTER_FUNCTION("MallocAndFree", malloc_and_free);
    HYPERLIGHT_REGISTER_FUNCTION("PrintTwoArgs", print_two_args);
    HYPERLIGHT_REGISTER_FUNCTION("PrintThreeArgs", print_three_args);
    HYPERLIGHT_REGISTER_FUNCTION("PrintFourArgs", print_four_args);
    HYPERLIGHT_REGISTER_FUNCTION("PrintFiveArgs", print_five_args);
    HYPERLIGHT_REGISTER_FUNCTION("PrintSixArgs", print_six_args);
    HYPERLIGHT_REGISTER_FUNCTION("PrintSevenArgs", print_seven_args);
    HYPERLIGHT_REGISTER_FUNCTION("PrintEightArgs", print_eight_args);
    HYPERLIGHT_REGISTER_FUNCTION("PrintNineArgs", print_nine_args);
    HYPERLIGHT_REGISTER_FUNCTION("PrintTenArgs", print_ten_args);
    HYPERLIGHT_REGISTER_FUNCTION("PrintElevenArgs", print_eleven_args);
    HYPERLIGHT_REGISTER_FUNCTION("EchoFloat", echo_float);
    HYPERLIGHT_REGISTER_FUNCTION("EchoDouble", echo_double);
    HYPERLIGHT_REGISTER_FUNCTION("SetStatic", set_static);
    // HYPERLIGHT_REGISTER_FUNCTION macro does not work for functions that return VecBytes,
    // so we use hl_register_function_definition directly
    hl_register_function_definition("GetSizePrefixedBuffer", get_size_prefixed_buffer, 1, (hl_ParameterType[]){hl_ParameterType_VecBytes}, hl_ReturnType_VecBytes);
    HYPERLIGHT_REGISTER_FUNCTION("GuestAbortWithCode", guest_abort_with_code);
    HYPERLIGHT_REGISTER_FUNCTION("GuestAbortWithMessage", guest_abort_with_msg);
    HYPERLIGHT_REGISTER_FUNCTION("ExecuteOnStack", execute_on_stack);
    HYPERLIGHT_REGISTER_FUNCTION("LogMessage", log_message);
}

// This dispatch function is only used when the host dispatches a guest function
// call but there is no registered guest function with the given name.
hl_Vec *c_guest_dispatch_function(const hl_FunctionCall *function_call) {
  const char *func_name = function_call->function_name;
  if (strcmp(func_name, "ThisIsNotARealFunctionButTheNameIsImportant") == 0) {
    // TODO DO A LOG HERE
    // This is special case for test `iostack_is_working
    return hl_flatbuffer_result_from_Int(99);
  }

  return NULL;
}
