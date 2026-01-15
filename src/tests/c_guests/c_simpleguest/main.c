// Included from hyperlight_guest_capi/include
#include "hyperlight_guest.h"
// Included from hyperlight_guest_bin/third_party/libc
#include "stdint.h"
#include "string.h"
#include "stdlib.h"
#include "assert.h"
// Included from hyperlight_guest_bin/third_party/printf
#include "printf.h"

// ============================================================================
// Time API tests - exercise the POSIX-style C time functions from hyperlight_guest_capi
// ============================================================================

// Check if the paravirtualized clock is available
int is_clock_available(void) {
    hl_timespec ts;
    return clock_gettime(hl_CLOCK_REALTIME, &ts) == 0 ? 1 : 0;
}

// Get the current monotonic time in nanoseconds
uint64_t monotonic_time_ns(void) {
    hl_timespec ts;
    if (clock_gettime(hl_CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Get the current wall clock time in nanoseconds (UTC since Unix epoch)
uint64_t wall_clock_time_ns(void) {
    hl_timespec ts;
    if (clock_gettime(hl_CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Test that monotonic time increases between reads
int monotonic_increases(void) {
    hl_timespec ts1, ts2;
    
    if (clock_gettime(hl_CLOCK_MONOTONIC, &ts1) != 0) {
        return 0;
    }
    
    // Small busy loop to ensure time passes
    for (volatile int i = 0; i < 10000; i++) {}
    
    if (clock_gettime(hl_CLOCK_MONOTONIC, &ts2) != 0) {
        return 0;
    }
    
    // Second reading should be > first
    uint64_t t1 = (uint64_t)ts1.tv_sec * 1000000000ULL + (uint64_t)ts1.tv_nsec;
    uint64_t t2 = (uint64_t)ts2.tv_sec * 1000000000ULL + (uint64_t)ts2.tv_nsec;
    
    return t2 > t1 ? 1 : 0;
}

// Get the UTC offset in seconds
int utc_offset_seconds(void) {
    hl_timeval tv;
    hl_timezone tz;
    if (gettimeofday(&tv, &tz) != 0) {
        return 0;
    }
    // tz_minuteswest is minutes WEST of UTC, so negate and convert to seconds
    return -(tz.tz_minuteswest * 60);
}

// Static buffers for formatted strings (safe - guests are single-threaded)
static char datetime_buffer[128];
static char timestamp_buffer[128];

// Format the current local time using strftime from hyperlight_guest_capi
const char* format_current_datetime(void) {
    int64_t now = time(NULL);
    if (now == -1) {
        return "Error: clock not available";
    }
    
    hl_tm tm_local;
    if (localtime_r(&now, &tm_local) == NULL) {
        return "Error: localtime_r failed";
    }
    
    // Use strftime from the C API: "Thursday 16 January 2026 15:48:39"
    if (strftime((uint8_t*)datetime_buffer, sizeof(datetime_buffer),
                 (const uint8_t*)"%A %d %B %Y %H:%M:%S", &tm_local) == 0) {
        return "Error: strftime failed";
    }
    
    return datetime_buffer;
}

// Format a UTC timestamp (nanoseconds) using strftime
const char* format_timestamp_ns(uint64_t timestamp_ns) {
    int64_t secs = (int64_t)(timestamp_ns / 1000000000ULL);
    
    hl_tm tm_utc;
    if (gmtime_r(&secs, &tm_utc) == NULL) {
        return "Error: gmtime_r failed";
    }
    
    if (strftime((uint8_t*)timestamp_buffer, sizeof(timestamp_buffer),
                 (const uint8_t*)"%A %d %B %Y %H:%M:%S", &tm_utc) == 0) {
        return "Error: strftime failed";
    }
    
    return timestamp_buffer;
}

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

hl_Vec *twenty_four_k_in_eight_k_out(const hl_FunctionCall* params) {
  hl_Vec input = params->parameters[0].value.VecBytes;
  assert(input.len == 24 * 1024);
  return hl_flatbuffer_result_from_Bytes(input.data, 8 * 1024);
}

int guest_function(const char *from_host) {
  char guest_message[256] = "Hello from GuestFunction1, ";
  int len = strlen(from_host);
  strncat(guest_message, from_host, len);

  hl_Parameter params = {.tag = hl_ParameterType_String,
                         .value = {.String = guest_message}};
  const hl_FunctionCall host_call = {.function_name = "HostMethod1",
                                     .parameters = &params,
                                     .parameters_len = 1,
                                     .return_type = hl_ReturnType_Int};
  hl_call_host_function(&host_call);
  hl_get_host_return_value_as_Int();

  return 0;
}

bool guest_fn_checks_if_host_returns_bool_value(int32_t a, int32_t b) {
  hl_Parameter params[2];

  params[0].tag = hl_ParameterType_Int;
  params[0].value.Int = a;

  params[1].tag = hl_ParameterType_Int;
  params[1].value.Int = b;

  const hl_FunctionCall host_call = {.function_name = "HostBool",
                                     .parameters = params,
                                     .parameters_len = 2,
                                     .return_type = hl_ReturnType_Bool
                                    };
  hl_call_host_function(&host_call);                                 
  return hl_get_host_return_value_as_Bool();
}

float guest_fn_checks_if_host_returns_float_value(float a, float b) {
  hl_Parameter params[2];

  params[0].tag = hl_ParameterType_Float;
  params[0].value.Float = a;

  params[1].tag = hl_ParameterType_Float;
  params[1].value.Float = b;

  const hl_FunctionCall host_call = {.function_name = "HostAddFloat",
                                     .parameters = params,
                                     .parameters_len = 2,
                                     .return_type = hl_ReturnType_Float
                                    };
  hl_call_host_function(&host_call); 
  return hl_get_host_return_value_as_Float();
}

double guest_fn_checks_if_host_returns_double_value(double a, double b) {
  hl_Parameter params[2];

  params[0].tag = hl_ParameterType_Double;
  params[0].value.Double = a;

  params[1].tag = hl_ParameterType_Double;
  params[1].value.Double = b;

  const hl_FunctionCall host_call = {.function_name = "HostAddDouble",
                                     .parameters = params,
                                     .parameters_len = 2,
                                     .return_type = hl_ReturnType_Double
                                    };
  hl_call_host_function(&host_call); 
  return hl_get_host_return_value_as_Double();
}

const char* guest_fn_checks_if_host_returns_string_value() {
  char guest_message[256] = "Guest Function";
  hl_Parameter params;

  params.tag = hl_ParameterType_String;
  params.value.String = guest_message;

  const hl_FunctionCall host_call = {.function_name = "HostAddStrings",
                                     .parameters = &params,
                                     .parameters_len = 1,
                                     .return_type = hl_ReturnType_String
                                    };
  hl_call_host_function(&host_call); 
  return hl_get_host_return_value_as_String();
}

HYPERLIGHT_WRAP_FUNCTION(guest_fn_checks_if_host_returns_float_value, Float, 2, Float, Float)
HYPERLIGHT_WRAP_FUNCTION(guest_fn_checks_if_host_returns_double_value, Double, 2, Double, Double)
HYPERLIGHT_WRAP_FUNCTION(guest_fn_checks_if_host_returns_string_value, String, 0)
HYPERLIGHT_WRAP_FUNCTION(guest_fn_checks_if_host_returns_bool_value, Bool, 2, Int, Int)
HYPERLIGHT_WRAP_FUNCTION(echo, String, 1, String)
// HYPERLIGHT_WRAP_FUNCTION(set_byte_array_to_zero, 1, VecBytes) is not valid for functions that return VecBytes
HYPERLIGHT_WRAP_FUNCTION(guest_function, Int, 1, String)
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
// Time API test functions
HYPERLIGHT_WRAP_FUNCTION(is_clock_available, Int, 0)
HYPERLIGHT_WRAP_FUNCTION(monotonic_time_ns, ULong, 0)
HYPERLIGHT_WRAP_FUNCTION(wall_clock_time_ns, ULong, 0)
HYPERLIGHT_WRAP_FUNCTION(monotonic_increases, Int, 0)
HYPERLIGHT_WRAP_FUNCTION(utc_offset_seconds, Int, 0)
HYPERLIGHT_WRAP_FUNCTION(format_current_datetime, String, 0)
HYPERLIGHT_WRAP_FUNCTION(format_timestamp_ns, String, 1, ULong)
// HYPERLIGHT_WRAP_FUNCTION(get_size_prefixed_buffer, Int, 1, VecBytes) is not valid for functions that return VecBytes
HYPERLIGHT_WRAP_FUNCTION(guest_abort_with_msg, Int, 2, Int, String)
HYPERLIGHT_WRAP_FUNCTION(guest_abort_with_code, Int, 1, Int)
HYPERLIGHT_WRAP_FUNCTION(execute_on_stack, Int, 0)
HYPERLIGHT_WRAP_FUNCTION(log_message, Int, 2, String, Long)
// HYPERLIGHT_WRAP_FUNCTION(twenty_four_k_in_eight_k_out, VecBytes, 1, VecBytes) is not valid for functions that return VecBytes

void hyperlight_main(void)
{
    HYPERLIGHT_REGISTER_FUNCTION("GuestRetrievesFloatValue", guest_fn_checks_if_host_returns_float_value);
    HYPERLIGHT_REGISTER_FUNCTION("GuestRetrievesDoubleValue", guest_fn_checks_if_host_returns_double_value);
    HYPERLIGHT_REGISTER_FUNCTION("GuestRetrievesStringValue", guest_fn_checks_if_host_returns_string_value);
    HYPERLIGHT_REGISTER_FUNCTION("GuestRetrievesBoolValue", guest_fn_checks_if_host_returns_bool_value);
    HYPERLIGHT_REGISTER_FUNCTION("Echo", echo);
    // HYPERLIGHT_REGISTER_FUNCTION macro does not work for functions that return VecBytes,
    // so we use hl_register_function_definition directly
    hl_register_function_definition("SetByteArrayToZero", set_byte_array_to_zero, 1, (hl_ParameterType[]){hl_ParameterType_VecBytes}, hl_ReturnType_VecBytes);
    HYPERLIGHT_REGISTER_FUNCTION("GuestMethod1", guest_function);
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
    // Time API test functions
    HYPERLIGHT_REGISTER_FUNCTION("TestClockAvailable", is_clock_available);
    HYPERLIGHT_REGISTER_FUNCTION("GetMonotonicTimeNs", monotonic_time_ns);
    HYPERLIGHT_REGISTER_FUNCTION("GetWallClockTimeNs", wall_clock_time_ns);
    HYPERLIGHT_REGISTER_FUNCTION("TestMonotonicIncreases", monotonic_increases);
    HYPERLIGHT_REGISTER_FUNCTION("GetUtcOffsetSeconds", utc_offset_seconds);
    HYPERLIGHT_REGISTER_FUNCTION("FormatCurrentDateTime", format_current_datetime);
    HYPERLIGHT_REGISTER_FUNCTION("FormatTimestampNs", format_timestamp_ns);
    // HYPERLIGHT_REGISTER_FUNCTION macro does not work for functions that return VecBytes,
    // so we use hl_register_function_definition directly
    hl_register_function_definition("GetSizePrefixedBuffer", get_size_prefixed_buffer, 1, (hl_ParameterType[]){hl_ParameterType_VecBytes}, hl_ReturnType_VecBytes);
    HYPERLIGHT_REGISTER_FUNCTION("GuestAbortWithCode", guest_abort_with_code);
    HYPERLIGHT_REGISTER_FUNCTION("GuestAbortWithMessage", guest_abort_with_msg);
    HYPERLIGHT_REGISTER_FUNCTION("ExecuteOnStack", execute_on_stack);
    HYPERLIGHT_REGISTER_FUNCTION("LogMessage", log_message);
    // HYPERLIGHT_REGISTER_FUNCTION macro does not work for functions that return VecBytes,
    // so we use hl_register_function_definition directly
    hl_register_function_definition("24K_in_8K_out", twenty_four_k_in_eight_k_out, 1, (hl_ParameterType[]){hl_ParameterType_VecBytes}, hl_ReturnType_VecBytes);
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
