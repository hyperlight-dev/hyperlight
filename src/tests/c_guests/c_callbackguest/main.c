// Included from hyperlight_guest_capi/include
#include "hyperlight_guest.h"
// Included from hyperlight_guest_bin/third_party/libc
#include "stdint.h"
#include "stdio.h"
#include "string.h"
// Included from hyperlight_guest_bin/third_party/printf
#include "printf.h"

int print_output(const char *message) {
  int res = printf("%s", message);

  return res;
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

HYPERLIGHT_WRAP_FUNCTION(print_output, Int, 1, String);
HYPERLIGHT_WRAP_FUNCTION(guest_function, Int, 1, String);

void hyperlight_main(void) {
  HYPERLIGHT_REGISTER_FUNCTION("PrintOutput", print_output);
  HYPERLIGHT_REGISTER_FUNCTION("GuestMethod1", guest_function);
}

// This dispatch function is only used when the host dispatches a guest function
// call but there is no registered guest function with the given name.
hl_Vec *c_guest_dispatch_function(const hl_FunctionCall *function_call) {
  const char *func_name = function_call->function_name;
  if (strcmp(func_name, "ThisIsNotARealFunctionButTheNameIsImportant") == 0) {
    // This is special case for test `iostack_is_working
    return hl_flatbuffer_result_from_Int(99);
  }

  return NULL;
}
