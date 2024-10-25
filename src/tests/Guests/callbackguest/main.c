/*
Copyright 2024 The Hyperlight Authors.

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

#include "hyperlight.h"
#include <string.h>

uint8_t* sendMessagetoHostMethod(char* methodName, char* guestMessage, const char* message)
{
#pragma warning(suppress:4244)
    char* messageToHost = strncat(guestMessage, message, strlen(message));
    int result = native_symbol_thunk_returning_int(methodName, 1, messageToHost);
    return GetFlatBufferResultFromInt(result);
}

uint8_t* guestFunction(const char *message)
{ 
    char guestMessage[256] = "Hello from GuestFunction, ";
    return sendMessagetoHostMethod("HostMethod", guestMessage, message);
}

uint8_t* guestFunction1(const char* message)
{
    char guestMessage[256] = "Hello from GuestFunction1, ";
    return sendMessagetoHostMethod("HostMethod1", guestMessage, message);
}

uint8_t* guestFunction2(const char* message)
{
    char guestMessage[256] = "Hello from GuestFunction2, ";
    return sendMessagetoHostMethod("HostMethod1", guestMessage, message);
}

uint8_t* guestFunction3(const char* message)
{
    char guestMessage[256] = "Hello from GuestFunction3, ";
    return sendMessagetoHostMethod("HostMethod1", guestMessage, message);
}

uint8_t* guestFunction4()
{
    char guestMessage[256] = "Hello from GuestFunction4";
    native_symbol_thunk("HostMethod4", 1,  guestMessage);
    return GetFlatBufferResultFromVoid();
}

// TODO: update to support void return 
uint8_t* logMessage(const char* message, const char* source, int logLevel)
{
    if (logLevel < 0 || logLevel > 6)
    {
        logLevel = 0;
    }
    LOG((LogLevel)logLevel, message, source);
    int result = (int)strlen(message);
    return GetFlatBufferResultFromInt(result);
}

uint8_t* callErrorMethod(const char* message)
{
    char guestMessage[256] = "Error From Host: ";
    return sendMessagetoHostMethod("ErrorMethod", guestMessage, message);
}

// Calls a method in the host that should keep the CPU busy forever

uint8_t* callHostSpin()
{
    native_symbol_thunk("Spin", 0);
    return GetFlatBufferResultFromVoid();
}

GENERATE_FUNCTION(printOutputAsGuestFunction, 1, hlstring);
GENERATE_FUNCTION(guestFunction, 1, hlstring);
GENERATE_FUNCTION(guestFunction1, 1, hlstring);
GENERATE_FUNCTION(guestFunction2, 1, hlstring);
GENERATE_FUNCTION(guestFunction3, 1, hlstring);
GENERATE_FUNCTION(guestFunction4, 0);
GENERATE_FUNCTION(logMessage, 3, hlstring, hlstring, hlint);
GENERATE_FUNCTION(callErrorMethod, 1, hlstring);
GENERATE_FUNCTION(callHostSpin, 0);

void HyperlightMain()
{
    RegisterFunction(FUNCTIONDETAILS("PrintOutput", printOutputAsGuestFunction));
    RegisterFunction(FUNCTIONDETAILS("GuestMethod", guestFunction));
    RegisterFunction(FUNCTIONDETAILS("GuestMethod1", guestFunction1));
    RegisterFunction(FUNCTIONDETAILS("GuestMethod2", guestFunction2));
    RegisterFunction(FUNCTIONDETAILS("GuestMethod3", guestFunction3));
    RegisterFunction(FUNCTIONDETAILS("GuestMethod4", guestFunction4));
    RegisterFunction(FUNCTIONDETAILS("LogMessage", logMessage));
    RegisterFunction(FUNCTIONDETAILS("CallErrorMethod", callErrorMethod));
    RegisterFunction(FUNCTIONDETAILS("CallHostSpin", callHostSpin));
}
