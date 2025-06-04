# A printf / sprintf Implementation for Embedded Systems

[![Build Status](https://travis-ci.org/mpaland/printf.svg?branch=master)](https://travis-ci.org/mpaland/printf)
[![codecov](https://codecov.io/gh/mpaland/printf/branch/master/graph/badge.svg)](https://codecov.io/gh/mpaland/printf)
[![Coverity Status](https://img.shields.io/coverity/scan/14180.svg)](https://scan.coverity.com/projects/mpaland-printf)
[![Github Issues](https://img.shields.io/github/issues/mpaland/printf.svg)](http://github.com/mpaland/printf/issues)
[![Github Releases](https://img.shields.io/github/release/mpaland/printf.svg)](https://github.com/mpaland/printf/releases)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/mpaland/avl_array/master/LICENSE)

This is a tiny but **fully loaded** printf, sprintf and (v)snprintf implementation.
Primarily designed for usage in embedded systems, where printf is not available due to memory issues or in avoidance of linking against libc.
Using the standard libc printf may pull **a lot** of unwanted library stuff and can bloat code size about 20k or is not 100% thread safe. In this cases the following implementation can be used.
Absolutely **NO dependencies** are required, *printf.c* brings all necessary routines, even its own fast `ftoa` (floating point), `ntoa` (decimal) conversion.

If memory footprint is really a critical issue, floating point, exponential and 'long long' support and can be turned off via the `PRINTF_DISABLE_SUPPORT_FLOAT`, `PRINTF_DISABLE_SUPPORT_EXPONENTIAL` and `PRINTF_DISABLE_SUPPORT_LONG_LONG` compiler switches.
When using printf (instead of sprintf/snprintf) you have to provide your own `_putchar()` low level function as console/serial output.


## Highlights and Design Goals

There is a boatload of so called 'tiny' printf implementations around. So why this one?
I've tested many implementations, but most of them have very limited flag/specifier support, a lot of other dependencies or are just not standard compliant and failing most of the test suite.
Therefore I decided to write an own, final implementation which meets the following items:

 - Very small implementation (around 600 code lines)
 - NO dependencies, no libs, just one module file
 - Support of all important flags, width and precision sub-specifiers (see below)
 - Support of decimal/floating number representation (with an own fast itoa/ftoa)
 - Reentrant and thread-safe, malloc free, no static vars/buffers
 - LINT and compiler L4 warning free, mature, coverity clean, automotive ready
 - Extensive test suite (> 400 test cases) passing
 - Simply the best *printf* around the net
 - MIT license


## Usage

Add/link *printf.c* to your project and include *printf.h*. That's it.
Implement your low level output function needed for `printf()`:
```C
void _putchar(char character)
{
  // send char to console etc.
}
```

Usage is 1:1 like the according stdio.h library version:
```C
int printf(const char* format, ...);
int sprintf(char* buffer, const char* format, ...);
int snprintf(char* buffer, size_t count, const char* format, ...);
int vsnprintf(char* buffer, size_t count, const char* format, va_list va);

// use output function (instead of buffer) for streamlike interface
int fctprintf(void (*out)(char character, void* arg), void* arg, const char* format, ...);
```

**Due to general security reasons it is highly recommended to prefer and use `snprintf` (with the max buffer size as `count` parameter) instead of `sprintf`.**
`sprintf` has no buffer limitation, so when needed - use it really with care!

### Streamlike Usage
Besides the regular standard `printf()` functions, this module also provides `fctprintf()`, which takes an output function as first parameter to build a streamlike output like `fprintf()`:
```C
// define the output function
void my_stream_output(char character, void* arg)
{
  // opt. evaluate the argument and send the char somewhere
}

{
  // in your code
  void* arg = (void*)100;  // this argument is passed to the output function
  fctprintf(&my_stream_output, arg, "This is a test: %X", 0xAA);
  fctprintf(&my_stream_output, nullptr, "Send to null dev");
}
```

## Format Specifiers

A format specifier follows this prototype: `%[flags][width][.precision][length]type`
The following format specifiers are supported:


### Supported Types

| Type   | Output |
|--------|--------|
| d or i | Signed decimal integer |
| u      | Unsigned decimal integer	|
| b      | Unsigned binary |
| o      | Unsigned octal |
| x      | Unsigned hexadecimal integer (lowercase) |
| X      | Unsigned hexadecimal integer (uppercase) |
| f or F | Decimal floating point |
| e or E | Scientific-notation (exponential) floating point |
| g or G | Scientific or decimal floating point |
| c      | Single character |
| s      | String of characters |
| p      | Pointer address |
| %      | A % followed by another % character will write a single % |


### Supported Flags

| Flags | Description |
|-------|-------------|
| -     | Left-justify within the given field width; Right justification is the default. |
| +     | Forces to precede the result with a plus or minus sign (+ or -) even for positive numbers.<br>By default, only negative numbers are preceded with a - sign. |
| (space) | If no sign is going to be written, a blank space is inserted before the value. |
| #     | Used with o, b, x or X specifiers the value is preceded with 0, 0b, 0x or 0X respectively for values different than zero.<br>Used with f, F it forces the written output to contain a decimal point even if no more digits follow. By default, if no digits follow, no decimal point is written. |
| 0     | Left-pads the number with zeros (0) instead of spaces when padding is specified (see width sub-specifier). |


### Supported Width

| Width    | Description |
|----------|-------------|
| (number) | Minimum number of characters to be printed. If the value to be printed is shorter than this number, the result is padded with blank spaces. The value is not truncated even if the result is larger. |
| *        | The width is not specified in the format string, but as an additional integer value argument preceding the argument that has to be formatted. |


### Supported Precision

| Precision	| Description |
|-----------|-------------|
| .number   | For integer specifiers (d, i, o, u, x, X): precision specifies the minimum number of digits to be written. If the value to be written is shorter than this number, the result is padded with leading zeros. The value is not truncated even if the result is longer. A precision of 0 means that no character is written for the value 0.<br>For f and F specifiers: this is the number of digits to be printed after the decimal point. **By default, this is 6, maximum is 9**.<br>For s: this is the maximum number of characters to be printed. By default all characters are printed until the ending null character is encountered.<br>If the period is specified without an explicit value for precision, 0 is assumed. |
| .*        | The precision is not specified in the format string, but as an additional integer value argument preceding the argument that has to be formatted. |


### Supported Length

The length sub-specifier modifies the length of the data type.

| Length | d i  | u o x X |
|--------|------|---------|
| (none) | int  | unsigned int |
| hh     | char | unsigned char |
| h      | short int | unsigned short int |
| l      | long int | unsigned long int |
| ll     | long long int | unsigned long long int (if PRINTF_SUPPORT_LONG_LONG is defined) |
| j      | intmax_t | uintmax_t |
| z      | size_t | size_t |
| t      | ptrdiff_t | ptrdiff_t (if PRINTF_SUPPORT_PTRDIFF_T is defined) |


### Return Value

Upon successful return, all functions return the number of characters written, _excluding_ the terminating null character used to end the string.
Functions `snprintf()` and `vsnprintf()` don't write more than `count` bytes, _including_ the terminating null byte ('\0').
Anyway, if the output was truncated due to this limit, the return value is the number of characters that _could_ have been written.
Notice that a value equal or larger than `count` indicates a truncation. Only when the returned value is non-negative and less than `count`,
the string has been completely written.
If any error is encountered, `-1` is returned.

If `buffer` is set to `NULL` (`nullptr`) nothing is written and just the formatted length is returned.
```C
int length = sprintf(NULL, "Hello, world"); // length is set to 12
```


## Compiler Switches/Defines

| Name | Default value | Description |
|------|---------------|-------------|
| PRINTF_INCLUDE_CONFIG_H            | undefined | Define this as compiler switch (e.g. `gcc -DPRINTF_INCLUDE_CONFIG_H`) to include a "printf_config.h" definition file |
| PRINTF_NTOA_BUFFER_SIZE            | 32        | ntoa (integer) conversion buffer size. This must be big enough to hold one converted numeric number _including_ leading zeros, normally 32 is a sufficient value. Created on the stack |
| PRINTF_FTOA_BUFFER_SIZE            | 32        | ftoa (float) conversion buffer size. This must be big enough to hold one converted float number _including_ leading zeros, normally 32 is a sufficient value. Created on the stack |
| PRINTF_DEFAULT_FLOAT_PRECISION     | 6         | Define the default floating point precision |
| PRINTF_MAX_FLOAT                   | 1e9       | Define the largest suitable value to be printed with %f, before using exponential representation |
| PRINTF_DISABLE_SUPPORT_FLOAT       | undefined | Define this to disable floating point (%f) support |
| PRINTF_DISABLE_SUPPORT_EXPONENTIAL | undefined | Define this to disable exponential floating point (%e) support |
| PRINTF_DISABLE_SUPPORT_LONG_LONG   | undefined | Define this to disable long long (%ll) support |
| PRINTF_DISABLE_SUPPORT_PTRDIFF_T   | undefined | Define this to disable ptrdiff_t (%t) support |


## Caveats
None anymore (finally).


## Test Suite
For testing just compile, build and run the test suite located in `test/test_suite.cpp`. This uses the [catch](https://github.com/catchorg/Catch2) framework for unit-tests, which is auto-adding main().
Running with the `--wait-for-keypress exit` option waits for the enter key after test end.


## Projects Using printf
- [turnkeyboard](https://github.com/mpaland/turnkeyboard) uses printf as log and generic tty (formatting) output.
- printf is part of [embeddedartistry/libc](https://github.com/embeddedartistry/libc), a libc targeted for embedded systems usage.
- The [Hatchling Platform]( https://github.com/adrian3git/HatchlingPlatform) uses printf.
(Just send me a mail/issue/PR to get *your* project listed here)


## Contributing

0. Give this project a :star:
1. Create an issue and describe your idea
2. [Fork it](https://github.com/mpaland/printf/fork)
3. Create your feature branch (`git checkout -b my-new-feature`)
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Publish the branch (`git push origin my-new-feature`)
6. Create a new pull request
7. Profit! :heavy_check_mark:


## License
printf is written under the [MIT license](http://www.opensource.org/licenses/MIT).
