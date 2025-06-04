///////////////////////////////////////////////////////////////////////////////
// \author (c) Marco Paland (info@paland.com)
//             2017-2019, PALANDesign Hannover, Germany
//
// \license The MIT License (MIT)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// \brief printf unit tests
//
///////////////////////////////////////////////////////////////////////////////

// use the 'catch' test framework
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <string.h>
#include <sstream>
#include <math.h>


namespace test {
  // use functions in own test namespace to avoid stdio conflicts
  #include "../printf.h"
  #include "../printf.c"
} // namespace test


// dummy putchar
static char   printf_buffer[100];
static size_t printf_idx = 0U;

void test::_putchar(char character)
{
  printf_buffer[printf_idx++] = character;
}

void _out_fct(char character, void* arg)
{
  (void)arg;
  printf_buffer[printf_idx++] = character;
}


TEST_CASE("printf", "[]" ) {
  printf_idx = 0U;
  memset(printf_buffer, 0xCC, 100U);
  REQUIRE(test::printf("% d", 4232) == 5);
  REQUIRE(printf_buffer[5] == (char)0xCC);
  printf_buffer[5] = 0;
  REQUIRE(!strcmp(printf_buffer, " 4232"));
}


TEST_CASE("fctprintf", "[]" ) {
  printf_idx = 0U;
  memset(printf_buffer, 0xCC, 100U);
  test::fctprintf(&_out_fct, nullptr, "This is a test of %X", 0x12EFU);
  REQUIRE(!strncmp(printf_buffer, "This is a test of 12EF", 22U));
  REQUIRE(printf_buffer[22] == (char)0xCC);
}


TEST_CASE("snprintf", "[]" ) {
  char buffer[100];

  test::snprintf(buffer, 100U, "%d", -1000);
  REQUIRE(!strcmp(buffer, "-1000"));

  test::snprintf(buffer, 3U, "%d", -1000);
  REQUIRE(!strcmp(buffer, "-1"));
}

static void vprintf_builder_1(char* buffer, ...)
{
  va_list args;
  va_start(args, buffer);
  test::vprintf("%d", args);
  va_end(args);
}

static void vsnprintf_builder_1(char* buffer, ...)
{
  va_list args;
  va_start(args, buffer);
  test::vsnprintf(buffer, 100U, "%d", args);
  va_end(args);
}

static void vsnprintf_builder_3(char* buffer, ...)
{
  va_list args;
  va_start(args, buffer);
  test::vsnprintf(buffer, 100U, "%d %d %s", args);
  va_end(args);
}


TEST_CASE("vprintf", "[]" ) {
  char buffer[100];
  printf_idx = 0U;
  memset(printf_buffer, 0xCC, 100U);
  vprintf_builder_1(buffer, 2345);
  REQUIRE(printf_buffer[4] == (char)0xCC);
  printf_buffer[4] = 0;
  REQUIRE(!strcmp(printf_buffer, "2345"));
}


TEST_CASE("vsnprintf", "[]" ) {
  char buffer[100];

  vsnprintf_builder_1(buffer, -1);
  REQUIRE(!strcmp(buffer, "-1"));

  vsnprintf_builder_3(buffer, 3, -1000, "test");
  REQUIRE(!strcmp(buffer, "3 -1000 test"));
}


TEST_CASE("space flag", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "% d", 42);
  REQUIRE(!strcmp(buffer, " 42"));

  test::sprintf(buffer, "% d", -42);
  REQUIRE(!strcmp(buffer, "-42"));

  test::sprintf(buffer, "% 5d", 42);
  REQUIRE(!strcmp(buffer, "   42"));

  test::sprintf(buffer, "% 5d", -42);
  REQUIRE(!strcmp(buffer, "  -42"));

  test::sprintf(buffer, "% 15d", 42);
  REQUIRE(!strcmp(buffer, "             42"));

  test::sprintf(buffer, "% 15d", -42);
  REQUIRE(!strcmp(buffer, "            -42"));

  test::sprintf(buffer, "% 15d", -42);
  REQUIRE(!strcmp(buffer, "            -42"));

  test::sprintf(buffer, "% 15.3f", -42.987);
  REQUIRE(!strcmp(buffer, "        -42.987"));

  test::sprintf(buffer, "% 15.3f", 42.987);
  REQUIRE(!strcmp(buffer, "         42.987"));

  test::sprintf(buffer, "% s", "Hello testing");
  REQUIRE(!strcmp(buffer, "Hello testing"));

  test::sprintf(buffer, "% d", 1024);
  REQUIRE(!strcmp(buffer, " 1024"));

  test::sprintf(buffer, "% d", -1024);
  REQUIRE(!strcmp(buffer, "-1024"));

  test::sprintf(buffer, "% i", 1024);
  REQUIRE(!strcmp(buffer, " 1024"));

  test::sprintf(buffer, "% i", -1024);
  REQUIRE(!strcmp(buffer, "-1024"));

  test::sprintf(buffer, "% u", 1024);
  REQUIRE(!strcmp(buffer, "1024"));

  test::sprintf(buffer, "% u", 4294966272U);
  REQUIRE(!strcmp(buffer, "4294966272"));

  test::sprintf(buffer, "% o", 511);
  REQUIRE(!strcmp(buffer, "777"));

  test::sprintf(buffer, "% o", 4294966785U);
  REQUIRE(!strcmp(buffer, "37777777001"));

  test::sprintf(buffer, "% x", 305441741);
  REQUIRE(!strcmp(buffer, "1234abcd"));

  test::sprintf(buffer, "% x", 3989525555U);
  REQUIRE(!strcmp(buffer, "edcb5433"));

  test::sprintf(buffer, "% X", 305441741);
  REQUIRE(!strcmp(buffer, "1234ABCD"));

  test::sprintf(buffer, "% X", 3989525555U);
  REQUIRE(!strcmp(buffer, "EDCB5433"));

  test::sprintf(buffer, "% c", 'x');
  REQUIRE(!strcmp(buffer, "x"));
}


TEST_CASE("+ flag", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%+d", 42);
  REQUIRE(!strcmp(buffer, "+42"));

  test::sprintf(buffer, "%+d", -42);
  REQUIRE(!strcmp(buffer, "-42"));

  test::sprintf(buffer, "%+5d", 42);
  REQUIRE(!strcmp(buffer, "  +42"));

  test::sprintf(buffer, "%+5d", -42);
  REQUIRE(!strcmp(buffer, "  -42"));

  test::sprintf(buffer, "%+15d", 42);
  REQUIRE(!strcmp(buffer, "            +42"));

  test::sprintf(buffer, "%+15d", -42);
  REQUIRE(!strcmp(buffer, "            -42"));

  test::sprintf(buffer, "%+s", "Hello testing");
  REQUIRE(!strcmp(buffer, "Hello testing"));

  test::sprintf(buffer, "%+d", 1024);
  REQUIRE(!strcmp(buffer, "+1024"));

  test::sprintf(buffer, "%+d", -1024);
  REQUIRE(!strcmp(buffer, "-1024"));

  test::sprintf(buffer, "%+i", 1024);
  REQUIRE(!strcmp(buffer, "+1024"));

  test::sprintf(buffer, "%+i", -1024);
  REQUIRE(!strcmp(buffer, "-1024"));

  test::sprintf(buffer, "%+u", 1024);
  REQUIRE(!strcmp(buffer, "1024"));

  test::sprintf(buffer, "%+u", 4294966272U);
  REQUIRE(!strcmp(buffer, "4294966272"));

  test::sprintf(buffer, "%+o", 511);
  REQUIRE(!strcmp(buffer, "777"));

  test::sprintf(buffer, "%+o", 4294966785U);
  REQUIRE(!strcmp(buffer, "37777777001"));

  test::sprintf(buffer, "%+x", 305441741);
  REQUIRE(!strcmp(buffer, "1234abcd"));

  test::sprintf(buffer, "%+x", 3989525555U);
  REQUIRE(!strcmp(buffer, "edcb5433"));

  test::sprintf(buffer, "%+X", 305441741);
  REQUIRE(!strcmp(buffer, "1234ABCD"));

  test::sprintf(buffer, "%+X", 3989525555U);
  REQUIRE(!strcmp(buffer, "EDCB5433"));

  test::sprintf(buffer, "%+c", 'x');
  REQUIRE(!strcmp(buffer, "x"));

  test::sprintf(buffer, "%+.0d", 0);
  REQUIRE(!strcmp(buffer, "+"));
}


TEST_CASE("0 flag", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%0d", 42);
  REQUIRE(!strcmp(buffer, "42"));

  test::sprintf(buffer, "%0ld", 42L);
  REQUIRE(!strcmp(buffer, "42"));

  test::sprintf(buffer, "%0d", -42);
  REQUIRE(!strcmp(buffer, "-42"));

  test::sprintf(buffer, "%05d", 42);
  REQUIRE(!strcmp(buffer, "00042"));

  test::sprintf(buffer, "%05d", -42);
  REQUIRE(!strcmp(buffer, "-0042"));

  test::sprintf(buffer, "%015d", 42);
  REQUIRE(!strcmp(buffer, "000000000000042"));

  test::sprintf(buffer, "%015d", -42);
  REQUIRE(!strcmp(buffer, "-00000000000042"));

  test::sprintf(buffer, "%015.2f", 42.1234);
  REQUIRE(!strcmp(buffer, "000000000042.12"));

  test::sprintf(buffer, "%015.3f", 42.9876);
  REQUIRE(!strcmp(buffer, "00000000042.988"));

  test::sprintf(buffer, "%015.5f", -42.9876);
  REQUIRE(!strcmp(buffer, "-00000042.98760"));
}


TEST_CASE("- flag", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%-d", 42);
  REQUIRE(!strcmp(buffer, "42"));

  test::sprintf(buffer, "%-d", -42);
  REQUIRE(!strcmp(buffer, "-42"));

  test::sprintf(buffer, "%-5d", 42);
  REQUIRE(!strcmp(buffer, "42   "));

  test::sprintf(buffer, "%-5d", -42);
  REQUIRE(!strcmp(buffer, "-42  "));

  test::sprintf(buffer, "%-15d", 42);
  REQUIRE(!strcmp(buffer, "42             "));

  test::sprintf(buffer, "%-15d", -42);
  REQUIRE(!strcmp(buffer, "-42            "));

  test::sprintf(buffer, "%-0d", 42);
  REQUIRE(!strcmp(buffer, "42"));

  test::sprintf(buffer, "%-0d", -42);
  REQUIRE(!strcmp(buffer, "-42"));

  test::sprintf(buffer, "%-05d", 42);
  REQUIRE(!strcmp(buffer, "42   "));

  test::sprintf(buffer, "%-05d", -42);
  REQUIRE(!strcmp(buffer, "-42  "));

  test::sprintf(buffer, "%-015d", 42);
  REQUIRE(!strcmp(buffer, "42             "));

  test::sprintf(buffer, "%-015d", -42);
  REQUIRE(!strcmp(buffer, "-42            "));

  test::sprintf(buffer, "%0-d", 42);
  REQUIRE(!strcmp(buffer, "42"));

  test::sprintf(buffer, "%0-d", -42);
  REQUIRE(!strcmp(buffer, "-42"));

  test::sprintf(buffer, "%0-5d", 42);
  REQUIRE(!strcmp(buffer, "42   "));

  test::sprintf(buffer, "%0-5d", -42);
  REQUIRE(!strcmp(buffer, "-42  "));

  test::sprintf(buffer, "%0-15d", 42);
  REQUIRE(!strcmp(buffer, "42             "));

  test::sprintf(buffer, "%0-15d", -42);
  REQUIRE(!strcmp(buffer, "-42            "));

  test::sprintf(buffer, "%0-15.3e", -42.);
#ifndef PRINTF_DISABLE_SUPPORT_EXPONENTIAL
  REQUIRE(!strcmp(buffer, "-4.200e+01     "));
#else
  REQUIRE(!strcmp(buffer, "e"));
#endif

  test::sprintf(buffer, "%0-15.3g", -42.);
#ifndef PRINTF_DISABLE_SUPPORT_EXPONENTIAL
  REQUIRE(!strcmp(buffer, "-42.0          "));
#else
  REQUIRE(!strcmp(buffer, "g"));
#endif
}


TEST_CASE("# flag", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%#.0x", 0);
  REQUIRE(!strcmp(buffer, ""));
  test::sprintf(buffer, "%#.1x", 0);
  REQUIRE(!strcmp(buffer, "0"));
  test::sprintf(buffer, "%#.0llx", (long long)0);
  REQUIRE(!strcmp(buffer, ""));
  test::sprintf(buffer, "%#.8x", 0x614e);
  REQUIRE(!strcmp(buffer, "0x0000614e"));
  test::sprintf(buffer,"%#b", 6);
  REQUIRE(!strcmp(buffer, "0b110"));
}


TEST_CASE("specifier", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "Hello testing");
  REQUIRE(!strcmp(buffer, "Hello testing"));

  test::sprintf(buffer, "%s", "Hello testing");
  REQUIRE(!strcmp(buffer, "Hello testing"));

  test::sprintf(buffer, "%d", 1024);
  REQUIRE(!strcmp(buffer, "1024"));

  test::sprintf(buffer, "%d", -1024);
  REQUIRE(!strcmp(buffer, "-1024"));

  test::sprintf(buffer, "%i", 1024);
  REQUIRE(!strcmp(buffer, "1024"));

  test::sprintf(buffer, "%i", -1024);
  REQUIRE(!strcmp(buffer, "-1024"));

  test::sprintf(buffer, "%u", 1024);
  REQUIRE(!strcmp(buffer, "1024"));

  test::sprintf(buffer, "%u", 4294966272U);
  REQUIRE(!strcmp(buffer, "4294966272"));

  test::sprintf(buffer, "%o", 511);
  REQUIRE(!strcmp(buffer, "777"));

  test::sprintf(buffer, "%o", 4294966785U);
  REQUIRE(!strcmp(buffer, "37777777001"));

  test::sprintf(buffer, "%x", 305441741);
  REQUIRE(!strcmp(buffer, "1234abcd"));

  test::sprintf(buffer, "%x", 3989525555U);
  REQUIRE(!strcmp(buffer, "edcb5433"));

  test::sprintf(buffer, "%X", 305441741);
  REQUIRE(!strcmp(buffer, "1234ABCD"));

  test::sprintf(buffer, "%X", 3989525555U);
  REQUIRE(!strcmp(buffer, "EDCB5433"));

  test::sprintf(buffer, "%%");
  REQUIRE(!strcmp(buffer, "%"));
}


TEST_CASE("width", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%1s", "Hello testing");
  REQUIRE(!strcmp(buffer, "Hello testing"));

  test::sprintf(buffer, "%1d", 1024);
  REQUIRE(!strcmp(buffer, "1024"));

  test::sprintf(buffer, "%1d", -1024);
  REQUIRE(!strcmp(buffer, "-1024"));

  test::sprintf(buffer, "%1i", 1024);
  REQUIRE(!strcmp(buffer, "1024"));

  test::sprintf(buffer, "%1i", -1024);
  REQUIRE(!strcmp(buffer, "-1024"));

  test::sprintf(buffer, "%1u", 1024);
  REQUIRE(!strcmp(buffer, "1024"));

  test::sprintf(buffer, "%1u", 4294966272U);
  REQUIRE(!strcmp(buffer, "4294966272"));

  test::sprintf(buffer, "%1o", 511);
  REQUIRE(!strcmp(buffer, "777"));

  test::sprintf(buffer, "%1o", 4294966785U);
  REQUIRE(!strcmp(buffer, "37777777001"));

  test::sprintf(buffer, "%1x", 305441741);
  REQUIRE(!strcmp(buffer, "1234abcd"));

  test::sprintf(buffer, "%1x", 3989525555U);
  REQUIRE(!strcmp(buffer, "edcb5433"));

  test::sprintf(buffer, "%1X", 305441741);
  REQUIRE(!strcmp(buffer, "1234ABCD"));

  test::sprintf(buffer, "%1X", 3989525555U);
  REQUIRE(!strcmp(buffer, "EDCB5433"));

  test::sprintf(buffer, "%1c", 'x');
  REQUIRE(!strcmp(buffer, "x"));
}


TEST_CASE("width 20", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%20s", "Hello");
  REQUIRE(!strcmp(buffer, "               Hello"));

  test::sprintf(buffer, "%20d", 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%20d", -1024);
  REQUIRE(!strcmp(buffer, "               -1024"));

  test::sprintf(buffer, "%20i", 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%20i", -1024);
  REQUIRE(!strcmp(buffer, "               -1024"));

  test::sprintf(buffer, "%20u", 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%20u", 4294966272U);
  REQUIRE(!strcmp(buffer, "          4294966272"));

  test::sprintf(buffer, "%20o", 511);
  REQUIRE(!strcmp(buffer, "                 777"));

  test::sprintf(buffer, "%20o", 4294966785U);
  REQUIRE(!strcmp(buffer, "         37777777001"));

  test::sprintf(buffer, "%20x", 305441741);
  REQUIRE(!strcmp(buffer, "            1234abcd"));

  test::sprintf(buffer, "%20x", 3989525555U);
  REQUIRE(!strcmp(buffer, "            edcb5433"));

  test::sprintf(buffer, "%20X", 305441741);
  REQUIRE(!strcmp(buffer, "            1234ABCD"));

  test::sprintf(buffer, "%20X", 3989525555U);
  REQUIRE(!strcmp(buffer, "            EDCB5433"));

  test::sprintf(buffer, "%20c", 'x');
  REQUIRE(!strcmp(buffer, "                   x"));
}


TEST_CASE("width *20", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%*s", 20, "Hello");
  REQUIRE(!strcmp(buffer, "               Hello"));

  test::sprintf(buffer, "%*d", 20, 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%*d", 20, -1024);
  REQUIRE(!strcmp(buffer, "               -1024"));

  test::sprintf(buffer, "%*i", 20, 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%*i", 20, -1024);
  REQUIRE(!strcmp(buffer, "               -1024"));

  test::sprintf(buffer, "%*u", 20, 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%*u", 20, 4294966272U);
  REQUIRE(!strcmp(buffer, "          4294966272"));

  test::sprintf(buffer, "%*o", 20, 511);
  REQUIRE(!strcmp(buffer, "                 777"));

  test::sprintf(buffer, "%*o", 20, 4294966785U);
  REQUIRE(!strcmp(buffer, "         37777777001"));

  test::sprintf(buffer, "%*x", 20, 305441741);
  REQUIRE(!strcmp(buffer, "            1234abcd"));

  test::sprintf(buffer, "%*x", 20, 3989525555U);
  REQUIRE(!strcmp(buffer, "            edcb5433"));

  test::sprintf(buffer, "%*X", 20, 305441741);
  REQUIRE(!strcmp(buffer, "            1234ABCD"));

  test::sprintf(buffer, "%*X", 20, 3989525555U);
  REQUIRE(!strcmp(buffer, "            EDCB5433"));

  test::sprintf(buffer, "%*c", 20,'x');
  REQUIRE(!strcmp(buffer, "                   x"));
}


TEST_CASE("width -20", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%-20s", "Hello");
  REQUIRE(!strcmp(buffer, "Hello               "));

  test::sprintf(buffer, "%-20d", 1024);
  REQUIRE(!strcmp(buffer, "1024                "));

  test::sprintf(buffer, "%-20d", -1024);
  REQUIRE(!strcmp(buffer, "-1024               "));

  test::sprintf(buffer, "%-20i", 1024);
  REQUIRE(!strcmp(buffer, "1024                "));

  test::sprintf(buffer, "%-20i", -1024);
  REQUIRE(!strcmp(buffer, "-1024               "));

  test::sprintf(buffer, "%-20u", 1024);
  REQUIRE(!strcmp(buffer, "1024                "));

  test::sprintf(buffer, "%-20.4f", 1024.1234);
  REQUIRE(!strcmp(buffer, "1024.1234           "));

  test::sprintf(buffer, "%-20u", 4294966272U);
  REQUIRE(!strcmp(buffer, "4294966272          "));

  test::sprintf(buffer, "%-20o", 511);
  REQUIRE(!strcmp(buffer, "777                 "));

  test::sprintf(buffer, "%-20o", 4294966785U);
  REQUIRE(!strcmp(buffer, "37777777001         "));

  test::sprintf(buffer, "%-20x", 305441741);
  REQUIRE(!strcmp(buffer, "1234abcd            "));

  test::sprintf(buffer, "%-20x", 3989525555U);
  REQUIRE(!strcmp(buffer, "edcb5433            "));

  test::sprintf(buffer, "%-20X", 305441741);
  REQUIRE(!strcmp(buffer, "1234ABCD            "));

  test::sprintf(buffer, "%-20X", 3989525555U);
  REQUIRE(!strcmp(buffer, "EDCB5433            "));

  test::sprintf(buffer, "%-20c", 'x');
  REQUIRE(!strcmp(buffer, "x                   "));

  test::sprintf(buffer, "|%5d| |%-2d| |%5d|", 9, 9, 9);
  REQUIRE(!strcmp(buffer, "|    9| |9 | |    9|"));

  test::sprintf(buffer, "|%5d| |%-2d| |%5d|", 10, 10, 10);
  REQUIRE(!strcmp(buffer, "|   10| |10| |   10|"));

  test::sprintf(buffer, "|%5d| |%-12d| |%5d|", 9, 9, 9);
  REQUIRE(!strcmp(buffer, "|    9| |9           | |    9|"));

  test::sprintf(buffer, "|%5d| |%-12d| |%5d|", 10, 10, 10);
  REQUIRE(!strcmp(buffer, "|   10| |10          | |   10|"));
}


TEST_CASE("width 0-20", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%0-20s", "Hello");
  REQUIRE(!strcmp(buffer, "Hello               "));

  test::sprintf(buffer, "%0-20d", 1024);
  REQUIRE(!strcmp(buffer, "1024                "));

  test::sprintf(buffer, "%0-20d", -1024);
  REQUIRE(!strcmp(buffer, "-1024               "));

  test::sprintf(buffer, "%0-20i", 1024);
  REQUIRE(!strcmp(buffer, "1024                "));

  test::sprintf(buffer, "%0-20i", -1024);
  REQUIRE(!strcmp(buffer, "-1024               "));

  test::sprintf(buffer, "%0-20u", 1024);
  REQUIRE(!strcmp(buffer, "1024                "));

  test::sprintf(buffer, "%0-20u", 4294966272U);
  REQUIRE(!strcmp(buffer, "4294966272          "));

  test::sprintf(buffer, "%0-20o", 511);
  REQUIRE(!strcmp(buffer, "777                 "));

  test::sprintf(buffer, "%0-20o", 4294966785U);
  REQUIRE(!strcmp(buffer, "37777777001         "));

  test::sprintf(buffer, "%0-20x", 305441741);
  REQUIRE(!strcmp(buffer, "1234abcd            "));

  test::sprintf(buffer, "%0-20x", 3989525555U);
  REQUIRE(!strcmp(buffer, "edcb5433            "));

  test::sprintf(buffer, "%0-20X", 305441741);
  REQUIRE(!strcmp(buffer, "1234ABCD            "));

  test::sprintf(buffer, "%0-20X", 3989525555U);
  REQUIRE(!strcmp(buffer, "EDCB5433            "));

  test::sprintf(buffer, "%0-20c", 'x');
  REQUIRE(!strcmp(buffer, "x                   "));
}


TEST_CASE("padding 20", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%020d", 1024);
  REQUIRE(!strcmp(buffer, "00000000000000001024"));

  test::sprintf(buffer, "%020d", -1024);
  REQUIRE(!strcmp(buffer, "-0000000000000001024"));

  test::sprintf(buffer, "%020i", 1024);
  REQUIRE(!strcmp(buffer, "00000000000000001024"));

  test::sprintf(buffer, "%020i", -1024);
  REQUIRE(!strcmp(buffer, "-0000000000000001024"));

  test::sprintf(buffer, "%020u", 1024);
  REQUIRE(!strcmp(buffer, "00000000000000001024"));

  test::sprintf(buffer, "%020u", 4294966272U);
  REQUIRE(!strcmp(buffer, "00000000004294966272"));

  test::sprintf(buffer, "%020o", 511);
  REQUIRE(!strcmp(buffer, "00000000000000000777"));

  test::sprintf(buffer, "%020o", 4294966785U);
  REQUIRE(!strcmp(buffer, "00000000037777777001"));

  test::sprintf(buffer, "%020x", 305441741);
  REQUIRE(!strcmp(buffer, "0000000000001234abcd"));

  test::sprintf(buffer, "%020x", 3989525555U);
  REQUIRE(!strcmp(buffer, "000000000000edcb5433"));

  test::sprintf(buffer, "%020X", 305441741);
  REQUIRE(!strcmp(buffer, "0000000000001234ABCD"));

  test::sprintf(buffer, "%020X", 3989525555U);
  REQUIRE(!strcmp(buffer, "000000000000EDCB5433"));
}


TEST_CASE("padding .20", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%.20d", 1024);
  REQUIRE(!strcmp(buffer, "00000000000000001024"));

  test::sprintf(buffer, "%.20d", -1024);
  REQUIRE(!strcmp(buffer, "-00000000000000001024"));

  test::sprintf(buffer, "%.20i", 1024);
  REQUIRE(!strcmp(buffer, "00000000000000001024"));

  test::sprintf(buffer, "%.20i", -1024);
  REQUIRE(!strcmp(buffer, "-00000000000000001024"));

  test::sprintf(buffer, "%.20u", 1024);
  REQUIRE(!strcmp(buffer, "00000000000000001024"));

  test::sprintf(buffer, "%.20u", 4294966272U);
  REQUIRE(!strcmp(buffer, "00000000004294966272"));

  test::sprintf(buffer, "%.20o", 511);
  REQUIRE(!strcmp(buffer, "00000000000000000777"));

  test::sprintf(buffer, "%.20o", 4294966785U);
  REQUIRE(!strcmp(buffer, "00000000037777777001"));

  test::sprintf(buffer, "%.20x", 305441741);
  REQUIRE(!strcmp(buffer, "0000000000001234abcd"));

  test::sprintf(buffer, "%.20x", 3989525555U);
  REQUIRE(!strcmp(buffer, "000000000000edcb5433"));

  test::sprintf(buffer, "%.20X", 305441741);
  REQUIRE(!strcmp(buffer, "0000000000001234ABCD"));

  test::sprintf(buffer, "%.20X", 3989525555U);
  REQUIRE(!strcmp(buffer, "000000000000EDCB5433"));
}


TEST_CASE("padding #020", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%#020d", 1024);
  REQUIRE(!strcmp(buffer, "00000000000000001024"));

  test::sprintf(buffer, "%#020d", -1024);
  REQUIRE(!strcmp(buffer, "-0000000000000001024"));

  test::sprintf(buffer, "%#020i", 1024);
  REQUIRE(!strcmp(buffer, "00000000000000001024"));

  test::sprintf(buffer, "%#020i", -1024);
  REQUIRE(!strcmp(buffer, "-0000000000000001024"));

  test::sprintf(buffer, "%#020u", 1024);
  REQUIRE(!strcmp(buffer, "00000000000000001024"));

  test::sprintf(buffer, "%#020u", 4294966272U);
  REQUIRE(!strcmp(buffer, "00000000004294966272"));

  test::sprintf(buffer, "%#020o", 511);
  REQUIRE(!strcmp(buffer, "00000000000000000777"));

  test::sprintf(buffer, "%#020o", 4294966785U);
  REQUIRE(!strcmp(buffer, "00000000037777777001"));

  test::sprintf(buffer, "%#020x", 305441741);
  REQUIRE(!strcmp(buffer, "0x00000000001234abcd"));

  test::sprintf(buffer, "%#020x", 3989525555U);
  REQUIRE(!strcmp(buffer, "0x0000000000edcb5433"));

  test::sprintf(buffer, "%#020X", 305441741);
  REQUIRE(!strcmp(buffer, "0X00000000001234ABCD"));

  test::sprintf(buffer, "%#020X", 3989525555U);
  REQUIRE(!strcmp(buffer, "0X0000000000EDCB5433"));
}


TEST_CASE("padding #20", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%#20d", 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%#20d", -1024);
  REQUIRE(!strcmp(buffer, "               -1024"));

  test::sprintf(buffer, "%#20i", 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%#20i", -1024);
  REQUIRE(!strcmp(buffer, "               -1024"));

  test::sprintf(buffer, "%#20u", 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%#20u", 4294966272U);
  REQUIRE(!strcmp(buffer, "          4294966272"));

  test::sprintf(buffer, "%#20o", 511);
  REQUIRE(!strcmp(buffer, "                0777"));

  test::sprintf(buffer, "%#20o", 4294966785U);
  REQUIRE(!strcmp(buffer, "        037777777001"));

  test::sprintf(buffer, "%#20x", 305441741);
  REQUIRE(!strcmp(buffer, "          0x1234abcd"));

  test::sprintf(buffer, "%#20x", 3989525555U);
  REQUIRE(!strcmp(buffer, "          0xedcb5433"));

  test::sprintf(buffer, "%#20X", 305441741);
  REQUIRE(!strcmp(buffer, "          0X1234ABCD"));

  test::sprintf(buffer, "%#20X", 3989525555U);
  REQUIRE(!strcmp(buffer, "          0XEDCB5433"));
}


TEST_CASE("padding 20.5", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%20.5d", 1024);
  REQUIRE(!strcmp(buffer, "               01024"));

  test::sprintf(buffer, "%20.5d", -1024);
  REQUIRE(!strcmp(buffer, "              -01024"));

  test::sprintf(buffer, "%20.5i", 1024);
  REQUIRE(!strcmp(buffer, "               01024"));

  test::sprintf(buffer, "%20.5i", -1024);
  REQUIRE(!strcmp(buffer, "              -01024"));

  test::sprintf(buffer, "%20.5u", 1024);
  REQUIRE(!strcmp(buffer, "               01024"));

  test::sprintf(buffer, "%20.5u", 4294966272U);
  REQUIRE(!strcmp(buffer, "          4294966272"));

  test::sprintf(buffer, "%20.5o", 511);
  REQUIRE(!strcmp(buffer, "               00777"));

  test::sprintf(buffer, "%20.5o", 4294966785U);
  REQUIRE(!strcmp(buffer, "         37777777001"));

  test::sprintf(buffer, "%20.5x", 305441741);
  REQUIRE(!strcmp(buffer, "            1234abcd"));

  test::sprintf(buffer, "%20.10x", 3989525555U);
  REQUIRE(!strcmp(buffer, "          00edcb5433"));

  test::sprintf(buffer, "%20.5X", 305441741);
  REQUIRE(!strcmp(buffer, "            1234ABCD"));

  test::sprintf(buffer, "%20.10X", 3989525555U);
  REQUIRE(!strcmp(buffer, "          00EDCB5433"));
}


TEST_CASE("padding neg numbers", "[]" ) {
  char buffer[100];

  // space padding
  test::sprintf(buffer, "% 1d", -5);
  REQUIRE(!strcmp(buffer, "-5"));

  test::sprintf(buffer, "% 2d", -5);
  REQUIRE(!strcmp(buffer, "-5"));

  test::sprintf(buffer, "% 3d", -5);
  REQUIRE(!strcmp(buffer, " -5"));

  test::sprintf(buffer, "% 4d", -5);
  REQUIRE(!strcmp(buffer, "  -5"));

  // zero padding
  test::sprintf(buffer, "%01d", -5);
  REQUIRE(!strcmp(buffer, "-5"));

  test::sprintf(buffer, "%02d", -5);
  REQUIRE(!strcmp(buffer, "-5"));

  test::sprintf(buffer, "%03d", -5);
  REQUIRE(!strcmp(buffer, "-05"));

  test::sprintf(buffer, "%04d", -5);
  REQUIRE(!strcmp(buffer, "-005"));
}


TEST_CASE("float padding neg numbers", "[]" ) {
  char buffer[100];

  // space padding
  test::sprintf(buffer, "% 3.1f", -5.);
  REQUIRE(!strcmp(buffer, "-5.0"));

  test::sprintf(buffer, "% 4.1f", -5.);
  REQUIRE(!strcmp(buffer, "-5.0"));

  test::sprintf(buffer, "% 5.1f", -5.);
  REQUIRE(!strcmp(buffer, " -5.0"));

#ifndef PRINTF_DISABLE_SUPPORT_EXPONENTIAL
  test::sprintf(buffer, "% 6.1g", -5.);
  REQUIRE(!strcmp(buffer, "    -5"));

  test::sprintf(buffer, "% 6.1e", -5.);
  REQUIRE(!strcmp(buffer, "-5.0e+00"));

  test::sprintf(buffer, "% 10.1e", -5.);
  REQUIRE(!strcmp(buffer, "  -5.0e+00"));
#endif

  // zero padding
  test::sprintf(buffer, "%03.1f", -5.);
  REQUIRE(!strcmp(buffer, "-5.0"));

  test::sprintf(buffer, "%04.1f", -5.);
  REQUIRE(!strcmp(buffer, "-5.0"));

  test::sprintf(buffer, "%05.1f", -5.);
  REQUIRE(!strcmp(buffer, "-05.0"));

  // zero padding no decimal point
  test::sprintf(buffer, "%01.0f", -5.);
  REQUIRE(!strcmp(buffer, "-5"));

  test::sprintf(buffer, "%02.0f", -5.);
  REQUIRE(!strcmp(buffer, "-5"));

  test::sprintf(buffer, "%03.0f", -5.);
  REQUIRE(!strcmp(buffer, "-05"));

#ifndef PRINTF_DISABLE_SUPPORT_EXPONENTIAL
  test::sprintf(buffer, "%010.1e", -5.);
  REQUIRE(!strcmp(buffer, "-005.0e+00"));

  test::sprintf(buffer, "%07.0E", -5.);
  REQUIRE(!strcmp(buffer, "-05E+00"));

  test::sprintf(buffer, "%03.0g", -5.);
  REQUIRE(!strcmp(buffer, "-05"));
#endif
}

TEST_CASE("length", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%.0s", "Hello testing");
  REQUIRE(!strcmp(buffer, ""));

  test::sprintf(buffer, "%20.0s", "Hello testing");
  REQUIRE(!strcmp(buffer, "                    "));

  test::sprintf(buffer, "%.s", "Hello testing");
  REQUIRE(!strcmp(buffer, ""));

  test::sprintf(buffer, "%20.s", "Hello testing");
  REQUIRE(!strcmp(buffer, "                    "));

  test::sprintf(buffer, "%20.0d", 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%20.0d", -1024);
  REQUIRE(!strcmp(buffer, "               -1024"));

  test::sprintf(buffer, "%20.d", 0);
  REQUIRE(!strcmp(buffer, "                    "));

  test::sprintf(buffer, "%20.0i", 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%20.i", -1024);
  REQUIRE(!strcmp(buffer, "               -1024"));

  test::sprintf(buffer, "%20.i", 0);
  REQUIRE(!strcmp(buffer, "                    "));

  test::sprintf(buffer, "%20.u", 1024);
  REQUIRE(!strcmp(buffer, "                1024"));

  test::sprintf(buffer, "%20.0u", 4294966272U);
  REQUIRE(!strcmp(buffer, "          4294966272"));

  test::sprintf(buffer, "%20.u", 0U);
  REQUIRE(!strcmp(buffer, "                    "));

  test::sprintf(buffer, "%20.o", 511);
  REQUIRE(!strcmp(buffer, "                 777"));

  test::sprintf(buffer, "%20.0o", 4294966785U);
  REQUIRE(!strcmp(buffer, "         37777777001"));

  test::sprintf(buffer, "%20.o", 0U);
  REQUIRE(!strcmp(buffer, "                    "));

  test::sprintf(buffer, "%20.x", 305441741);
  REQUIRE(!strcmp(buffer, "            1234abcd"));

  test::sprintf(buffer, "%50.x", 305441741);
  REQUIRE(!strcmp(buffer, "                                          1234abcd"));

  test::sprintf(buffer, "%50.x%10.u", 305441741, 12345);
  REQUIRE(!strcmp(buffer, "                                          1234abcd     12345"));

  test::sprintf(buffer, "%20.0x", 3989525555U);
  REQUIRE(!strcmp(buffer, "            edcb5433"));

  test::sprintf(buffer, "%20.x", 0U);
  REQUIRE(!strcmp(buffer, "                    "));

  test::sprintf(buffer, "%20.X", 305441741);
  REQUIRE(!strcmp(buffer, "            1234ABCD"));

  test::sprintf(buffer, "%20.0X", 3989525555U);
  REQUIRE(!strcmp(buffer, "            EDCB5433"));

  test::sprintf(buffer, "%20.X", 0U);
  REQUIRE(!strcmp(buffer, "                    "));

  test::sprintf(buffer, "%02.0u", 0U);
  REQUIRE(!strcmp(buffer, "  "));

  test::sprintf(buffer, "%02.0d", 0);
  REQUIRE(!strcmp(buffer, "  "));
}


TEST_CASE("float", "[]" ) {
  char buffer[100];

  // test special-case floats using math.h macros
  test::sprintf(buffer, "%8f", NAN);
  REQUIRE(!strcmp(buffer, "     nan"));

  test::sprintf(buffer, "%8f", INFINITY);
  REQUIRE(!strcmp(buffer, "     inf"));

  test::sprintf(buffer, "%-8f", -INFINITY);
  REQUIRE(!strcmp(buffer, "-inf    "));

#ifndef PRINTF_DISABLE_SUPPORT_EXPONENTIAL
  test::sprintf(buffer, "%+8e", INFINITY);
  REQUIRE(!strcmp(buffer, "    +inf"));
#endif

  test::sprintf(buffer, "%.4f", 3.1415354);
  REQUIRE(!strcmp(buffer, "3.1415"));

  test::sprintf(buffer, "%.3f", 30343.1415354);
  REQUIRE(!strcmp(buffer, "30343.142"));

  test::sprintf(buffer, "%.0f", 34.1415354);
  REQUIRE(!strcmp(buffer, "34"));

  test::sprintf(buffer, "%.0f", 1.3);
  REQUIRE(!strcmp(buffer, "1"));

  test::sprintf(buffer, "%.0f", 1.55);
  REQUIRE(!strcmp(buffer, "2"));

  test::sprintf(buffer, "%.1f", 1.64);
  REQUIRE(!strcmp(buffer, "1.6"));

  test::sprintf(buffer, "%.2f", 42.8952);
  REQUIRE(!strcmp(buffer, "42.90"));

  test::sprintf(buffer, "%.9f", 42.8952);
  REQUIRE(!strcmp(buffer, "42.895200000"));

  test::sprintf(buffer, "%.10f", 42.895223);
  REQUIRE(!strcmp(buffer, "42.8952230000"));

  // this testcase checks, that the precision is truncated to 9 digits.
  // a perfect working float should return the whole number
  test::sprintf(buffer, "%.12f", 42.89522312345678);
  REQUIRE(!strcmp(buffer, "42.895223123000"));

  // this testcase checks, that the precision is truncated AND rounded to 9 digits.
  // a perfect working float should return the whole number
  test::sprintf(buffer, "%.12f", 42.89522387654321);
  REQUIRE(!strcmp(buffer, "42.895223877000"));

  test::sprintf(buffer, "%6.2f", 42.8952);
  REQUIRE(!strcmp(buffer, " 42.90"));

  test::sprintf(buffer, "%+6.2f", 42.8952);
  REQUIRE(!strcmp(buffer, "+42.90"));

  test::sprintf(buffer, "%+5.1f", 42.9252);
  REQUIRE(!strcmp(buffer, "+42.9"));

  test::sprintf(buffer, "%f", 42.5);
  REQUIRE(!strcmp(buffer, "42.500000"));

  test::sprintf(buffer, "%.1f", 42.5);
  REQUIRE(!strcmp(buffer, "42.5"));

  test::sprintf(buffer, "%f", 42167.0);
  REQUIRE(!strcmp(buffer, "42167.000000"));

  test::sprintf(buffer, "%.9f", -12345.987654321);
  REQUIRE(!strcmp(buffer, "-12345.987654321"));

  test::sprintf(buffer, "%.1f", 3.999);
  REQUIRE(!strcmp(buffer, "4.0"));

  test::sprintf(buffer, "%.0f", 3.5);
  REQUIRE(!strcmp(buffer, "4"));

  test::sprintf(buffer, "%.0f", 4.5);
  REQUIRE(!strcmp(buffer, "4"));

  test::sprintf(buffer, "%.0f", 3.49);
  REQUIRE(!strcmp(buffer, "3"));

  test::sprintf(buffer, "%.1f", 3.49);
  REQUIRE(!strcmp(buffer, "3.5"));

  test::sprintf(buffer, "a%-5.1f", 0.5);
  REQUIRE(!strcmp(buffer, "a0.5  "));

  test::sprintf(buffer, "a%-5.1fend", 0.5);
  REQUIRE(!strcmp(buffer, "a0.5  end"));

#ifndef PRINTF_DISABLE_SUPPORT_EXPONENTIAL
  test::sprintf(buffer, "%G", 12345.678);
  REQUIRE(!strcmp(buffer, "12345.7"));

  test::sprintf(buffer, "%.7G", 12345.678);
  REQUIRE(!strcmp(buffer, "12345.68"));

  test::sprintf(buffer, "%.5G", 123456789.);
  REQUIRE(!strcmp(buffer, "1.2346E+08"));

  test::sprintf(buffer, "%.6G", 12345.);
  REQUIRE(!strcmp(buffer, "12345.0"));

  test::sprintf(buffer, "%+12.4g", 123456789.);
  REQUIRE(!strcmp(buffer, "  +1.235e+08"));

  test::sprintf(buffer, "%.2G", 0.001234);
  REQUIRE(!strcmp(buffer, "0.0012"));

  test::sprintf(buffer, "%+10.4G", 0.001234);
  REQUIRE(!strcmp(buffer, " +0.001234"));

  test::sprintf(buffer, "%+012.4g", 0.00001234);
  REQUIRE(!strcmp(buffer, "+001.234e-05"));

  test::sprintf(buffer, "%.3g", -1.2345e-308);
  REQUIRE(!strcmp(buffer, "-1.23e-308"));

  test::sprintf(buffer, "%+.3E", 1.23e+308);
  REQUIRE(!strcmp(buffer, "+1.230E+308"));
#endif

  // out of range for float: should switch to exp notation if supported, else empty
  test::sprintf(buffer, "%.1f", 1E20);
#ifndef PRINTF_DISABLE_SUPPORT_EXPONENTIAL
  REQUIRE(!strcmp(buffer, "1.0e+20"));
#else
  REQUIRE(!strcmp(buffer, ""));
#endif

  // brute force float
  bool fail = false;
  std::stringstream str;
  str.precision(5);
  for (float i = -100000; i < 100000; i += 1) {
    test::sprintf(buffer, "%.5f", i / 10000);
    str.str("");
    str << std::fixed << i / 10000;
    fail = fail || !!strcmp(buffer, str.str().c_str());
  }
  REQUIRE(!fail);


#ifndef PRINTF_DISABLE_SUPPORT_EXPONENTIAL
  // brute force exp
  str.setf(std::ios::scientific, std::ios::floatfield);
  for (float i = -1e20; i < 1e20; i += 1e15) {
    test::sprintf(buffer, "%.5f", i);
    str.str("");
    str << i;
    fail = fail || !!strcmp(buffer, str.str().c_str());
  }
  REQUIRE(!fail);
#endif
}


TEST_CASE("types", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%i", 0);
  REQUIRE(!strcmp(buffer, "0"));

  test::sprintf(buffer, "%i", 1234);
  REQUIRE(!strcmp(buffer, "1234"));

  test::sprintf(buffer, "%i", 32767);
  REQUIRE(!strcmp(buffer, "32767"));

  test::sprintf(buffer, "%i", -32767);
  REQUIRE(!strcmp(buffer, "-32767"));

  test::sprintf(buffer, "%li", 30L);
  REQUIRE(!strcmp(buffer, "30"));

  test::sprintf(buffer, "%li", -2147483647L);
  REQUIRE(!strcmp(buffer, "-2147483647"));

  test::sprintf(buffer, "%li", 2147483647L);
  REQUIRE(!strcmp(buffer, "2147483647"));

  test::sprintf(buffer, "%lli", 30LL);
  REQUIRE(!strcmp(buffer, "30"));

  test::sprintf(buffer, "%lli", -9223372036854775807LL);
  REQUIRE(!strcmp(buffer, "-9223372036854775807"));

  test::sprintf(buffer, "%lli", 9223372036854775807LL);
  REQUIRE(!strcmp(buffer, "9223372036854775807"));

  test::sprintf(buffer, "%lu", 100000L);
  REQUIRE(!strcmp(buffer, "100000"));

  test::sprintf(buffer, "%lu", 0xFFFFFFFFL);
  REQUIRE(!strcmp(buffer, "4294967295"));

  test::sprintf(buffer, "%llu", 281474976710656LLU);
  REQUIRE(!strcmp(buffer, "281474976710656"));

  test::sprintf(buffer, "%llu", 18446744073709551615LLU);
  REQUIRE(!strcmp(buffer, "18446744073709551615"));

  test::sprintf(buffer, "%zu", 2147483647UL);
  REQUIRE(!strcmp(buffer, "2147483647"));

  test::sprintf(buffer, "%zd", 2147483647UL);
  REQUIRE(!strcmp(buffer, "2147483647"));

  if (sizeof(size_t) == sizeof(long)) {
    test::sprintf(buffer, "%zi", -2147483647L);
    REQUIRE(!strcmp(buffer, "-2147483647"));
  }
  else {
    test::sprintf(buffer, "%zi", -2147483647LL);
    REQUIRE(!strcmp(buffer, "-2147483647"));
  }

  test::sprintf(buffer, "%b", 60000);
  REQUIRE(!strcmp(buffer, "1110101001100000"));

  test::sprintf(buffer, "%lb", 12345678L);
  REQUIRE(!strcmp(buffer, "101111000110000101001110"));

  test::sprintf(buffer, "%o", 60000);
  REQUIRE(!strcmp(buffer, "165140"));

  test::sprintf(buffer, "%lo", 12345678L);
  REQUIRE(!strcmp(buffer, "57060516"));

  test::sprintf(buffer, "%lx", 0x12345678L);
  REQUIRE(!strcmp(buffer, "12345678"));

  test::sprintf(buffer, "%llx", 0x1234567891234567LLU);
  REQUIRE(!strcmp(buffer, "1234567891234567"));

  test::sprintf(buffer, "%lx", 0xabcdefabL);
  REQUIRE(!strcmp(buffer, "abcdefab"));

  test::sprintf(buffer, "%lX", 0xabcdefabL);
  REQUIRE(!strcmp(buffer, "ABCDEFAB"));

  test::sprintf(buffer, "%c", 'v');
  REQUIRE(!strcmp(buffer, "v"));

  test::sprintf(buffer, "%cv", 'w');
  REQUIRE(!strcmp(buffer, "wv"));

  test::sprintf(buffer, "%s", "A Test");
  REQUIRE(!strcmp(buffer, "A Test"));

  test::sprintf(buffer, "%hhu", 0xFFFFUL);
  REQUIRE(!strcmp(buffer, "255"));

  test::sprintf(buffer, "%hu", 0x123456UL);
  REQUIRE(!strcmp(buffer, "13398"));

  test::sprintf(buffer, "%s%hhi %hu", "Test", 10000, 0xFFFFFFFF);
  REQUIRE(!strcmp(buffer, "Test16 65535"));

  test::sprintf(buffer, "%tx", &buffer[10] - &buffer[0]);
  REQUIRE(!strcmp(buffer, "a"));

// TBD
  if (sizeof(intmax_t) == sizeof(long)) {
    test::sprintf(buffer, "%ji", -2147483647L);
    REQUIRE(!strcmp(buffer, "-2147483647"));
  }
  else {
    test::sprintf(buffer, "%ji", -2147483647LL);
    REQUIRE(!strcmp(buffer, "-2147483647"));
  }
}


TEST_CASE("pointer", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%p", (void*)0x1234U);
  if (sizeof(void*) == 4U) {
    REQUIRE(!strcmp(buffer, "00001234"));
  }
  else {
    REQUIRE(!strcmp(buffer, "0000000000001234"));
  }

  test::sprintf(buffer, "%p", (void*)0x12345678U);
  if (sizeof(void*) == 4U) {
    REQUIRE(!strcmp(buffer, "12345678"));
  }
  else {
    REQUIRE(!strcmp(buffer, "0000000012345678"));
  }

  test::sprintf(buffer, "%p-%p", (void*)0x12345678U, (void*)0x7EDCBA98U);
  if (sizeof(void*) == 4U) {
    REQUIRE(!strcmp(buffer, "12345678-7EDCBA98"));
  }
  else {
    REQUIRE(!strcmp(buffer, "0000000012345678-000000007EDCBA98"));
  }

  if (sizeof(uintptr_t) == sizeof(uint64_t)) {
    test::sprintf(buffer, "%p", (void*)(uintptr_t)0xFFFFFFFFU);
    REQUIRE(!strcmp(buffer, "00000000FFFFFFFF"));
  }
  else {
    test::sprintf(buffer, "%p", (void*)(uintptr_t)0xFFFFFFFFU);
    REQUIRE(!strcmp(buffer, "FFFFFFFF"));
  }
}


TEST_CASE("unknown flag", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%kmarco", 42, 37);
  REQUIRE(!strcmp(buffer, "kmarco"));
}


TEST_CASE("string length", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%.4s", "This is a test");
  REQUIRE(!strcmp(buffer, "This"));

  test::sprintf(buffer, "%.4s", "test");
  REQUIRE(!strcmp(buffer, "test"));

  test::sprintf(buffer, "%.7s", "123");
  REQUIRE(!strcmp(buffer, "123"));

  test::sprintf(buffer, "%.7s", "");
  REQUIRE(!strcmp(buffer, ""));

  test::sprintf(buffer, "%.4s%.2s", "123456", "abcdef");
  REQUIRE(!strcmp(buffer, "1234ab"));

  test::sprintf(buffer, "%.4.2s", "123456");
  REQUIRE(!strcmp(buffer, ".2s"));

  test::sprintf(buffer, "%.*s", 3, "123456");
  REQUIRE(!strcmp(buffer, "123"));
}


TEST_CASE("buffer length", "[]" ) {
  char buffer[100];
  int ret;

  ret = test::snprintf(nullptr, 10, "%s", "Test");
  REQUIRE(ret == 4);
  ret = test::snprintf(nullptr, 0, "%s", "Test");
  REQUIRE(ret == 4);

  buffer[0] = (char)0xA5;
  ret = test::snprintf(buffer, 0, "%s", "Test");
  REQUIRE(buffer[0] == (char)0xA5);
  REQUIRE(ret == 4);

  buffer[0] = (char)0xCC;
  test::snprintf(buffer, 1, "%s", "Test");
  REQUIRE(buffer[0] == '\0');

  test::snprintf(buffer, 2, "%s", "Hello");
  REQUIRE(!strcmp(buffer, "H"));
}


TEST_CASE("ret value", "[]" ) {
  char buffer[100] ;
  int ret;

  ret = test::snprintf(buffer, 6, "0%s", "1234");
  REQUIRE(!strcmp(buffer, "01234"));
  REQUIRE(ret == 5);

  ret = test::snprintf(buffer, 6, "0%s", "12345");
  REQUIRE(!strcmp(buffer, "01234"));
  REQUIRE(ret == 6);  // '5' is truncated

  ret = test::snprintf(buffer, 6, "0%s", "1234567");
  REQUIRE(!strcmp(buffer, "01234"));
  REQUIRE(ret == 8);  // '567' are truncated

  ret = test::snprintf(buffer, 10, "hello, world");
  REQUIRE(ret == 12);

  ret = test::snprintf(buffer, 3, "%d", 10000);
  REQUIRE(ret == 5);
  REQUIRE(strlen(buffer) == 2U);
  REQUIRE(buffer[0] == '1');
  REQUIRE(buffer[1] == '0');
  REQUIRE(buffer[2] == '\0');
}


TEST_CASE("misc", "[]" ) {
  char buffer[100];

  test::sprintf(buffer, "%u%u%ctest%d %s", 5, 3000, 'a', -20, "bit");
  REQUIRE(!strcmp(buffer, "53000atest-20 bit"));

  test::sprintf(buffer, "%.*f", 2, 0.33333333);
  REQUIRE(!strcmp(buffer, "0.33"));

  test::sprintf(buffer, "%.*d", -1, 1);
  REQUIRE(!strcmp(buffer, "1"));

  test::sprintf(buffer, "%.3s", "foobar");
  REQUIRE(!strcmp(buffer, "foo"));

  test::sprintf(buffer, "% .0d", 0);
  REQUIRE(!strcmp(buffer, " "));

  test::sprintf(buffer, "%10.5d", 4);
  REQUIRE(!strcmp(buffer, "     00004"));

  test::sprintf(buffer, "%*sx", -3, "hi");
  REQUIRE(!strcmp(buffer, "hi x"));

#ifndef PRINTF_DISABLE_SUPPORT_EXPONENTIAL
  test::sprintf(buffer, "%.*g", 2, 0.33333333);
  REQUIRE(!strcmp(buffer, "0.33"));

  test::sprintf(buffer, "%.*e", 2, 0.33333333);
  REQUIRE(!strcmp(buffer, "3.33e-01"));
#endif
}
