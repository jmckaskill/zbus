#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>

#define PRINT_INT32_LEN 11 // -2147483648
#define PRINT_UINT32_LEN 10 // 4294967295
#define PRINT_INT64_LEN 20 // -9223372036854775808
#define PRINT_UINT64_LEN 20 // 18446744073709551615

size_t print_int32(char *buf, int32_t val);
size_t print_int64(char *buf, int64_t val);
size_t print_uint32(char *buf, uint32_t val);
size_t print_uint64(char *buf, uint64_t val);

// parses a decimal positive int. Does not skip over leading/trailing spaces or
// apply locales. returns # of chars parsed. 0 on end of string/no number or -ve
// on overflow.
int parse_pos_int(const char *p, int *pval);

#define UTF16_SPACE(U8LEN) ((U8LEN)*2)
#define UTF8_SPACE(U16LEN) ((U16LEN)*3)

char *utf16_to_utf8(char *dst, const wchar_t *src, size_t len);
wchar_t *utf8_to_utf16(wchar_t *dst, const char *src, size_t len);

int utf8argv(const wchar_t *cmdline, char ***pargv);
char *utf8dup(const wchar_t *wstr);
wchar_t *utf16dup(const char *str);
