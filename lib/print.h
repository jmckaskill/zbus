#pragma once
#include <stdint.h>
#include <stdlib.h>

#define PRINT_INT32_LEN 11 // -2147483648
#define PRINT_UINT32_LEN 10 // 4294967295
#define PRINT_INT64_LEN 20 // -9223372036854775808
#define PRINT_UINT64_LEN 20 // 18446744073709551615

size_t print_int32(char *buf, int32_t val);
size_t print_int64(char *buf, int64_t val);
size_t print_uint32(char *buf, uint32_t val);
size_t print_uint64(char *buf, uint64_t val);
