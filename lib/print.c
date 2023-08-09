#include "print.h"
#include <string.h>

size_t print_int32(char *buf, int32_t num)
{
	char *e = buf + PRINT_INT32_LEN;
	char *p = e;
	int sign = 0;
	if (num < 0) {
		sign = 1;
		num = -num;
	}
	do {
		*--p = '0' + (num % 10);
		num /= 10;
	} while (num);
	if (sign) {
		*--p = '-';
	}
	size_t n = e - p;
	memmove(buf, p, n);
	return n;
}

size_t print_int64(char *buf, int64_t num)
{
	char *e = buf + PRINT_INT64_LEN;
	char *p = e;
	int sign = 0;
	if (num < 0) {
		sign = 1;
		num = -num;
	}
	do {
		*--p = '0' + (num % 10);
		num /= 10;
	} while (num);
	if (sign) {
		*--p = '-';
	}
	size_t n = e - p;
	memmove(buf, p, n);
	return n;
}

size_t print_uint32(char *buf, uint32_t num)
{
	char *e = buf + PRINT_UINT32_LEN;
	char *p = e;
	do {
		*--p = '0' + (num % 10);
		num /= 10;
	} while (num);
	size_t n = e - p;
	memmove(buf, p, n);
	return n;
}

size_t print_uint64(char *buf, uint64_t num)
{
	char *e = buf + PRINT_UINT64_LEN;
	char *p = e;
	do {
		*--p = '0' + (num % 10);
		num /= 10;
	} while (num);
	size_t n = e - p;
	memmove(buf, p, n);
	return n;
}
