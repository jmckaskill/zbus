#pragma once
#define _GNU_SOURCE
#include "str.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

struct iterator;
struct builder;
struct stream;
struct message;
struct unix_oob;

#define ALIGN_UINT_DOWN(VAL, BOUNDARY) ((VAL) & (~(BOUNDARY##U - 1)))

#define ALIGN_UINT_UP(VAL, BOUNDARY) \
	(((VAL) + (BOUNDARY##U - 1)) & (~(BOUNDARY##U - 1)))

#define ALIGN_PTR_UP(PTR, BOUNDARY)                                    \
	((char *)((((uintptr_t)(PTR)) + ((uintptr_t)(BOUNDARY)) - 1) & \
		  (~((((uintptr_t)(BOUNDARY)) - 1)))))

#define MAX_ARRAY_SIZE 0x4000000U
#define MAX_TYPE_DEPTH 64

#define TYPE_BYTE 'y'
#define TYPE_BOOL 'b'
#define TYPE_INT16 'n'
#define TYPE_UINT16 'q'
#define TYPE_INT32 'i'
#define TYPE_UINT32 'u'
#define TYPE_INT64 'x'
#define TYPE_UINT64 't'
#define TYPE_DOUBLE 'd'
#define TYPE_STRING 's'
#define TYPE_PATH 'o'
#define TYPE_SIGNATURE 'g'
#define TYPE_VARIANT 'v'
#define TYPE_ARRAY 'a'
#define TYPE_STRUCT 'r'
#define TYPE_STRUCT_BEGIN '('
#define TYPE_STRUCT_END ')'
#define TYPE_DICT 'e'
#define TYPE_DICT_BEGIN '{'
#define TYPE_DICT_END '}'

static inline bool is_signature(const char *sig, const char *test)
{
	// depending on where it's come from sig may contain arguments
	// after the one we're interested in. As long as test is a complete
	// type, which it should be as the programmer provided it, we just
	// need to test up to strlen(test)
	return !strncmp(sig, test, strlen(test));
}

static inline void write_native_2(char *p, uint16_t v)
{
	memcpy(p, &v, 2);
}

static inline void write_native_4(char *p, uint32_t v)
{
	memcpy(p, &v, 4);
}

static inline void write_native_8(char *p, uint64_t v)
{
	memcpy(p, &v, 8);
}

static inline void write_little_4(char *p, uint32_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	memcpy(p, &v, 4);
#else
	*(uint8_t *)(p) = (uint8_t)(v);
	*(uint8_t *)(p + 1) = (uint8_t)(v >> 8);
	*(uint8_t *)(p + 2) = (uint8_t)(v >> 16);
	*(uint8_t *)(p + 3) = (uint8_t)(v >> 24);
#endif
}

static inline uint16_t read_native_2(const char *n)
{
	uint16_t u;
	memcpy(&u, n, 2);
	return u;
}

static inline uint32_t read_native_4(const char *n)
{
	uint32_t u;
	memcpy(&u, n, 4);
	return u;
}

static inline uint64_t read_native_8(const char *n)
{
	uint64_t u;
	memcpy(&u, n, 8);
	return u;
}

static inline uint32_t read_little_4(const char *n)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint32_t u;
	memcpy(&u, n, 4);
	return u;
#else
	const uint8_t *u = n;
	return ((uint32_t)u[0]) | (((uint32_t)u[1]) << 8) |
	       (((uint32_t)u[2]) << 16) | (((uint32_t)u[3]) << 24);
#endif
}
