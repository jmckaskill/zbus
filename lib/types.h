#pragma once

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

struct iterator;
struct buffer;
struct stream;
struct message;

#define ALIGN_UINT_DOWN(VAL, BOUNDARY) ((VAL) & (~(BOUNDARY##U - 1)))

#define ALIGN_UINT_UP(VAL, BOUNDARY) \
	(((VAL) + (BOUNDARY##U - 1)) & (~(BOUNDARY##U - 1)))

#define ALIGN_PTR_UP(TYPE, PTR, BOUNDARY)                            \
	((TYPE)((((uintptr_t)(PTR)) + ((uintptr_t)(BOUNDARY)) - 1) & \
		(~((((uintptr_t)(BOUNDARY)) - 1)))))

#define TYPE_INVALID ""
#define TYPE_BYTE "y"
#define TYPE_BOOL "b"
#define TYPE_INT16 "n"
#define TYPE_UINT16 "q"
#define TYPE_INT32 "i"
#define TYPE_UINT32 "u"
#define TYPE_INT64 "x"
#define TYPE_UINT64 "t"
#define TYPE_DOUBLE "d"
#define TYPE_STRING "s"
#define TYPE_PATH "o"
#define TYPE_SIGNATURE "g"
#define TYPE_VARIANT "v"
#define TYPE_ARRAY "a"
#define TYPE_STRUCT "("
#define TYPE_STRUCT_END ")"
#define TYPE_DICT "{"
#define TYPE_DICT_END "}"

#define TYPE_INVALID_BYTE '\0'
#define TYPE_BYTE_BYTE 'y'
#define TYPE_BOOL_BYTE 'b'
#define TYPE_INT16_BYTE 'n'
#define TYPE_UINT16_BYTE 'q'
#define TYPE_INT32_BYTE 'i'
#define TYPE_UINT32_BYTE 'u'
#define TYPE_INT64_BYTE 'x'
#define TYPE_UINT64_BYTE 't'
#define TYPE_DOUBLE_BYTE 'd'
#define TYPE_STRING_BYTE 's'
#define TYPE_PATH_BYTE 'o'
#define TYPE_SIGNATURE_BYTE 'g'
#define TYPE_VARIANT_BYTE 'v'
#define TYPE_ARRAY_BYTE 'a'
#define TYPE_STRUCT_BYTE '('
#define TYPE_STRUCT_END_BYTE ')'
#define TYPE_DICT_BYTE '{'
#define TYPE_DICT_END_BYTE '}'

static inline bool is_signature(const char *sig, const char *test)
{
	// depending on where it's come from sig may contain arguments
	// after the one we're interested in. As long as test is a complete
	// type, which it should be as the programmer provided it, we just
	// need to test up to strlen(test)
	return !strncmp(sig, test, strlen(test));
}

struct string {
	const char *p;
	unsigned len;
};

#define INIT_STRING   \
	{             \
		"", 0 \
	}

#define STRLEN(x) (sizeof(x) - 1)

static inline struct string to_string(const char *str)
{
	struct string ret;
	ret.p = str;
	ret.len = strlen(str);
	return ret;
}

static inline struct string to_string2(const char *str, unsigned sz)
{
	struct string ret = { str, sz };
	return ret;
}

static inline bool is_string(struct string a, const char *test)
{
	return a.len == strlen(test) && !memcmp(a.p, test, a.len);
}

int compare_string_x(const char *a, unsigned an, const char *b, unsigned bn);
int compare_string_p(const void *a, const void *b);

static inline int compare_string(struct string a, struct string b)
{
	return compare_string_x(a.p, a.len, b.p, b.len);
}

struct iterator {
	const char *n;
	const char *e;
	const char *sig;
	unsigned depth;
	unsigned error;
};

union variant_union {
	bool b;
	uint8_t u8;
	int16_t i16;
	uint16_t u16;
	int32_t i32;
	uint32_t u32;
	int64_t i64;
	uint64_t u64;
	double d;
	struct string str;
	struct string path;
	const char *sig;
	struct iterator data; // used for struct, array and variant
};

struct variant {
	const char *sig;
	struct iterator data;
	union variant_union u;
};

static inline void init_iterator(struct iterator *p, const char *sig,
				 const void *data, unsigned len)
{
	p->n = (const char *)data;
	p->e = p->n + len;
	p->sig = sig;
	p->depth = 0;
	p->error = 0;
}
