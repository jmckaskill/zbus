#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TYPE_INVALID '\0'
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
#define TYPE_STRUCT_BEGIN '('
#define TYPE_STRUCT_END ')'
#define TYPE_DICT_BEGIN '{'
#define TYPE_DICT_END '}'
#define TYPE_RECORD 'r' // only used for variant->type

#define ALIGN_UINT_DOWN(VAL, BOUNDARY) \
	(((unsigned)(VAL)) & (~((((unsigned)(BOUNDARY)) - 1))))

#define ALIGN_UINT_UP(VAL, BOUNDARY)                        \
	((((unsigned)(VAL)) + ((unsigned)(BOUNDARY)) - 1) & \
	 (~((((unsigned)(BOUNDARY)) - 1))))

#define ALIGN_PTR_UP(TYPE, PTR, BOUNDARY)                            \
	((TYPE)((((uintptr_t)(PTR)) + ((uintptr_t)(BOUNDARY)) - 1) & \
		(~((((uintptr_t)(BOUNDARY)) - 1)))))

struct parser {
	const char *n;
	const char *e;
	const char *sig;
	unsigned depth;
	unsigned error;
};

struct string {
	const char *p;
	unsigned len;
};

#define INIT_STRING   \
	{             \
		"", 0 \
	}

static inline bool is_string(struct string a, const char *test)
{
	return a.len == strlen(test) && !memcmp(a.p, test, a.len);
}

int compare_string_x(const char *a, unsigned alen, const char *b,
		     unsigned blen);
int compare_string_p(const void *a, const void *b);

static inline int compare_string(struct string a, struct string b)
{
	return compare_string_x(a.p, a.len, b.p, b.len);
}

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
	struct parser data; // used for struct, array and variant
};

struct variant {
	char type;
	struct parser data;
	union variant_union u;
};

static inline void init_parser(struct parser *p, const char *sig,
			       const void *data, unsigned len)
{
	p->n = (const char *)data;
	p->e = p->n + len;
	p->sig = sig;
	p->depth = 0;
	p->error = 0;
}

// check p->error before using any of these values
uint8_t parse_byte(struct parser *p);
bool parse_bool(struct parser *p);
int16_t parse_int16(struct parser *p);
uint16_t parse_uint16(struct parser *p);
int32_t parse_int32(struct parser *p);
uint32_t parse_uint32(struct parser *p);
int64_t parse_int64(struct parser *p);
uint64_t parse_uint64(struct parser *p);
struct string parse_string(struct parser *p);
struct string parse_path(struct parser *p);
const char *parse_signature(struct parser *p);
struct variant parse_variant(struct parser *p);
void parse_struct_begin(struct parser *p);
void parse_struct_end(struct parser *p);
void parse_dict_begin(struct parser *p);
void parse_dict_end(struct parser *p);

// psig must point to NULL before first call
bool parse_array_next(struct parser *p, const char **psig);

extern struct parser skip_array(struct parser *p);
extern struct parser skip_struct(struct parser *p);
int skip_value(struct parser *p);
int skip_signature(const char **psig);

void TEST_parse();
