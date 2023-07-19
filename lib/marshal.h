#pragma once

#include "types.h"
#include <assert.h>
#include <stdarg.h>

#define MAX_BUF_SIZE 0x8000000

struct buffer {
	char *base;
	const char *sig;
	uint32_t off;
	uint32_t cap;
};

static void init_buffer(struct buffer *b, void *p, size_t len);

extern void append_raw(struct buffer *b, const char *sig, const void *p,
		       size_t len);

extern void append_byte(struct buffer *b, uint8_t v);
static void append_bool(struct buffer *b, bool v);
static void append_uint16(struct buffer *b, uint16_t v);
static void append_int16(struct buffer *b, int16_t v);
static void append_uint32(struct buffer *b, uint32_t v);
static void append_int16(struct buffer *b, int16_t v);
static void append_uint64(struct buffer *b, uint64_t v);
static void append_int64(struct buffer *b, int64_t v);
static void append_double(struct buffer *b, double v);
static void append_string(struct buffer *b, slice_t v);
extern void append_format(struct buffer *b, const char *fmt, ...);
extern void append_vformat(struct buffer *b, const char *fmt, va_list ap);
static void append_path(struct buffer *b, slice_t v);
static void append_signature(struct buffer *b, const char *sig);

// provided signature is the signature of the inner type and
// should correspond to a single complete type
// returned string should be fed back into the corresponding end_variant
extern const char *start_variant(struct buffer *b, const char *sig);
extern void end_variant(struct buffer *b, const char *start);
extern void append_variant(struct buffer *b, const char *sig, const void *raw,
			   size_t len);

extern void start_struct(struct buffer *b);
extern void end_struct(struct buffer *b);

struct array_data {
	const char *sig;
	uint32_t start;
	uint8_t siglen;
	uint8_t hdrlen;
};
extern struct array_data start_array(struct buffer *b);
extern void end_array(struct buffer *b, struct array_data data);
// should be called before adding each array element
extern void next_in_array(struct buffer *b, struct array_data *pdata);

struct dict_data {
	struct array_data a;
};

extern struct dict_data start_dict(struct buffer *b);
extern void end_dict(struct buffer *b, struct dict_data a);
static void next_in_dict(struct buffer *b, struct dict_data *a);

extern void align_buffer_8(struct buffer *b);

///////////////////////////////////////////////////////
// Inline implementationns

void _append2(struct buffer *b, uint16_t u, char type);
void _append4(struct buffer *b, uint32_t u, char type);
void _append8(struct buffer *b, uint64_t u, char type);

static inline void init_buffer(struct buffer *b, void *p, size_t cap)
{
	// cap must be 8 byte aligned
	assert(!(cap & 7));
	b->base = (char *)p;
	b->sig = "";
	b->off = 0;
	b->cap = cap > MAX_BUF_SIZE ? MAX_BUF_SIZE : cap;
}

static inline void append_bool(struct buffer *b, bool v)
{
	_append4(b, v ? 1 : 0, TYPE_UINT32);
}

static inline void append_int16(struct buffer *b, int16_t v)
{
	union {
		uint16_t u;
		int16_t i;
	} u;
	u.i = v;
	_append2(b, u.u, TYPE_UINT16);
}

static inline void append_uint16(struct buffer *b, uint16_t v)
{
	_append2(b, v, TYPE_UINT16);
}

static inline void append_int32(struct buffer *b, int32_t v)
{
	union {
		uint32_t u;
		int32_t i;
	} u;
	u.i = v;
	_append4(b, u.u, TYPE_INT32);
}

static inline void append_uint32(struct buffer *b, uint32_t v)
{
	_append4(b, v, TYPE_UINT32);
}

static inline void append_int64(struct buffer *b, int64_t v)
{
	union {
		uint64_t u;
		int64_t i;
	} u;
	u.i = v;
	_append8(b, u.u, TYPE_INT64);
}

static inline void append_uint64(struct buffer *b, uint64_t v)
{
	_append8(b, v, TYPE_UINT64);
}

static inline void append_double(struct buffer *b, double v)
{
	union {
		uint64_t u;
		double d;
	} u;
	u.d = v;
	_append8(b, u.u, TYPE_DOUBLE);
}

extern void _append_string(struct buffer *b, slice_t str, char type);

static inline void append_path(struct buffer *b, slice_t str)
{
	_append_string(b, str, TYPE_PATH);
}

static inline void append_string(struct buffer *b, slice_t str)
{
	_append_string(b, str, TYPE_STRING);
}

extern void _append_signature(struct buffer *b, const char *sig, char type);

static inline void append_signature(struct buffer *b, const char *sig)
{
	_append_signature(b, sig, TYPE_SIGNATURE);
}

static inline void next_in_dict(struct buffer *b, struct dict_data *d)
{
	next_in_array(b, &d->a);
}
