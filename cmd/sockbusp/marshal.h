#pragma once

#include "types.h"
#include <assert.h>

struct buffer {
	char *base;
	const char *sig;
	unsigned off;
	unsigned cap;
	unsigned depth;
	unsigned error;
};

static void init_buffer(struct buffer *b, char *p, unsigned len);
extern void move_buffer(struct buffer *b, char *newdata, unsigned newcap);

extern void append_raw(struct buffer *b, const char *sig, const void *p,
		       unsigned len);

extern void append_byte(struct buffer *b, uint8_t v);
static void append_bool(struct buffer *b, bool v);
static void append_uint16(struct buffer *b, uint16_t v);
static void append_int16(struct buffer *b, int16_t v);
static void append_uint32(struct buffer *b, uint32_t v);
static void append_int16(struct buffer *b, int16_t v);
static void append_uint64(struct buffer *b, uint64_t v);
static void append_int64(struct buffer *b, int64_t v);
static void append_double(struct buffer *b, double v);
static void append_string(struct buffer *b, struct string v);
static void append_path(struct buffer *b, struct string v);
static void append_signature(struct buffer *b, const char *sig);

// provided signature is the signature of the inner type and
// should correspond to a single complete type
// returned string should be fed back into the corresponding end_variant
extern const char *start_variant(struct buffer *b, const char *sig);
extern void end_variant(struct buffer *b, const char *start);
extern void append_variant(struct buffer *b, const char *sig, const void *raw,
			   unsigned len);

extern void start_struct(struct buffer *b);
extern void end_struct(struct buffer *b);

struct array_data {
	const char *sig;
	unsigned start;
	uint8_t siglen;
	uint8_t hdrlen;
};
extern void start_array(struct buffer *b, struct array_data *pdata);
extern void end_array(struct buffer *b, struct array_data *pdata);
// should be called before adding each array element
extern void next_in_array(struct buffer *b, struct array_data *pdata);

extern void start_dict(struct buffer *b, struct array_data *a);
extern void end_dict(struct buffer *b, struct array_data *a);
static void next_in_dict(struct buffer *b, struct array_data *a);

extern void align_buffer_8(struct buffer *b);

///////////////////////////////////////////////////////
// Inline implementationns

void _append2(struct buffer *b, uint16_t u, char type);
void _append4(struct buffer *b, uint32_t u, char type);
void _append8(struct buffer *b, uint64_t u, char type);

static inline void init_buffer(struct buffer *b, char *p, unsigned cap)
{
	b->depth = 0;
	b->sig = "";
	b->off = 0;
	b->error = 0;
	move_buffer(b, p, cap);
}

static inline void append_bool(struct buffer *b, bool v)
{
	_append4(b, v ? 1 : 0, TYPE_UINT32_BYTE);
}

static inline void append_int16(struct buffer *b, int16_t v)
{
	union {
		uint16_t u;
		int16_t i;
	} u;
	u.i = v;
	_append2(b, u.u, TYPE_UINT16_BYTE);
}

static inline void append_uint16(struct buffer *b, uint16_t v)
{
	_append2(b, v, TYPE_UINT16_BYTE);
}

static inline void append_int32(struct buffer *b, int32_t v)
{
	union {
		uint32_t u;
		int32_t i;
	} u;
	u.i = v;
	_append4(b, u.u, TYPE_INT32_BYTE);
}

static inline void append_uint32(struct buffer *b, uint32_t v)
{
	_append4(b, v, TYPE_UINT32_BYTE);
}

static inline void append_int64(struct buffer *b, int64_t v)
{
	union {
		uint64_t u;
		int64_t i;
	} u;
	u.i = v;
	_append8(b, u.u, TYPE_INT64_BYTE);
}

static inline void append_uint64(struct buffer *b, uint64_t v)
{
	_append8(b, v, TYPE_UINT64_BYTE);
}

static inline void append_double(struct buffer *b, double v)
{
	union {
		uint64_t u;
		double d;
	} u;
	u.d = v;
	_append8(b, u.u, TYPE_DOUBLE_BYTE);
}

extern void _append_string(struct buffer *b, struct string str, char type);

static inline void append_path(struct buffer *b, struct string str)
{
	_append_string(b, str, TYPE_PATH_BYTE);
}

static inline void append_string(struct buffer *b, struct string str)
{
	_append_string(b, str, TYPE_STRING_BYTE);
}

extern void _append_signature(struct buffer *b, const char *sig, char type);

static inline void append_signature(struct buffer *b, const char *sig)
{
	_append_signature(b, sig, TYPE_SIGNATURE_BYTE);
}

static inline void next_in_dict(struct buffer *b, struct array_data *a)
{
	next_in_array(b, a);
}
