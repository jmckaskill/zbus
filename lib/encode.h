#pragma once

#include "types.h"
#include <assert.h>
#include <stdarg.h>

struct builder {
	char *next;
	char *end;
	char *base;
	const char *sig;
};

/////////////////////////////
// raw encoded data handling

static void init_builder(struct builder *b, void *p, size_t len);
static inline int builder_error(struct builder b);

extern void append_raw(struct builder *b, const char *sig, const void *p,
		       size_t len);

extern void append_byte(struct builder *b, uint8_t v);
static void append_bool(struct builder *b, bool v);
static void append_uint16(struct builder *b, uint16_t v);
static void append_int16(struct builder *b, int16_t v);
static void append_uint32(struct builder *b, uint32_t v);
static void append_int16(struct builder *b, int16_t v);
static void append_uint64(struct builder *b, uint64_t v);
static void append_int64(struct builder *b, int64_t v);
static void append_double(struct builder *b, double v);
static void append_string(struct builder *b, slice_t v);
extern void append_format(struct builder *b, const char *fmt, ...);
extern void append_vformat(struct builder *b, const char *fmt, va_list ap);
static void append_path(struct builder *b, slice_t v);
static void append_signature(struct builder *b, const char *sig);

extern struct variant_data start_variant(struct builder *b, const char *sig);
extern void end_variant(struct builder *b, struct variant_data);
extern void append_variant(struct builder *b, const char *sig, const void *raw,
			   size_t len);

extern void start_struct(struct builder *b);
extern void end_struct(struct builder *b);

extern struct array_data start_array(struct builder *b);
extern void end_array(struct builder *b, struct array_data data);
// should be called before adding each array element
extern void next_in_array(struct builder *b, struct array_data *pdata);

extern struct dict_data start_dict(struct builder *b);
extern void end_dict(struct builder *b, struct dict_data a);
static void next_in_dict(struct builder *b, struct dict_data *a);

extern void align_buffer_8(struct builder *b);

/////////////////////////////////////
// message handling

void init_message(struct message *m, enum msg_type type, uint32_t serial);
struct builder start_message(struct message *m, void *buf, size_t bufsz);

// returns -ve on error or +ve number of bytes in message
int end_message(struct builder b);

// returns -ve on error or +ve number of bytes in header
int write_message_header(struct message *m, void *buf, size_t bufsz);

///////////////////////////////////////////////////////
// Inline implementationns

struct array_data {
	const char *sig;
	const char *start;
	uint8_t siglen;
	uint8_t hdrlen;
};

struct dict_data {
	struct array_data a;
};

struct variant_data {
	const char *nextsig;
};

void _append2(struct builder *b, uint16_t u, char type);
void _append4(struct builder *b, uint32_t u, char type);
void _append8(struct builder *b, uint64_t u, char type);

static inline void init_builder(struct builder *b, void *p, size_t cap)
{
#ifndef NDEBUG
	memset(p, 0xBD, cap);
#endif
	// cap and base must be 8 byte aligned
	assert(!((uintptr_t)p & 7));
	assert(!(cap & 7));
	b->next = (char *)p;
	b->base = (char *)p;
	b->end = b->next +
		 (cap > DBUS_MAX_VALUE_SIZE ? DBUS_MAX_VALUE_SIZE : cap);
	b->sig = "";
}

static inline int builder_error(struct builder b)
{
	return (intptr_t)((uintptr_t)b.next - (uintptr_t)b.end) > 0;
}

static inline void append_bool(struct builder *b, bool v)
{
	_append4(b, v ? 1 : 0, TYPE_UINT32);
}

static inline void append_int16(struct builder *b, int16_t v)
{
	union {
		uint16_t u;
		int16_t i;
	} u;
	u.i = v;
	_append2(b, u.u, TYPE_UINT16);
}

static inline void append_uint16(struct builder *b, uint16_t v)
{
	_append2(b, v, TYPE_UINT16);
}

static inline void append_int32(struct builder *b, int32_t v)
{
	union {
		uint32_t u;
		int32_t i;
	} u;
	u.i = v;
	_append4(b, u.u, TYPE_INT32);
}

static inline void append_uint32(struct builder *b, uint32_t v)
{
	_append4(b, v, TYPE_UINT32);
}

static inline void append_int64(struct builder *b, int64_t v)
{
	union {
		uint64_t u;
		int64_t i;
	} u;
	u.i = v;
	_append8(b, u.u, TYPE_INT64);
}

static inline void append_uint64(struct builder *b, uint64_t v)
{
	_append8(b, v, TYPE_UINT64);
}

static inline void append_double(struct builder *b, double v)
{
	union {
		uint64_t u;
		double d;
	} u;
	u.d = v;
	_append8(b, u.u, TYPE_DOUBLE);
}

extern void _append_string(struct builder *b, slice_t str, char type);

static inline void append_path(struct builder *b, slice_t str)
{
	_append_string(b, str, TYPE_PATH);
}

static inline void append_string(struct builder *b, slice_t str)
{
	_append_string(b, str, TYPE_STRING);
}

extern void _append_signature(struct builder *b, const char *sig, char type);

static inline void append_signature(struct builder *b, const char *sig)
{
	_append_signature(b, sig, TYPE_SIGNATURE);
}

static inline void next_in_dict(struct builder *b, struct dict_data *d)
{
	next_in_array(b, &d->a);
}
