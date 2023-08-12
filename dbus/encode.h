#pragma once

#include "types.h"
#include <assert.h>
#include <stdarg.h>

/////////////////////////////
// raw encoded data handling

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
static void append_string(struct builder *b, const char *v, size_t len);
static int append_string8(struct builder *b, const str8_t *v);
static void append_path(struct builder *b, const char *v, size_t len);
static void append_signature(struct builder *b, const char *sig);
extern void append_multiv(struct builder *b, const char *sig, va_list ap);
extern void append_multi(struct builder *b, const char *sig, ...);

// Create a string directly in the message buffer.
// Returned buffer can be written to up to *psz bytes. Nul terminator does not
// (and generally should not) be written. Then call finish_string to complete
// the string with the actual number of bytes written.
extern char *start_string(struct builder *b, size_t *psz);
extern void finish_string(struct builder *b, size_t size);

extern struct variant_data start_variant(struct builder *b, const char *sig);
extern void end_variant(struct builder *b, struct variant_data);
extern void append_variant(struct builder *b, const struct variant *v);
extern void append_raw_variant(struct builder *b, const char *sig,
			       const void *raw, size_t len);

extern void start_struct(struct builder *b);
extern void end_struct(struct builder *b);

extern struct array_data start_array(struct builder *b);
extern void end_array(struct builder *b, struct array_data a);
// should be called before adding each array element
extern void start_array_entry(struct builder *b, struct array_data a);

extern struct dict_data start_dict(struct builder *b);
extern void end_dict(struct builder *b, struct dict_data d);
static void start_dict_entry(struct builder *b, struct dict_data d);

extern void align_buffer_8(struct builder *b);

/////////////////////////////////////
// message handling

void init_message(struct message *m, enum msg_type type, uint32_t serial);

// Writes a message header to the supplied buffer.
// Supplied buffer must be 8 byte aligned
// returns -ve on error
// returns number of bytes consumed on success
int write_header(char *buf, size_t bufsz, const struct message *m,
		 size_t bodysz);

// appends a message to the supplied buffer. Returns -ve on error
// Returns number of bytes consumed on success
struct builder start_message(char *buf, size_t bufsz, const struct message *m);
int end_message(struct builder b);

// These functions let you modify a written header buffer in place
void set_serial(char *buf, uint32_t serial);
void set_reply_serial(char *buf, uint32_t serial);

///////////////////////////////////////////////////////
// Inline implementationns

struct dict_data {
	struct array_data a;
};

struct variant_data {
	const char *nextsig;
};

void _append2(struct builder *b, uint16_t u, char type);
void _append4(struct builder *b, uint32_t u, char type);
void _append8(struct builder *b, uint64_t u, char type);

static inline int builder_error(struct builder b)
{
	return (intptr_t)((uintptr_t)b.next - (uintptr_t)b.end) > 0;
}

static inline void builder_set_error(struct builder *b)
{
	b->next = b->end + 1;
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

extern int _append_string(struct builder *b, const char *str, size_t len,
			  char type);

static inline void append_path(struct builder *b, const char *str, size_t len)
{
	_append_string(b, str, len, TYPE_PATH);
}

static inline void append_string(struct builder *b, const char *str, size_t len)
{
	_append_string(b, str, len, TYPE_STRING);
}

static inline int append_string8(struct builder *b, const str8_t *str)
{
	return _append_string(b, str->p, str->len, TYPE_STRING);
}

extern void _append_signature(struct builder *b, const char *sig, char type);

static inline void append_signature(struct builder *b, const char *sig)
{
	_append_signature(b, sig, TYPE_SIGNATURE);
}

static inline void start_dict_entry(struct builder *b, struct dict_data d)
{
	start_array_entry(b, d.a);
}
