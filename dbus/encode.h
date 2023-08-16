#pragma once

#include "types.h"
#include "str8.h"
#include <assert.h>
#include <stdarg.h>

/////////////////////////////
// raw encoded data handling

ZB_INLINE int zb_builder_get_error(const struct zb_builder *b);
ZB_INLINE void zb_builder_set_error(struct zb_builder *b);

ZB_EXTERN void zb_add_raw(struct zb_builder *b, const char *sig, const void *p,
			  size_t len);

ZB_EXTERN void zb_add_byte(struct zb_builder *b, uint8_t v);
ZB_INLINE void zb_add_bool(struct zb_builder *b, bool v);
ZB_INLINE void zb_add_u16(struct zb_builder *b, uint16_t v);
ZB_INLINE void zb_add_i16(struct zb_builder *b, int16_t v);
ZB_INLINE void zb_add_u32(struct zb_builder *b, uint32_t v);
ZB_INLINE void zb_add_i16(struct zb_builder *b, int16_t v);
ZB_INLINE void zb_add_u64(struct zb_builder *b, uint64_t v);
ZB_INLINE void zb_add_i64(struct zb_builder *b, int64_t v);
ZB_INLINE void zb_add_double(struct zb_builder *b, double v);
ZB_INLINE void zb_add_string(struct zb_builder *b, const char *v, size_t len);
ZB_INLINE void zb_add_str8(struct zb_builder *b, const zb_str8 *v);
ZB_INLINE void zb_add_path(struct zb_builder *b, const char *v, size_t len);
ZB_INLINE void zb_add_signature(struct zb_builder *b, const char *sig);
ZB_EXTERN void zb_add_multiv(struct zb_builder *b, const char *sig, va_list ap);
ZB_EXTERN void zb_add_multi(struct zb_builder *b, const char *sig, ...);

// Create a string directly in the message buffer.
// Returned buffer can be written to up to *psz bytes. Nul terminator does not
// (and generally should not) be written. Then call zb_end_string to complete
// the string with the actual number of bytes written.
ZB_EXTERN char *zb_start_string(struct zb_builder *b, size_t *psz);
ZB_EXTERN void zb_end_string(struct zb_builder *b, size_t size);

ZB_EXTERN void zb_start_variant(struct zb_builder *b, const char *sig,
				struct zb_scope *s);
ZB_EXTERN void zb_end_variant(struct zb_builder *b, struct zb_scope *s);
ZB_EXTERN void zb_add_variant(struct zb_builder *b, const struct zb_variant *v);
ZB_EXTERN void zb_add_raw_variant(struct zb_builder *b, const char *sig,
				  const void *raw, size_t len);

ZB_EXTERN void zb_start_struct(struct zb_builder *b);
ZB_EXTERN void zb_end_struct(struct zb_builder *b);

ZB_EXTERN void zb_start_array(struct zb_builder *b, struct zb_scope *s);
ZB_EXTERN void zb_end_array(struct zb_builder *b, struct zb_scope *s);
// should be called before adding each array element
ZB_EXTERN void zb_add_array_entry(struct zb_builder *b, struct zb_scope *s);

ZB_EXTERN void zb_start_dict(struct zb_builder *b, struct zb_scope *s);
ZB_EXTERN void zb_end_dict(struct zb_builder *b, struct zb_scope *s);
ZB_INLINE void zb_add_dict_entry(struct zb_builder *b, struct zb_scope *s);

/////////////////////////////////////
// message handling

ZB_EXTERN void zb_init_message(struct zb_message *m, enum zb_msg_type type,
			       uint32_t serial);

// Writes a message header to the supplied buffer.
// Supplied buffer must be 8 byte aligned
// returns -ve on error
// returns number of bytes consumed on success
ZB_EXTERN int zb_write_header(char *buf, size_t bufsz,
			      const struct zb_message *m, size_t bodysz);

// adds a message to the supplied buffer. Returns -ve on error
// Returns number of bytes consumed on success
ZB_EXTERN void zb_start(struct zb_builder *b, char *buf, size_t bufsz,
			const struct zb_message *m);
ZB_EXTERN int zb_end(struct zb_builder *b);

// These functions let you modify a written header buffer in place
ZB_INLINE void zb_set_serial(char *buf, uint32_t serial);
ZB_INLINE void zb_set_reply_serial(char *buf, uint32_t serial);

///////////////////////////////////////////////////////
// Inline implementationns

ZB_EXTERN void _zb_add2(struct zb_builder *b, uint16_t u, char type);
ZB_EXTERN void _zb_add4(struct zb_builder *b, uint32_t u, char type);
ZB_EXTERN void _zb_add8(struct zb_builder *b, uint64_t u, char type);
ZB_EXTERN void _zb_add_string(struct zb_builder *b, const char *str, size_t len,
			      char type);
ZB_EXTERN void _zb_add_signature(struct zb_builder *b, const char *sig,
				 char type);

ZB_INLINE int zb_builder_get_error(const struct zb_builder *b)
{
	return b->next > b->end;
}

ZB_INLINE void zb_builder_set_error(struct zb_builder *b)
{
	b->next = b->end + 1;
}

ZB_INLINE void zb_add_bool(struct zb_builder *b, bool v)
{
	_zb_add4(b, v ? 1 : 0, ZB_UINT32);
}

ZB_INLINE void zb_add_i16(struct zb_builder *b, int16_t v)
{
	union {
		uint16_t u;
		int16_t i;
	} u;
	u.i = v;
	_zb_add2(b, u.u, ZB_UINT16);
}

ZB_INLINE void zb_add_u16(struct zb_builder *b, uint16_t v)
{
	_zb_add2(b, v, ZB_UINT16);
}

ZB_INLINE void zb_add_i32(struct zb_builder *b, int32_t v)
{
	union {
		uint32_t u;
		int32_t i;
	} u;
	u.i = v;
	_zb_add4(b, u.u, ZB_INT32);
}

ZB_INLINE void zb_add_u32(struct zb_builder *b, uint32_t v)
{
	_zb_add4(b, v, ZB_UINT32);
}

ZB_INLINE void zb_add_i64(struct zb_builder *b, int64_t v)
{
	union {
		uint64_t u;
		int64_t i;
	} u;
	u.i = v;
	_zb_add8(b, u.u, ZB_INT64);
}

ZB_INLINE void zb_add_u64(struct zb_builder *b, uint64_t v)
{
	_zb_add8(b, v, ZB_UINT64);
}

ZB_INLINE void zb_add_double(struct zb_builder *b, double v)
{
	union {
		uint64_t u;
		double d;
	} u;
	u.d = v;
	_zb_add8(b, u.u, ZB_DOUBLE);
}

ZB_INLINE void zb_add_path(struct zb_builder *b, const char *str, size_t len)
{
	_zb_add_string(b, str, len, ZB_PATH);
}

ZB_INLINE void zb_add_string(struct zb_builder *b, const char *str, size_t len)
{
	_zb_add_string(b, str, len, ZB_STRING);
}

ZB_INLINE void zb_add_str8(struct zb_builder *b, const zb_str8 *str)
{
	_zb_add_string(b, str->p, str->len, ZB_STRING);
}

ZB_INLINE void zb_add_signature(struct zb_builder *b, const char *sig)
{
	_zb_add_signature(b, sig, ZB_SIGNATURE);
}

ZB_INLINE void zb_add_dict_entry(struct zb_builder *b, struct zb_scope *s)
{
	zb_add_array_entry(b, s);
}

ZB_INLINE void zb_set_serial(char *buf, uint32_t serial)
{
	memcpy(buf + 8, &serial, 4);
}

ZB_INLINE void zb_set_reply_serial(char *buf, uint32_t reply_serial)
{
	// this function assumes that we created the header
	// in which case the reply serial is right after the raw header
	assert(buf[16] == ZB_FIELD_REPLY_SERIAL);
	memcpy(buf + 16 + 4, &reply_serial, 4);
}
