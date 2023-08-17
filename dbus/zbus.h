#pragma once
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>

#ifdef __cplusplus
#define ZB_EXTERN extern "C"
#else
#define ZB_EXTERN extern
#endif

#define ZB_INLINE static inline

///////////////////////////////////////
// Constants

#define ZB_BYTE 'y'
#define ZB_BOOL 'b'
#define ZB_INT16 'n'
#define ZB_UINT16 'q'
#define ZB_INT32 'i'
#define ZB_UINT32 'u'
#define ZB_INT64 'x'
#define ZB_UINT64 't'
#define ZB_DOUBLE 'd'
#define ZB_STRING 's'
#define ZB_PATH 'o'
#define ZB_SIGNATURE 'g'
#define ZB_VARIANT 'v'
#define ZB_ARRAY 'a'
#define ZB_STRUCT 'r'
#define ZB_STRUCT_BEGIN '('
#define ZB_STRUCT_END ')'
#define ZB_DICT 'e'
#define ZB_DICT_BEGIN '{'
#define ZB_DICT_END '}'

#define ZB_MIN_MSG_SIZE 16
#define ZB_MAX_MSG_SIZE 0x8000000U
#define ZB_MAX_VALUE_SIZE 0x4000000U

#define ZB_BUF_FIELD 8 // string: 3B padding, 4B tag, u32: 4B tag, 4B value
#define ZB_BUF_STRING 8 // 3B padding, 4B length, 1B nul
#define ZB_BUF_ARRAY 12 // 3B padding, 4B length, 4B padding

#define ZB_NO_REPLY_EXPECTED 1
#define ZB_NO_AUTO_START 2
#define ZB_ALLOW_INTERACTIVE_AUTHORIZATION 4
#define ZB_FLAG_MASK 7

#define ZB_FIELD_PATH 1
#define ZB_FIELD_INTERFACE 2
#define ZB_FIELD_MEMBER 3
#define ZB_FIELD_ERROR_NAME 4
#define ZB_FIELD_REPLY_SERIAL 5
#define ZB_FIELD_DESTINATION 6
#define ZB_FIELD_SENDER 7
#define ZB_FIELD_SIGNATURE 8
#define ZB_FIELD_UNIX_FDS 9
#define ZB_FIELD_LAST 9

#define ZB_STREAM_OK 0
#define ZB_STREAM_ERROR -1
#define ZB_STREAM_READ_MORE -2
#define ZB_STREAM_WRITE_MORE -3

/////////////////////////////////////
// Types

struct zb_iterator;
struct zb_builder;
struct zb_stream;
struct zb_message;
struct zb_str8;
typedef struct zb_str8 zb_str8;

enum zb_msg_type {
	ZB_METHOD = 1,
	ZB_REPLY = 2,
	ZB_ERROR = 3,
	ZB_SIGNAL = 4,
};

struct zb_message {
	// NULL pointer indicates lack of the field
	const zb_str8 *path;
	const zb_str8 *interface;
	const zb_str8 *member;
	const zb_str8 *error;
	const zb_str8 *destination;
	const zb_str8 *sender;
	// signature must be non NULL
	const char *signature;
	uint32_t fdnum;
	// 0 is the invalid serial value
	uint32_t serial;
	uint32_t reply_serial;
	uint8_t type;
	uint8_t flags;
};

struct zb_scope {
	void *data[3];
};

struct zb_iterator {
	char *base;
	const char *nextsig;
	int_fast32_t next;
	int_fast32_t end;
};

struct zb_builder {
	char *base;
	const char *nextsig;
	int_fast32_t next;
	int_fast32_t end;
};

struct zb_variant {
	const char *sig;
	union {
		bool b;
		uint8_t u8;
		int16_t i16;
		uint16_t u16;
		int32_t i32;
		uint32_t u32;
		int64_t i64;
		uint64_t u64;
		double d;
		struct {
			const char *p;
			size_t len;
		} str, path;
		const char *sig;
		struct zb_iterator record;
		struct zb_iterator array;
		struct zb_iterator variant;
	} u;
};

struct zb_stream {
	size_t cap;
	size_t defrag;
	size_t used;
	size_t have;
	char *body;
	size_t bsz[2];
	char buf[1];
};

///////////////////////////////////////////
// String

// Used for a short pascal style string. The first byte being the length and is
// null terminated. When allocating on the heap, allocate sizeof(*s) + len.
// The buffer shouldn't contain embedded nuls, but that is only guaranteed if
// the string has been checked. The buffer must have a terminating nul.
struct zb_str8 {
	uint8_t len;
	char p[1];
};

#define ZB_S8(STR) (assert((STR)[0] + 2 == sizeof(STR)), (const zb_str8 *)(STR))

ZB_INLINE void zb_copy_str8(zb_str8 *to, const zb_str8 *from);
// Works as long as one of the two strings has been checked for no embedded
// nuls.
ZB_INLINE int zb_cmp_str8(const zb_str8 *a, const zb_str8 *b);
ZB_INLINE int zb_eq_str8(const zb_str8 *a, const zb_str8 *b);

///////////////////////////////////////////
// Authentication

// Client auth assume the auth handshake will succeed and sends the entire
// conversation in the initial send. This allows a client to send the auth and
// messages all in one send. However it may fail if the server doesn't like the
// handshake.

// returns # of bytes written or -ve on error
ZB_EXTERN int zb_write_auth_external(char *buf, size_t bufsz, const char *uid,
				     uint32_t serial);

// returns 0 if more data is needed, -ve on error, or # of bytes read on success
ZB_EXTERN int zb_decode_auth_reply(char *in, size_t sz);

////////////////////////////////////////////
// String Checking

ZB_EXTERN int zb_check_path(const char *s, size_t len);
ZB_EXTERN int zb_check_member(const char *s, size_t len);
ZB_EXTERN int zb_check_interface(const char *s, size_t len);
ZB_EXTERN int zb_check_address(const char *s, size_t len);
ZB_EXTERN int zb_check_unique_address(const char *s, size_t len);
ZB_INLINE int zb_check_error_name(const char *s, size_t len);
ZB_INLINE int zb_check_known_address(const char *s, size_t len);
ZB_INLINE int zb_cmp_signature(const char *sig, const char *test);

/////////////////////
// Argument Decoding

ZB_INLINE void zb_init_iterator(struct zb_iterator *ii, const char *sig,
				char *data, size_t sz);

ZB_INLINE int zb_get_iter_error(struct zb_iterator *p);
ZB_INLINE void zb_set_iter_error(struct zb_iterator *p);

// check zb_get_iter_error before using any of these values
ZB_EXTERN uint8_t zb_parse_byte(struct zb_iterator *p);
ZB_EXTERN bool zb_parse_bool(struct zb_iterator *p);
ZB_EXTERN int16_t zb_parse_i16(struct zb_iterator *p);
ZB_EXTERN uint16_t zb_parse_u16(struct zb_iterator *p);
ZB_EXTERN int32_t zb_parse_i32(struct zb_iterator *p);
ZB_EXTERN uint32_t zb_parse_u32(struct zb_iterator *p);
ZB_EXTERN int64_t zb_parse_i64(struct zb_iterator *p);
ZB_EXTERN uint64_t zb_parse_u64(struct zb_iterator *p);
ZB_EXTERN double zb_parse_double(struct zb_iterator *p);
ZB_EXTERN char *zb_parse_string(struct zb_iterator *p, size_t *psz);
ZB_EXTERN char *zb_parse_path(struct zb_iterator *p, size_t *psz);
ZB_EXTERN const zb_str8 *zb_parse_str8(struct zb_iterator *p);
ZB_EXTERN const char *zb_parse_signature(struct zb_iterator *p);
ZB_EXTERN void zb_parse_variant(struct zb_iterator *p, struct zb_variant *pv);
ZB_EXTERN void zb_enter_struct(struct zb_iterator *p);
ZB_EXTERN void zb_exit_struct(struct zb_iterator *p);
ZB_EXTERN void zb_enter_dict_entry(struct zb_iterator *p);
ZB_EXTERN void zb_exit_dict_entry(struct zb_iterator *p);

ZB_EXTERN void zb_enter_array(struct zb_iterator *p, struct zb_scope *s);
ZB_EXTERN void zb_exit_array(struct zb_iterator *p, struct zb_scope *s);
ZB_EXTERN bool zb_array_has_more(struct zb_iterator *p, struct zb_scope *s);

// zb_skip skips over a complete value optionally returning an iterator to the
// data. It does not validate the data.
ZB_EXTERN void zb_skip(struct zb_iterator *p, struct zb_iterator *pval);

ZB_EXTERN int zb_skip_signature(const char **psig);
ZB_INLINE int zb_cmp_signature(const char *sig, const char *test);

//////////////////////////////////////
// Message Decoding

ZB_EXTERN void zb_init_message(struct zb_message *m, enum zb_msg_type type,
			       uint32_t serial);

// buffer must be at least ZB_MIN_MSG_SIZE long
// returns non-zero on invalid message header
// returns zero on success and sets phdr and pbody to the header and body sizes
// returns number of bytes in header or message
ZB_EXTERN int zb_parse_size(char *p, size_t *phdr, size_t *pbody);

// buffer needs to be at least as long as the hdr size returned
// by zb_parse_size
// returns non-zero on error
ZB_EXTERN int zb_parse_header(struct zb_message *msg, char *p);

/////////////////////////////
// Argument Encoding

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
// Message Encoding

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

/////////////////////////////////////////////
// Receive Stream

// msgsz must be a power of 2
ZB_EXTERN void zb_init_stream(struct zb_stream *s, size_t msgsz, size_t hdrsz);
ZB_EXTERN void zb_get_stream_recvbuf(struct zb_stream *s, char **p1, size_t *n1,
				     char **p2, size_t *n2);

// returns -ve on error, 0 on more data needed, +ve on ok
ZB_EXTERN int zb_read_message(struct zb_stream *s, struct zb_message *m);
ZB_EXTERN int zb_read_auth(struct zb_stream *s);

ZB_EXTERN int zb_defragment_body(struct zb_stream *s, struct zb_message *m,
				 struct zb_iterator *ii);

ZB_INLINE void zb_get_stream_body(struct zb_stream *s, char **p1, size_t *n1,
				  char **p2, size_t *n2);

////////////////////////////////////////
// inline implementations

ZB_INLINE void zb_copy_str8(zb_str8 *to, const zb_str8 *from)
{
	memcpy(&to->len, &from->len, from->len + 2);
}

// Works as long as one of the two strings has been checked for no embedded
// nuls.
ZB_INLINE int zb_cmp_str8(const zb_str8 *a, const zb_str8 *b)
{
	return strcmp((char *)&a->len, (char *)&b->len);
}

ZB_INLINE int zb_eq_str8(const zb_str8 *a, const zb_str8 *b)
{
	return !zb_cmp_str8(a, b);
}

ZB_INLINE int zb_check_error_name(const char *s, size_t len)
{
	return zb_check_interface(s, len);
}

ZB_INLINE int zb_check_known_address(const char *s, size_t len)
{
	return zb_check_interface(s, len);
}

ZB_INLINE int zb_cmp_signature(const char *sig, const char *test)
{
	// depending on where it's come from sig may contain arguments
	// after the one we're interested in. As long as test is a complete
	// type, which it should be as the programmer provided it, we just
	// need to test up to strlen(test)
	return strncmp(sig, test, strlen(test));
}

ZB_INLINE void zb_init_iterator(struct zb_iterator *ii, const char *sig,
				char *p, size_t sz)
{
	assert(sz < ZB_MAX_MSG_SIZE);
	ii->base = p;
	ii->next = 0;
	ii->end = (uint32_t)sz;
	ii->nextsig = sig;
}

ZB_INLINE int zb_get_iter_error(struct zb_iterator *p)
{
	return p->next > p->end;
}

ZB_INLINE void zb_set_iter_error(struct zb_iterator *p)
{
	p->next = p->end + 1;
}

// Internal methods used by inline implementations

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

ZB_INLINE void zb_get_stream_body(struct zb_stream *s, char **p1, size_t *n1,
				  char **p2, size_t *n2)
{
	*p1 = s->body;
	*n1 = s->bsz[0];
	*p2 = s->buf;
	*n2 = s->bsz[1];
}
