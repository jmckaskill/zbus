#include "encode.h"
#include "decode.h"
#include <stdarg.h>
#include <stdio.h>
#include <limits.h>

/////////////////////////////////
// alignment

static uint32_t align2(char *base, uint32_t off)
{
	uint32_t mod = off & 1U;
	if (!mod) {
		return off;
	}
	base[off] = 0;
	return off + 1;
}

static uint32_t align4(char *base, uint32_t off)
{
	uint32_t aligned = ALIGN_UINT_UP(off, 4);
	while (off < aligned) {
		base[off++] = 0;
	}
	return off;
}

static uint32_t align8(char *base, uint32_t off)
{
	uint32_t aligned = ALIGN_UINT_UP(off, 8);
	while (off < aligned) {
		base[off++] = 0;
	}
	return off;
}

void align_buffer_8(struct builder *b)
{
	// buffer is guarenteed to have 8 byte alignment so this should never
	// fail
	b->next = align8(b->base, b->next);
}

static uint32_t alignx(char *base, uint32_t off, char type)
{
	switch (type) {
	case TYPE_INT16:
	case TYPE_UINT16:
		return align2(base, off);
	case TYPE_BOOL:
	case TYPE_INT32:
	case TYPE_UINT32:
	case TYPE_STRING:
	case TYPE_PATH:
	case TYPE_ARRAY:
		return align4(base, off);
	case TYPE_INT64:
	case TYPE_UINT64:
	case TYPE_DOUBLE:
	case TYPE_DICT_BEGIN:
	case TYPE_STRUCT_BEGIN:
		return align8(base, off);
	case TYPE_BYTE:
	case TYPE_SIGNATURE:
	case TYPE_VARIANT:
	default:
		return off;
	}
}

///////////////////////////////
// raw data encoding

void append_raw(struct builder *b, const char *sig, const void *p, size_t len)
{
	assert(len < DBUS_MAX_MSG_SIZE);
	uint32_t off = alignx(b->base, b->next, *sig);
	b->next = off + (uint32_t)len;
	if (!is_signature(b->sig, sig)) {
		b->next = b->end + 1;
	} else if (!len && b->next <= b->end) {
		memcpy(b->base + off, p, len);
		b->sig += strlen(sig);
	}
}

void append_byte(struct builder *b, uint8_t v)
{
	if (*b->sig != TYPE_BYTE) {
		b->next = b->end + 1;
	} else if (b->next < b->end) {
		*(uint8_t *)(b->base + b->next) = v;
		b->next++;
		b->sig++;
	}
}

void _append2(struct builder *b, uint16_t u, char type)
{
	uint32_t off = align2(b->base, b->next);
	b->next = off + 2;
	if (*b->sig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		memcpy(b->base + off, &u, 2);
		b->sig++;
	}
}

void _append4(struct builder *b, uint32_t u, char type)
{
	uint32_t off = align4(b->base, b->next);
	b->next = off + 4;
	if (*b->sig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		memcpy(b->base + off, &u, 4);
		b->sig++;
	}
}

void _append8(struct builder *b, uint64_t u, char type)
{
	uint32_t off = align8(b->base, b->next);
	b->next = off + 8;
	if (*b->sig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		memcpy(b->base + off, &u, 8);
		b->sig++;
	}
}

int _append_string(struct builder *b, const char *str, size_t len, char type)
{
	uint32_t lenoff = align4(b->base, b->next);
	uint32_t stroff = lenoff + 4;
	uint32_t nuloff = stroff + (uint32_t)len;
	b->next = nuloff + 1;
	if (*b->sig != type || len > DBUS_MAX_VALUE_SIZE) {
		b->next = b->end + 1;
		return -1;
	} else if (b->next <= b->end) {
		uint32_t len32 = (uint32_t)len;
		memcpy(b->base + lenoff, &len32, 4);
		memcpy(b->base + stroff, str, len);
		b->base[nuloff] = 0;
		b->sig++;
		return 0;
	} else {
		return -1;
	}
}

void _append_signature(struct builder *b, const char *sig, char type)
{
	size_t len = strlen(sig);
	uint32_t lenoff = b->next;
	uint32_t stroff = lenoff + 1;
	b->next = stroff + (uint32_t)len + 1;
	if (len > 255 || *b->sig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		*(uint8_t *)(b->base + lenoff) = (uint8_t)len;
		memcpy(b->base + stroff, sig, len + 1);
		b->sig++;
	}
}

char *start_string(struct builder *b, size_t *psz)
{
	uint32_t lenoff = align4(b->base, b->next);
	uint32_t stroff = lenoff + 4;
	b->next = stroff + 1;
	if (b->next > b->end || *b->sig != TYPE_STRING) {
		b->next = b->end + 1;
		*psz = 0;
		return NULL;
	} else {
		*psz = b->end - b->next;
		return b->base + stroff;
	}
}

void finish_string(struct builder *b, size_t sz)
{
	assert(sz < DBUS_MAX_VALUE_SIZE);
	b->next += (uint32_t)sz;
	if (b->next <= b->end) {
		b->base[b->next - 1] = 0;
	}
}

struct variant_data start_variant(struct builder *b, const char *sig)
{
	_append_signature(b, sig, TYPE_VARIANT);
	struct variant_data vd = { .nextsig = b->sig };
	b->sig = sig;
	return vd;
}

void end_variant(struct builder *b, struct variant_data vd)
{
	// should have consumed the signature
	if (*b->sig) {
		b->next = b->end + 1;
	}
	b->sig = vd.nextsig;
}

void append_variant(struct builder *b, const struct variant *v)
{
	struct variant_data vd = start_variant(b, v->sig);
	const char *sig = v->sig;
	char type = *sig++;
	switch (type) {
	case TYPE_BOOL:
		append_bool(b, v->u.b);
		break;
	case TYPE_BYTE:
		append_byte(b, v->u.u8);
		break;
	case TYPE_INT16:
	case TYPE_UINT16:
		_append2(b, v->u.u16, type);
		break;
	case TYPE_INT32:
	case TYPE_UINT32:
		_append4(b, v->u.u32, type);
		break;
	case TYPE_INT64:
	case TYPE_UINT64:
	case TYPE_DOUBLE:
		_append8(b, v->u.u64, type);
		break;
	case TYPE_STRING:
	case TYPE_PATH:
		_append_string(b, v->u.str.p, v->u.str.len, type);
		break;
	case TYPE_SIGNATURE:
		append_signature(b, v->u.sig);
		break;
	case TYPE_ARRAY: {
		struct iterator ii = v->u.array;
		struct array_data ad = start_array(b);
		append_raw(b, ii.sig, ii.base + ii.next, ii.end - ii.next);
		end_array(b, ad);
		break;
	}
	case TYPE_STRUCT_BEGIN: {
		struct iterator ii = v->u.record;
		append_raw(b, ii.sig, ii.base + ii.next, ii.end - ii.next);
		break;
	}
	case TYPE_VARIANT: {
		struct iterator ii = v->u.variant;
		append_raw_variant(b, ii.sig, ii.base + ii.next,
				   ii.end - ii.next);
		break;
	}
	default:
		b->next = b->end + 1;
		break;
	}
	end_variant(b, vd);
}

void append_raw_variant(struct builder *b, const char *sig, const void *raw,
			size_t len)
{
	struct variant_data vd = start_variant(b, sig);
	append_raw(b, sig, raw, len);
	end_variant(b, vd);
}

void start_struct(struct builder *b)
{
	// alignment can't fail
	if (*b->sig == TYPE_STRUCT_BEGIN) {
		b->next = align8(b->base, b->next);
		b->sig++;
	} else {
		b->next = b->end + 1;
	}
}

void end_struct(struct builder *b)
{
	if (*b->sig == TYPE_STRUCT_END) {
		b->sig++;
	} else {
		b->next = b->end + 1;
	}
}

struct array_data start_array(struct builder *b)
{
	struct array_data a;
	if (*b->sig != TYPE_ARRAY) {
		goto error;
	}
	const char *sig = b->sig++;
	uint32_t lenoff = align4(b->base, b->next);
	b->next = alignx(b->base, lenoff + 4, sig[1]);
	if (b->next > b->end || skip_signature(&sig)) {
		goto error;
	}
	a.sig = b->sig;
	a.siglen = (uint8_t)(sig - b->sig);
	a.off = b->next;
	a.hdr = (uint8_t)(b->next - lenoff);
	return a;
error:
	// setup an error state such that start_array_entry and end_array don't
	// crash
	a.sig = "";
	a.siglen = 0;
	a.off = 0;
	a.hdr = 0;
	b->next = b->end + 1;
	return a;
}

void start_array_entry(struct builder *b, struct array_data a)
{
	// check that the signature is where we expect
	if (b->sig != ((b->next != a.off) ? (a.sig + a.siglen) : a.sig)) {
		b->next = b->end + 1;
	}
	b->sig = a.sig;
}

void end_array(struct builder *b, struct array_data a)
{
	uint32_t len = b->next - a.off;
	memcpy(b->base + a.off - a.hdr, &len, 4);

	// check that the signature is where we expect
	if (b->sig != (len ? (a.sig + a.siglen) : a.sig)) {
		b->next = b->end + 1;
	}
	b->sig = a.sig + a.siglen;
}

struct dict_data start_dict(struct builder *b)
{
	struct dict_data d;
	if (b->sig[0] != TYPE_ARRAY || b->sig[1] != TYPE_DICT_BEGIN) {
		goto error;
	}

	uint32_t lenoff = align4(b->base, b->next);
	uint32_t dataoff = lenoff + 4;
	// data is 0 or 4 (mod 8)
	if (dataoff & 7U) {
		memset(b->base, 0, 4);
		dataoff += 4;
	}

	const char *nextsig = b->sig;
	b->sig += 2; // want to point to key signature
	b->next = dataoff;
	if (b->next > b->end || skip_signature(&nextsig)) {
		goto error;
	}
	nextsig -= 1; // want to point to ending }

	d.a.sig = b->sig;
	d.a.siglen = (uint8_t)(nextsig - b->sig);
	d.a.off = b->next;
	d.a.hdr = (uint8_t)(b->next - lenoff);
	return d;
error:
	// setup an error state with siglen = 0 and hdrlen = 0
	// so that start_dict_entry and end_dict don't crash
	d.a.sig = "}";
	d.a.siglen = 0;
	d.a.off = 0;
	d.a.hdr = 0;
	b->next = b->end + 1;
	return d;
}

void end_dict(struct builder *b, struct dict_data d)
{
	end_array(b, d.a);
	b->sig++; // }
}

void append_multiv(struct builder *b, const char *sig, va_list ap)
{
	while (*sig) {
		char type = *sig++;
		switch (type) {
		case TYPE_BYTE:
			append_byte(b, (uint8_t)va_arg(ap, int));
			break;
		case TYPE_BOOL:
			append_bool(b, (bool)va_arg(ap, int));
			break;
		case TYPE_INT16:
		case TYPE_UINT16:
			_append2(b, (uint16_t)va_arg(ap, int), type);
			break;
		case TYPE_INT32:
		case TYPE_UINT32:
			_append4(b, va_arg(ap, uint32_t), type);
			break;
		case TYPE_INT64:
		case TYPE_UINT64:
			_append8(b, va_arg(ap, uint64_t), type);
			break;
		case TYPE_DOUBLE:
			append_double(b, va_arg(ap, double));
			break;
		case TYPE_PATH:
		case TYPE_STRING: {
			const char *str = va_arg(ap, const char *);
			_append_string(b, str, strlen(str), type);
			break;
		}
		case TYPE_SIGNATURE:
			append_signature(b, va_arg(ap, const char *));
			break;
		case TYPE_VARIANT:
			append_variant(b, va_arg(ap, struct variant *));
			break;
		case TYPE_STRUCT_BEGIN: {
			struct iterator *ii = va_arg(ap, struct iterator *);
			append_raw(b, ii->sig, ii->base + ii->next,
				   ii->end - ii->next);
			// step back one so skip_signature can pick up that
			// we're in a struct
			sig--;
			if (skip_signature(&sig)) {
				goto error;
			}
			break;
		}
		case TYPE_ARRAY: {
			struct iterator *ii = va_arg(ap, struct iterator *);
			struct array_data ad = start_array(b);
			append_raw(b, ii->sig, ii->base + ii->next,
				   ii->end - ii->next);
			end_array(b, ad);
			// step back one so skip_signature can pick up that
			// we're in an array
			sig--;
			if (skip_signature(&sig)) {
				goto error;
			}
			break;
		}
		default:
			goto error;
		}
	}
	return;
error:
	b->next = b->next + 1;
}

void append_multi(struct builder *b, const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	append_multiv(b, sig, ap);
	va_end(ap);
}

//////////////////////////////
// message encoding

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

static void append_uint32_field(struct builder *b, uint32_t tag, uint32_t v)
{
	// should be called first so that we are still aligned
	assert(!(b->next & 3U));
	uint32_t tagoff = b->next;
	uint32_t valoff = tagoff + 4;
	b->next = valoff + 4;
	if (b->next <= b->end) {
		write_little_4(b->base + tagoff, tag);
		memcpy(b->base + valoff, &v, 4);
	}
}

static void append_string_field(struct builder *b, uint32_t tag,
				const str8_t *str)
{
	align_buffer_8(b);
	uint32_t tagoff = b->next;
	uint32_t lenoff = tagoff + 4;
	uint32_t stroff = lenoff + 4;
	b->next = stroff + str->len + 1;
	if (b->next <= b->end) {
		uint32_t len32 = str->len;
		write_little_4(b->base + tagoff, tag);
		memcpy(b->base + lenoff, &len32, 4);
		memcpy(b->base + stroff, str->p, str->len + 1);
	}
}

static void append_signature_field(struct builder *b, uint32_t tag,
				   const char *sig)
{
	align_buffer_8(b);
	size_t len = strlen(sig);
	if (len > 255) {
		b->next = b->end + 1;
		return;
	}
	uint32_t tagoff = b->next;
	uint32_t lenoff = tagoff + 4;
	uint32_t stroff = lenoff + 1;
	b->next = stroff + (uint8_t)len + 1;
	if (b->next <= b->end) {
		write_little_4(b->base + tagoff, tag);
		*(uint8_t *)(b->base + lenoff) = (uint8_t)len;
		memcpy(b->base + stroff, sig, len + 1);
	}
}

static inline void init_builder(struct builder *b, char *buf, size_t bufsz,
				const char *sig)
{
	// align the capacity down. This makes alignment calls not fail.
	size_t cap = bufsz & ~(size_t)7U;
	if (cap > DBUS_MAX_MSG_SIZE) {
		cap = DBUS_MAX_MSG_SIZE;
	}
#ifndef NDEBUG
	memset(buf, 0xBD, cap);
#endif
	b->base = buf;
	b->sig = sig;
	b->next = 0;
	b->end = (uint32_t)cap;

	// Put in a dummy buffer in an error state if the supplied buffer is
	// stupid small. This stops array encoding from crashing
	if (bufsz < 8) {
		static char dummy[8];
		b->base = dummy;
		b->next = b->end + 1;
	}
}

void set_serial(char *buf, uint32_t serial)
{
	struct raw_header *h = (struct raw_header *)buf;
	memcpy(h->serial, &serial, 4);
}

void set_reply_serial(char *buf, uint32_t reply_serial)
{
	// this function assumes that we created the header
	// in which case the reply serial is right after the raw header
	assert(buf[sizeof(struct raw_header)] == FIELD_REPLY_SERIAL);
	memcpy(buf + sizeof(struct raw_header) + 4, &reply_serial, 4);
}

static int append_header(struct builder *b, const struct message *m,
			 size_t blen)
{
	uint32_t start = b->next;
	b->next += sizeof(struct raw_header);
	if (b->next > b->end || blen > DBUS_MAX_MSG_SIZE) {
		return -1;
	}

	// unwrap the standard marshalling functions to add the field
	// type and variant signature in one go

	// fixed length fields go first so we can maintain 8 byte alignment
	if (m->reply_serial) {
		append_uint32_field(b, FTAG_REPLY_SERIAL, m->reply_serial);
	}
	if (m->fdnum) {
		append_uint32_field(b, FTAG_UNIX_FDS, m->fdnum);
	}
	if (*m->signature) {
		append_signature_field(b, FTAG_SIGNATURE, m->signature);
	}
	if (m->path) {
		append_string_field(b, FTAG_PATH, m->path);
	}
	if (m->interface) {
		append_string_field(b, FTAG_INTERFACE, m->interface);
	}
	if (m->member) {
		append_string_field(b, FTAG_MEMBER, m->member);
	}
	if (m->error) {
		append_string_field(b, FTAG_ERROR_NAME, m->error);
	}
	if (m->destination) {
		append_string_field(b, FTAG_DESTINATION, m->destination);
	}
	if (m->sender) {
		append_string_field(b, FTAG_SENDER, m->sender);
	}

	struct raw_header *h = (struct raw_header *)(b->base + start);
	h->endian = native_endian();
	h->type = m->type;
	h->flags = m->flags;
	h->version = DBUS_VERSION;
	uint32_t serial = m->serial;
	uint32_t flen32 = b->next - start - sizeof(*h);
	uint32_t blen32 = (uint32_t)blen;
	memcpy(h->serial, &serial, 4);
	memcpy(h->body_len, &blen32, 4);
	memcpy(h->field_len, &flen32, 4);

	// align the end of the fields
	align_buffer_8(b);

	return (b->next > b->end);
}

int write_header(char *buf, size_t bufsz, const struct message *msg,
		 size_t bodysz)
{
	struct builder b;
	init_builder(&b, buf, bufsz, NULL);
	if (append_header(&b, msg, bodysz)) {
		return -1;
	}
	return (int)b.next;
}

struct builder start_message(char *buf, size_t bufsz, const struct message *msg)
{
	struct builder b;
	init_builder(&b, buf, bufsz, msg->signature);
	// append_header leaves b in an error state if there was an error
	append_header(&b, msg, 0);
	return b;
}

int end_message(struct builder b)
{
	if (builder_error(b) || *b.sig) {
		// error during marshalling or missing arguments
		return -1;
	}
	struct raw_header *h = (struct raw_header *)b.base;
	uint32_t fsz;
	memcpy(&fsz, h->field_len, 4);
	uint32_t bsz = b.next - ALIGN_UINT_UP(fsz, 8) - sizeof(*h);
	memcpy(h->body_len, &bsz, 4);
	return (int)b.next;
}
