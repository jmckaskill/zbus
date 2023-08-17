#include "internal.h"

/////////////////////////////////
// alignment

static int_fast32_t align2(char *base, int_fast32_t off)
{
	int_fast32_t mod = off & 1U;
	if (!mod) {
		return off;
	}
	base[off] = 0;
	return off + 1;
}

static int_fast32_t align4(char *base, int_fast32_t off)
{
	int_fast32_t aligned = ZB_ALIGN_UP(off, 4);
	while (off < aligned) {
		base[off++] = 0;
	}
	return off;
}

static int_fast32_t align8(char *base, int_fast32_t off)
{
	int_fast32_t aligned = ZB_ALIGN_UP(off, 8);
	while (off < aligned) {
		base[off++] = 0;
	}
	return off;
}

void align_buffer_8(struct zb_builder *b)
{
	// buffer is guarenteed to have 8 byte alignment so this should never
	// fail
	b->next = align8(b->base, b->next);
}

static int_fast32_t alignx(char *base, int_fast32_t off, char type)
{
	switch (type) {
	case ZB_INT16:
	case ZB_UINT16:
		return align2(base, off);
	case ZB_BOOL:
	case ZB_INT32:
	case ZB_UINT32:
	case ZB_STRING:
	case ZB_PATH:
	case ZB_ARRAY:
		return align4(base, off);
	case ZB_INT64:
	case ZB_UINT64:
	case ZB_DOUBLE:
	case ZB_DICT_BEGIN:
	case ZB_STRUCT_BEGIN:
		return align8(base, off);
	case ZB_BYTE:
	case ZB_SIGNATURE:
	case ZB_VARIANT:
	default:
		return off;
	}
}

///////////////////////////////
// raw data encoding

void zb_add_raw(struct zb_builder *b, const char *sig, const void *p,
		size_t len)
{
	assert(len < ZB_MAX_MSG_SIZE);
	int_fast32_t off = alignx(b->base, b->next, *sig);
	b->next = off + (int_fast32_t)len;
	if (zb_cmp_signature(b->nextsig, sig)) {
		b->next = b->end + 1;
	} else if (!len && b->next <= b->end) {
		memcpy(b->base + off, p, len);
		b->nextsig += strlen(sig);
	}
}

void zb_add_byte(struct zb_builder *b, uint8_t v)
{
	if (*b->nextsig != ZB_BYTE) {
		b->next = b->end + 1;
	} else if (b->next < b->end) {
		*(uint8_t *)(b->base + b->next) = v;
		b->next++;
		b->nextsig++;
	}
}

void _zb_add2(struct zb_builder *b, uint16_t u, char type)
{
	int_fast32_t off = align2(b->base, b->next);
	b->next = off + 2;
	if (*b->nextsig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		memcpy(b->base + off, &u, 2);
		b->nextsig++;
	}
}

void _zb_add4(struct zb_builder *b, uint32_t u, char type)
{
	int_fast32_t off = align4(b->base, b->next);
	b->next = off + 4;
	if (*b->nextsig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		memcpy(b->base + off, &u, 4);
		b->nextsig++;
	}
}

void _zb_add8(struct zb_builder *b, uint64_t u, char type)
{
	int_fast32_t off = align8(b->base, b->next);
	b->next = off + 8;
	if (*b->nextsig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		memcpy(b->base + off, &u, 8);
		b->nextsig++;
	}
}

void _zb_add_string(struct zb_builder *b, const char *str, size_t len,
		    char type)
{
	int_fast32_t lenoff = align4(b->base, b->next);
	int_fast32_t stroff = lenoff + 4;
	int_fast32_t nuloff = stroff + (int_fast32_t)len;
	b->next = nuloff + 1;
	if (*b->nextsig != type || len > ZB_MAX_VALUE_SIZE) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		uint32_t len32 = (uint32_t)len;
		memcpy(b->base + lenoff, &len32, 4);
		memcpy(b->base + stroff, str, len);
		b->base[nuloff] = 0;
		b->nextsig++;
	}
}

void _zb_add_signature(struct zb_builder *b, const char *sig, char type)
{
	size_t len = strlen(sig);
	int_fast32_t lenoff = b->next;
	int_fast32_t stroff = lenoff + 1;
	b->next = stroff + (int_fast32_t)len + 1;
	if (len > 255 || *b->nextsig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		*(uint8_t *)(b->base + lenoff) = (uint8_t)len;
		memcpy(b->base + stroff, sig, len + 1);
		b->nextsig++;
	}
}

char *zb_start_string(struct zb_builder *b, size_t *psz)
{
	int_fast32_t lenoff = align4(b->base, b->next);
	int_fast32_t stroff = lenoff + 4;
	if (stroff + 1 > b->end || *b->nextsig != ZB_STRING) {
		b->next = b->end + 1;
		*psz = 0;
		return NULL;
	} else {
		*psz = b->end - stroff - 1;
		return b->base + stroff;
	}
}

void zb_end_string(struct zb_builder *b, size_t sz)
{
	assert(sz < ZB_MAX_VALUE_SIZE);
	if (b->next > b->end) {
		return;
	}
	uint32_t len32 = (uint32_t)sz;
	memcpy(b->base + b->next, &len32, 4);
	b->next += 4 + len32;
	b->base[b->next++] = 0;
	assert(b->next <= b->end);
	assert(*b->nextsig == ZB_STRING);
	b->nextsig++;
}

struct variant_data {
	const char *nextsig;
};

void zb_start_variant(struct zb_builder *b, const char *sig, struct zb_scope *s)
{
	_zb_add_signature(b, sig, ZB_VARIANT);
	struct variant_data *v = (void *)s;
	v->nextsig = b->nextsig;
	b->nextsig = sig;
}

void zb_end_variant(struct zb_builder *b, struct zb_scope *s)
{
	// should have consumed the signature
	if (*b->nextsig) {
		b->next = b->end + 1;
	}
	struct variant_data *v = (void *)s;
	b->nextsig = v->nextsig;
}

void zb_add_variant(struct zb_builder *b, const struct zb_variant *v)
{
	struct zb_scope s;
	zb_start_variant(b, v->sig, &s);
	const char *sig = v->sig;
	char type = *sig++;
	switch (type) {
	case ZB_BOOL:
		zb_add_bool(b, v->u.b);
		break;
	case ZB_BYTE:
		zb_add_byte(b, v->u.u8);
		break;
	case ZB_INT16:
	case ZB_UINT16:
		_zb_add2(b, v->u.u16, type);
		break;
	case ZB_INT32:
	case ZB_UINT32:
		_zb_add4(b, v->u.u32, type);
		break;
	case ZB_INT64:
	case ZB_UINT64:
	case ZB_DOUBLE:
		_zb_add8(b, v->u.u64, type);
		break;
	case ZB_STRING:
	case ZB_PATH:
		_zb_add_string(b, v->u.str.p, v->u.str.len, type);
		break;
	case ZB_SIGNATURE:
		zb_add_signature(b, v->u.sig);
		break;
	case ZB_ARRAY: {
		struct zb_iterator ii = v->u.array;
		struct zb_scope array;
		zb_start_array(b, &array);
		zb_add_raw(b, ii.nextsig, ii.base + ii.next, ii.end - ii.next);
		zb_end_array(b, &array);
		break;
	}
	case ZB_STRUCT_BEGIN: {
		struct zb_iterator ii = v->u.record;
		zb_add_raw(b, ii.nextsig, ii.base + ii.next, ii.end - ii.next);
		break;
	}
	case ZB_VARIANT: {
		struct zb_iterator ii = v->u.variant;
		zb_add_raw_variant(b, ii.nextsig, ii.base + ii.next,
				   ii.end - ii.next);
		break;
	}
	default:
		b->next = b->end + 1;
		break;
	}
	zb_end_variant(b, &s);
}

void zb_add_raw_variant(struct zb_builder *b, const char *sig, const void *raw,
			size_t len)
{
	struct zb_scope s;
	zb_start_variant(b, sig, &s);
	zb_add_raw(b, sig, raw, len);
	zb_end_variant(b, &s);
}

void zb_start_struct(struct zb_builder *b)
{
	// alignment can't fail
	if (*b->nextsig == ZB_STRUCT_BEGIN) {
		b->next = align8(b->base, b->next);
		b->nextsig++;
	} else {
		b->next = b->end + 1;
	}
}

void zb_end_struct(struct zb_builder *b)
{
	if (*b->nextsig == ZB_STRUCT_END) {
		b->nextsig++;
	} else {
		b->next = b->end + 1;
	}
}

struct build_array {
	const char *sig_start;
	int_fast32_t data_start;
	uint8_t siglen;
	uint8_t hdrlen;
};

static_assert(sizeof(struct build_array) <= sizeof(struct zb_scope), "");

void zb_start_array(struct zb_builder *b, struct zb_scope *s)
{
	struct build_array *a = (void *)s;
	if (*b->nextsig != ZB_ARRAY) {
		goto error;
	}
	const char *sig = b->nextsig++;
	int_fast32_t lenoff = align4(b->base, b->next);
	b->next = alignx(b->base, lenoff + 4, sig[1]);
	if (b->next > b->end || zb_skip_signature(&sig)) {
		goto error;
	}
	a->sig_start = b->nextsig;
	a->siglen = (uint8_t)(sig - b->nextsig);
	a->data_start = b->next;
	a->hdrlen = (uint8_t)(b->next - lenoff);
	return;
error:
	// setup an error state such that zb_add_array_entry and zb_end_array
	// don't crash
	a->sig_start = "";
	a->siglen = 0;
	a->data_start = 0;
	a->hdrlen = 0;
	b->next = b->end + 1;
}

void zb_add_array_entry(struct zb_builder *b, struct zb_scope *s)
{
	// check that the signature is where we expect
	struct build_array *a = (void *)s;
	size_t sigoff = (b->next != a->data_start) ? a->siglen : 0;
	if (b->nextsig != a->sig_start + sigoff) {
		b->next = b->end + 1;
	}
	b->nextsig = a->sig_start;
}

void zb_end_array(struct zb_builder *b, struct zb_scope *s)
{
	struct build_array *a = (void *)s;

	uint32_t len = (uint32_t)(b->next - a->data_start);
	memcpy(b->base + a->data_start - a->hdrlen, &len, 4);

	// check that the signature is where we expect
	size_t sigoff = (b->next != a->data_start) ? a->siglen : 0;
	if (b->nextsig != a->sig_start + sigoff) {
		b->next = b->end + 1;
	}
	b->nextsig = a->sig_start + a->siglen;
}

void zb_start_dict(struct zb_builder *b, struct zb_scope *s)
{
	struct build_array *a = (void *)s;
	if (b->nextsig[0] != ZB_ARRAY || b->nextsig[1] != ZB_DICT_BEGIN) {
		goto error;
	}

	int_fast32_t lenoff = align4(b->base, b->next);
	int_fast32_t dataoff = lenoff + 4;
	// data is 0 or 4 (mod 8)
	if (dataoff & 7U) {
		memset(b->base, 0, 4);
		dataoff += 4;
	}

	const char *nextsig = b->nextsig;
	b->nextsig += 2; // want to point to key signature
	b->next = dataoff;
	if (b->next > b->end || zb_skip_signature(&nextsig)) {
		goto error;
	}
	nextsig -= 1; // want to point to ending }

	a->sig_start = b->nextsig;
	a->siglen = (uint8_t)(nextsig - b->nextsig);
	a->data_start = b->next;
	a->hdrlen = (uint8_t)(b->next - lenoff);
	return;
error:
	// setup an error state with siglen = 0 and hdrlen = 0
	// so that zb_add_dict_entry and zb_end_dict don't crash
	a->sig_start = "}";
	a->siglen = 0;
	a->data_start = 0;
	a->hdrlen = 0;
	b->next = b->end + 1;
}

void zb_end_dict(struct zb_builder *b, struct zb_scope *s)
{
	zb_end_array(b, s);
	b->nextsig++; // }
}

void zb_add_multiv(struct zb_builder *b, const char *sig, va_list ap)
{
	while (*sig) {
		char type = *sig++;
		switch (type) {
		case ZB_BYTE:
			zb_add_byte(b, (uint8_t)va_arg(ap, int));
			break;
		case ZB_BOOL:
			zb_add_bool(b, (bool)va_arg(ap, int));
			break;
		case ZB_INT16:
		case ZB_UINT16:
			_zb_add2(b, (uint16_t)va_arg(ap, int), type);
			break;
		case ZB_INT32:
		case ZB_UINT32:
			_zb_add4(b, va_arg(ap, uint32_t), type);
			break;
		case ZB_INT64:
		case ZB_UINT64:
			_zb_add8(b, va_arg(ap, uint64_t), type);
			break;
		case ZB_DOUBLE:
			zb_add_double(b, va_arg(ap, double));
			break;
		case ZB_PATH:
		case ZB_STRING: {
			const char *str = va_arg(ap, const char *);
			_zb_add_string(b, str, strlen(str), type);
			break;
		}
		case ZB_SIGNATURE:
			zb_add_signature(b, va_arg(ap, const char *));
			break;
		case ZB_VARIANT:
			zb_add_variant(b, va_arg(ap, struct zb_variant *));
			break;
		case ZB_STRUCT_BEGIN: {
			struct zb_iterator *ii =
				va_arg(ap, struct zb_iterator *);
			zb_add_raw(b, ii->nextsig, ii->base + ii->next,
				   ii->end - ii->next);
			// step back one so zb_skip_signature can pick up that
			// we're in a struct
			sig--;
			if (zb_skip_signature(&sig)) {
				goto error;
			}
			break;
		}
		case ZB_ARRAY: {
			struct zb_iterator *ii =
				va_arg(ap, struct zb_iterator *);
			struct zb_scope array;
			zb_start_array(b, &array);
			zb_add_raw(b, ii->nextsig, ii->base + ii->next,
				   ii->end - ii->next);
			zb_end_array(b, &array);
			// step back one so zb_skip_signature can pick up that
			// we're in an array
			sig--;
			if (zb_skip_signature(&sig)) {
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

void zb_add_multi(struct zb_builder *b, const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	zb_add_multiv(b, sig, ap);
	va_end(ap);
}

//////////////////////////////
// message encoding

ZB_INLINE void write_little_4(char *p, uint32_t v)
{
#if defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	memcpy(p, &v, 4);
#else
	*(uint8_t *)(p) = (uint8_t)(v);
	*(uint8_t *)(p + 1) = (uint8_t)(v >> 8);
	*(uint8_t *)(p + 2) = (uint8_t)(v >> 16);
	*(uint8_t *)(p + 3) = (uint8_t)(v >> 24);
#endif
}

static void add_uint32_field(struct zb_builder *b, uint32_t tag, uint32_t v)
{
	// should be called first so that we are still aligned
	assert(!(b->next & 3U));
	int_fast32_t tagoff = b->next;
	int_fast32_t valoff = tagoff + 4;
	b->next = valoff + 4;
	if (b->next <= b->end) {
		write_little_4(b->base + tagoff, tag);
		memcpy(b->base + valoff, &v, 4);
	}
}

static void add_string_field(struct zb_builder *b, uint32_t tag,
			     const zb_str8 *str)
{
	align_buffer_8(b);
	int_fast32_t tagoff = b->next;
	int_fast32_t lenoff = tagoff + 4;
	int_fast32_t stroff = lenoff + 4;
	b->next = stroff + str->len + 1;
	if (b->next <= b->end) {
		uint32_t len32 = str->len;
		write_little_4(b->base + tagoff, tag);
		memcpy(b->base + lenoff, &len32, 4);
		memcpy(b->base + stroff, str->p, str->len + 1);
	}
}

static void add_signature_field(struct zb_builder *b, uint32_t tag,
				const char *sig)
{
	align_buffer_8(b);
	size_t len = strlen(sig);
	if (len > 255) {
		b->next = b->end + 1;
		return;
	}
	int_fast32_t tagoff = b->next;
	int_fast32_t lenoff = tagoff + 4;
	int_fast32_t stroff = lenoff + 1;
	b->next = stroff + (uint8_t)len + 1;
	if (b->next <= b->end) {
		write_little_4(b->base + tagoff, tag);
		*(uint8_t *)(b->base + lenoff) = (uint8_t)len;
		memcpy(b->base + stroff, sig, len + 1);
	}
}

ZB_INLINE void init_builder(struct zb_builder *b, char *buf, size_t bufsz,
			    const char *sig)
{
	// align the capacity down. This makes alignment calls not fail.
	size_t cap = bufsz & ~(size_t)7U;
	if (cap > ZB_MAX_MSG_SIZE) {
		cap = ZB_MAX_MSG_SIZE;
	}
#ifndef NDEBUG
	memset(buf, 0xBD, cap);
#endif
	b->base = buf;
	b->nextsig = sig;
	b->next = 0;
	b->end = (int_fast32_t)cap;

	// Put in a dummy buffer in an error state if the supplied buffer is
	// stupid small. This stops array encoding from crashing
	if (bufsz < 8) {
		static char dummy[8];
		b->base = dummy;
		b->next = b->end + 1;
	}
}

static int add_header(struct zb_builder *b, const struct zb_message *m,
		      size_t blen)
{
	int_fast32_t start = b->next;
	b->next += sizeof(struct raw_header);
	if (b->next > b->end || blen > ZB_MAX_MSG_SIZE) {
		return -1;
	}

	// unwrap the standard marshalling functions to add the field
	// type and variant signature in one go

	// fixed length fields go first so we can maintain 8 byte alignment
	if (m->reply_serial) {
		add_uint32_field(b, FTAG_REPLY_SERIAL, m->reply_serial);
	}
	if (m->fdnum) {
		add_uint32_field(b, FTAG_UNIX_FDS, m->fdnum);
	}
	if (*m->signature) {
		add_signature_field(b, FTAG_SIGNATURE, m->signature);
	}
	if (m->path) {
		add_string_field(b, FTAG_PATH, m->path);
	}
	if (m->interface) {
		add_string_field(b, FTAG_INTERFACE, m->interface);
	}
	if (m->member) {
		add_string_field(b, FTAG_MEMBER, m->member);
	}
	if (m->error) {
		add_string_field(b, FTAG_ERROR_NAME, m->error);
	}
	if (m->destination) {
		add_string_field(b, FTAG_DESTINATION, m->destination);
	}
	if (m->sender) {
		add_string_field(b, FTAG_SENDER, m->sender);
	}

	struct raw_header *h = (struct raw_header *)(b->base + start);
	h->endian = native_endian();
	h->type = m->type;
	h->flags = m->flags;
	h->version = DBUS_VERSION;
	uint32_t serial = m->serial;
	uint32_t flen32 = (uint32_t)(b->next - start - sizeof(*h));
	uint32_t blen32 = (uint32_t)blen;
	memcpy(h->serial, &serial, 4);
	memcpy(h->body_len, &blen32, 4);
	memcpy(h->field_len, &flen32, 4);

	// align the end of the fields
	align_buffer_8(b);

	return (b->next > b->end);
}

int zb_write_header(char *buf, size_t bufsz, const struct zb_message *msg,
		    size_t bodysz)
{
	struct zb_builder b;
	init_builder(&b, buf, bufsz, NULL);
	if (add_header(&b, msg, bodysz)) {
		return -1;
	}
	return (int)b.next;
}

void zb_start(struct zb_builder *b, char *buf, size_t bufsz,
	      const struct zb_message *msg)
{
	init_builder(b, buf, bufsz, msg->signature);
	// add_header leaves b in an error state if there was an error
	add_header(b, msg, 0);
}

int zb_end(struct zb_builder *b)
{
	if (zb_builder_get_error(b) || *b->nextsig) {
		// error during marshalling or missing arguments
		return -1;
	}
	struct raw_header *h = (struct raw_header *)b->base;
	uint32_t fsz;
	memcpy(&fsz, h->field_len, 4);
	uint32_t bsz = (uint32_t)(b->next - ZB_ALIGN_UP(fsz, 8) - sizeof(*h));
	memcpy(h->body_len, &bsz, 4);
	return (int)b->next;
}
