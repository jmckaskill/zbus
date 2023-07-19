#include "marshal.h"
#include "parse.h"
#include <stdarg.h>
#include <stdio.h>
#include <limits.h>

// a surprising amount of the time the data is already aligned
// e.g. string within struct
// outside of that, the alignment is unpredictable so use bitops
// pulling the already aligned case out also makes the bitops a bit simpler

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
	uint32_t mod = off & 3U;
	if (!mod) {
		return off;
	}
	uint32_t mask = (UINT32_C(1) << (mod * 8U)) - UINT32_C(1);
	uint32_t floor = off & ~3U;
	uint32_t data = read_native_4(base + floor);
	data &= mask;
	write_native_4(base + floor, data);
	return floor + 4;
}

static uint32_t align8(char *base, uint32_t off)
{
	uint32_t mod = off & 7U;
	if (!mod) {
		return off;
	}
	uint64_t mask = (UINT64_C(1) << (mod * 8U)) - UINT64_C(1);
	uint32_t floor = off & ~7U;
	uint64_t data = read_native_8(base + floor);
	data &= mask;
	write_native_8(base + floor, data);
	return floor + 8;
}

void align_buffer_8(struct buffer *b)
{
	// buffer is guarenteed to have 8 byte alignment so this should never
	// fail
	b->off = align8(b->base, b->off);
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

void append_raw(struct buffer *b, const char *sig, const void *p, size_t len)
{
	uint32_t off = alignx(b->base, b->off, *sig);
	uint32_t end = off + len;
	if (len + (size_t)off > UINT32_MAX || end > b->cap ||
	    !is_signature(b->sig, sig)) {
		b->off = UINT_MAX;
	} else {
		memcpy(b->base + off, p, len);
		b->off = end;
		b->sig += strlen(sig);
	}
}

void append_byte(struct buffer *b, uint8_t v)
{
	if (b->off >= b->cap || *b->sig != TYPE_BYTE) {
		b->off = UINT_MAX;
	} else {
		*(uint8_t *)(b->base + b->off) = v;
		b->off++;
		b->sig++;
	}
}

void _append2(struct buffer *b, uint16_t u, char type)
{
	uint32_t off = align2(b->base, b->off);
	b->off = off + 2;
	if (b->off > b->cap || *b->sig != type) {
		b->off = UINT_MAX;
	} else {
		u = read_native_2(b->base + off);
		b->sig++;
	}
}

void _append4(struct buffer *b, uint32_t u, char type)
{
	uint32_t off = align4(b->base, b->off);
	b->off = off + 4;
	if (b->off > b->cap || *b->sig != type) {
		b->off = UINT_MAX;
	} else {
		u = read_native_4(b->base + off);
		b->sig++;
	}
}

void _append8(struct buffer *b, uint64_t u, char type)
{
	uint32_t off = align8(b->base, b->off);
	b->off = off + 8;
	if (b->off > b->cap || *b->sig != type) {
		b->off = UINT_MAX;
	} else {
		u = read_native_8(b->base + off);
		b->sig++;
	}
}

void _append_string(struct buffer *b, slice_t str, char type)
{
	uint32_t len_off = align4(b->base, b->off);
	uint32_t str_off = len_off + 4;
	uint32_t nul_off = str_off + str.len;
	b->off = nul_off + 1;
	if (b->off > b->cap || *b->sig != type) {
		b->off = UINT_MAX;
	} else {
		write_native_4(b->base + len_off, str.len);
		memcpy(b->base + str_off, str.p, str.len);
		b->base[nul_off] = 0;
		b->sig++;
	}
}

void _append_signature(struct buffer *b, const char *sig, char type)
{
	size_t sig_len = strlen(sig);
	uint32_t len_off = b->off;
	uint32_t str_off = len_off + 1;
	b->off = str_off + sig_len + 1;
	if (sig_len > 255 || b->off > b->cap || *b->sig != type) {
		b->off = UINT_MAX;
	} else {
		*(uint8_t *)(b->base + len_off) = (uint8_t)sig_len;
		memcpy(b->base + str_off, sig, sig_len + 1);
		b->sig++;
	}
}

void append_vformat(struct buffer *b, const char *fmt, va_list ap)
{
	uint32_t len_off = align4(b->base, b->off);
	uint32_t data_off = len_off + 4;
	if (data_off + 1 > b->cap || *b->sig != TYPE_STRING) {
		b->off = UINT_MAX;
		return;
	}
	uint32_t maxsz = b->cap - data_off;
	// snprintf takes max number of bytes include nul
	// snprintf returns number of bytes excluding the nul
	int n = vsnprintf(b->base + data_off, maxsz, fmt, ap);
	if (n < 0 || n >= maxsz) {
		b->off = UINT_MAX;
		return;
	}
	write_native_4(b->base + len_off, n);
	b->off = data_off + n;
	b->sig++;
}

void append_format(struct buffer *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	append_vformat(b, fmt, ap);
	va_end(ap);
}

const char *start_variant(struct buffer *b, const char *sig)
{
	_append_signature(b, sig, TYPE_VARIANT);
	const char *ret = b->sig;
	b->sig = sig;
	return ret;
}

void end_variant(struct buffer *b, const char *start)
{
	// should have consumed the signature
	if (*b->sig) {
		b->off = UINT_MAX;
	}
	b->sig = start;
}

void append_variant(struct buffer *b, const char *sig, const void *raw,
		    size_t len)
{
	const char *nextsig = start_variant(b, sig);
	append_raw(b, sig, raw, len);
	end_variant(b, nextsig);
}

void start_struct(struct buffer *b)
{
	// alignment can't fail
	b->off = align8(b->base, b->off);
	if (*b->sig == TYPE_STRUCT_BEGIN) {
		b->sig++;
	} else {
		b->off = UINT_MAX;
	}
}

void end_struct(struct buffer *b)
{
	if (*b->sig == TYPE_STRUCT_END) {
		b->sig++;
	} else {
		b->off = UINT_MAX;
	}
}

struct array_data start_array(struct buffer *b)
{
	struct array_data a;
	if (*b->sig != TYPE_ARRAY) {
		goto error;
	}
	const char *nextsig = b->sig + 1;
	uint32_t start = align4(b->base, b->off);
	b->off = alignx(b->base, start + 4, b->sig[1]);
	if (b->off > b->cap || skip_signature(&nextsig, true)) {
		goto error;
	}
	b->sig++;
	a.siglen = (uint8_t)(nextsig - b->sig);
	a.hdrlen = (uint8_t)(b->off - start);
	a.sig = b->sig;
	a.start = start;
	return a;
error:
	// setup an error state with siglen = 0 and hdrlen = 0
	// so that next_in_array and end_array don't crash
	a.sig = "";
	a.start = 0;
	a.siglen = 0;
	a.hdrlen = 0;
	b->off = UINT_MAX;
	return a;
}

void next_in_array(struct buffer *b, struct array_data *a)
{
	// second or more array element, sig should be at the end
	if (b->off != a->start + a->hdrlen && b->sig != a->sig + a->siglen) {
		b->off = UINT_MAX;
	}
	b->sig = a->sig;
}

void end_array(struct buffer *b, struct array_data a)
{
	uint32_t len = b->off - a.start - a.hdrlen;
	memcpy(b->base + a.start, &len, 4);
	if (!len) {
		// no elements added
		b->sig = a.sig + a.siglen;
	} else if (b->sig != a.sig + a.siglen) {
		// elements added, sig should be at the end
		b->off = UINT_MAX;
	}
}

struct dict_data start_dict(struct buffer *b)
{
	struct dict_data d;
	if (b->sig[0] != TYPE_ARRAY || b->sig[1] != TYPE_DICT_BEGIN) {
		goto error;
	}
	const char *nextsig = b->sig + 2 /*a{*/;
	uint32_t start = align4(b->base, b->off);
	uint32_t data = start + 4;
	// data is 0 or 4 (mod 8)
	if (data & 7U) {
		memset(b->base + data, 0, 4);
		data += 4;
	}

	b->off = data;
	if (b->off > b->cap || skip_signature(&nextsig, false) ||
	    skip_signature(&nextsig, false) || *nextsig != TYPE_DICT_END) {
		goto error;
	}

	b->sig += 2; // a{
	d.a.siglen = (uint8_t)(nextsig - b->sig);
	d.a.hdrlen = (uint8_t)(data - start);
	d.a.sig = b->sig;
	d.a.start = start;
	return d;
error:
	// setup an error state with siglen = 0 and hdrlen = 0
	// so that next_in_dict and end_dict don't crash
	d.a.sig = "";
	d.a.start = 0;
	d.a.siglen = 0;
	d.a.hdrlen = 0;
	b->off = UINT_MAX;
	return d;
}

void end_dict(struct buffer *b, struct dict_data d)
{
	end_array(b, d.a);

	// b->sig may be "" in case of an error. Don't want to run the point off
	// the end of the string
	if (*b->sig) {
		b->sig++; // }
	}
}
