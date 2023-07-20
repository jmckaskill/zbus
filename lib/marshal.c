#include "marshal.h"
#include "parse.h"
#include <stdarg.h>
#include <stdio.h>
#include <limits.h>

// a surprising amount of the time the data is already aligned
// e.g. string within struct
// outside of that, the alignment is unpredictable so use bitops
// pulling the already aligned case out also makes the bitops a bit simpler

static char *align2(char *n)
{
	unsigned mod = ((unsigned)(uintptr_t)n) & 1U;
	if (!mod) {
		return n;
	}
	*n = 0;
	return n + 1;
}

static char *align4(char *n)
{
	unsigned mod = ((unsigned)(uintptr_t)n) & 3U;
	if (!mod) {
		return n;
	}
	char *pfloor = n - mod;
	uint32_t mask = (UINT32_C(1) << (mod * 8U)) - UINT32_C(1);
	*(uint32_t *)pfloor &= mask;
	return pfloor + 4;
}

static char *align8(char *n)
{
	unsigned mod = ((unsigned)(uintptr_t)n) & 7U;
	if (!mod) {
		return n;
	}
	char *pfloor = n - mod;
	uint64_t mask = (UINT64_C(1) << (mod * 8U)) - UINT64_C(1);
	*(uint64_t *)pfloor &= mask;
	return pfloor + 8;
}

void align_buffer_8(struct builder *b)
{
	// buffer is guarenteed to have 8 byte alignment so this should never
	// fail
	b->next = align8(b->next);
}

static char *alignx(char *next, char type)
{
	switch (type) {
	case TYPE_INT16:
	case TYPE_UINT16:
		return align2(next);
	case TYPE_BOOL:
	case TYPE_INT32:
	case TYPE_UINT32:
	case TYPE_STRING:
	case TYPE_PATH:
	case TYPE_ARRAY:
		return align4(next);
	case TYPE_INT64:
	case TYPE_UINT64:
	case TYPE_DOUBLE:
	case TYPE_DICT_BEGIN:
	case TYPE_STRUCT_BEGIN:
		return align8(next);
	case TYPE_BYTE:
	case TYPE_SIGNATURE:
	case TYPE_VARIANT:
	default:
		return next;
	}
}

void append_raw(struct builder *b, const char *sig, const void *p, size_t len)
{
	char *base = alignx(b->next, *sig);
	char *end = base + len;
	if (end > b->end || !is_signature(b->sig, sig)) {
		b->next = b->end + 1;
	} else {
		memcpy(base, p, len);
		b->next = end;
		b->sig += strlen(sig);
	}
}

void append_byte(struct builder *b, uint8_t v)
{
	if (*b->sig != TYPE_BYTE) {
		b->next = b->end + 1;
	} else if (b->next < b->end) {
		*(uint8_t *)(b->next++) = v;
		b->sig++;
	}
}

void _append2(struct builder *b, uint16_t u, char type)
{
	char *base = align2(b->next);
	b->next = base + 2;
	if (*b->sig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		*(uint16_t *)base = u;
		b->sig++;
	}
}

void _append4(struct builder *b, uint32_t u, char type)
{
	char *base = align4(b->next);
	b->next = base + 2;
	if (*b->sig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		*(uint32_t *)base = u;
		b->sig++;
	}
}

void _append8(struct builder *b, uint64_t u, char type)
{
	char *base = align8(b->next);
	b->next = base + 8;
	if (*b->sig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		*(uint64_t *)base = u;
		b->sig++;
	}
}

void _append_string(struct builder *b, slice_t str, char type)
{
	char *plen = align4(b->next);
	char *pstr = plen + 4;
	char *pnul = pstr + str.len;
	b->next = pnul + 1;
	if (*b->sig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		*(uint32_t *)plen = str.len;
		memcpy(pstr, str.p, str.len);
		*pnul = 0;
		b->sig++;
	}
}

void _append_signature(struct builder *b, const char *sig, char type)
{
	size_t len = strlen(sig);
	char *plen = b->next;
	char *pstr = plen + 1;
	b->next = pstr + len + 1;
	if (len > 255 || *b->sig != type) {
		b->next = b->end + 1;
	} else if (b->next <= b->end) {
		*(uint8_t *)plen = (uint8_t)len;
		memcpy(pstr, sig, len + 1);
		b->sig++;
	}
}

void append_vformat(struct builder *b, const char *fmt, va_list ap)
{
	char *plen = align4(b->next);
	char *pstr = plen + 4;
	if (pstr + 1 > b->end || *b->sig != TYPE_STRING) {
		goto error;
	}
	// snprintf takes max number of bytes include nul
	// snprintf returns number of bytes excluding the nul
	size_t maxsz = b->end - pstr;
	int n = vsnprintf(pstr, maxsz, fmt, ap);
	if (n < 0 || n >= maxsz) {
		goto error;
	}
	*(uint32_t *)plen = (uint32_t)n;
	b->next = pstr + n + 1;
	b->sig++;
	return;
error:
	b->next = b->end + 1;
}

void append_format(struct builder *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	append_vformat(b, fmt, ap);
	va_end(ap);
}

const char *start_variant(struct builder *b, const char *sig)
{
	_append_signature(b, sig, TYPE_VARIANT);
	const char *ret = b->sig;
	b->sig = sig;
	return ret;
}

void end_variant(struct builder *b, const char *start)
{
	// should have consumed the signature
	if (*b->sig) {
		b->next = b->end + 1;
	}
	b->sig = start;
}

void append_variant(struct builder *b, const char *sig, const void *raw,
		    size_t len)
{
	const char *nextsig = start_variant(b, sig);
	append_raw(b, sig, raw, len);
	end_variant(b, nextsig);
}

void start_struct(struct builder *b)
{
	// alignment can't fail
	if (*b->sig == TYPE_STRUCT_BEGIN) {
		b->next = align8(b->next);
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
	const char *nextsig = b->sig + 1;
	char *start = align4(b->next);
	b->next = alignx(start + 4, b->sig[1]);
	if (b->next > b->end || skip_signature(&nextsig, true)) {
		goto error;
	}
	b->sig++;
	a.siglen = (uint8_t)(nextsig - b->sig);
	a.hdrlen = (uint8_t)(b->next - start);
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
	b->next = b->end + 1;
	return a;
}

void next_in_array(struct builder *b, struct array_data *a)
{
	// second or more array element, sig should be at the end
	if (b->next != a->start + a->hdrlen && b->sig != a->sig + a->siglen) {
		b->next = b->end + 1;
	}
	b->sig = a->sig;
}

void end_array(struct builder *b, struct array_data a)
{
	size_t len = b->next - a.start;
	*(uint32_t *)a.start = (uint32_t)len;
	if (!len) {
		// no elements added, so need to move forward sig manually
		b->sig = a.sig + a.siglen;
	} else if (b->sig != a.sig + a.siglen) {
		// elements added, sig should be at the end
		b->next = b->end + 1;
	}
}

struct dict_data start_dict(struct builder *b)
{
	struct dict_data d;
	if (b->sig[0] != TYPE_ARRAY || b->sig[1] != TYPE_DICT_BEGIN) {
		goto error;
	}
	const char *nextsig = b->sig + 2 /*a{*/;
	char *start = align4(b->next);
	char *data = start + 4;
	// data is 0 or 4 (mod 8)
	if (((unsigned)(uintptr_t)data) & 7U) {
		*(uint32_t *)data = 0;
		data += 4;
	}

	b->next = data;
	if (b->next > b->end || skip_signature(&nextsig, false) ||
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
	b->next = b->end + 1;
	return d;
}

void end_dict(struct builder *b, struct dict_data d)
{
	end_array(b, d.a);

	// b->sig may be "" in case of an error. Don't want to run the point off
	// the end of the string
	if (*b->sig) {
		b->sig++; // }
	}
}
