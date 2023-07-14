#include "marshal.h"
#include "parse.h"

void move_buffer(struct buffer *b, char *p, unsigned cap)
{
	// need to have a non-zero buffer to allow end_array to work even
	// if start_array failed
	assert(cap > 4);
	// ensure the capacity is a multiple of 8. this way we can easily
	// align the body in start_body without having to do a size check
	assert(ALIGN_UINT_UP(cap, 8) == cap);
	// needs to be aligned as we use pointer casts to set data
	assert(ALIGN_PTR_UP(char *, p, 8) == p);
	b->base = p;
	b->cap = cap;
#ifndef NDEBUG
	memset(b->base + b->off, 0xDE, b->cap - b->off);
#endif
}

// a surprising amount of the time the data is already aligned
// e.g. string within struct
// outside of that, the alignment is unpredictable so use bitops
// pulling the already aligned case out also makes the bitops a bit simpler

static unsigned align2(char *base, unsigned off)
{
	unsigned mod = off & 1U;
	if (!mod) {
		return off;
	}
	base[off] = 0;
	return off + 1;
}

static unsigned align4(char *base, unsigned off)
{
	unsigned mod = off & 3U;
	if (!mod) {
		return off;
	}
	uint32_t mask = (UINT32_C(1) << (mod * 8U)) - UINT32_C(1);
	unsigned existing = off & ~3U;
	uint32_t *pexisting = (uint32_t *)(base + existing);
	*pexisting &= mask;
	return existing + 4;
}

static unsigned align8(char *base, unsigned off)
{
	unsigned mod = off & 7U;
	if (!mod) {
		return off;
	}
	uint64_t mask = (UINT64_C(1) << (mod * 8U)) - UINT64_C(1);
	unsigned existing = off & ~7U;
	uint64_t *pexisting = (uint64_t *)(base + existing);
	*pexisting &= mask;
	return existing + 8;
}

void align_buffer_8(struct buffer *b)
{
	// buffer is guarenteed to have 8 byte alignment so this should never
	// fail
	b->off = align8(b->base, b->off);
}

static unsigned alignx(char *base, unsigned off, char type)
{
	switch (type) {
	case TYPE_INT16_BYTE:
	case TYPE_UINT16_BYTE:
		return align2(base, off);
	case TYPE_BOOL_BYTE:
	case TYPE_INT32_BYTE:
	case TYPE_UINT32_BYTE:
	case TYPE_STRING_BYTE:
	case TYPE_PATH_BYTE:
	case TYPE_ARRAY_BYTE:
		return align4(base, off);
	case TYPE_INT64_BYTE:
	case TYPE_UINT64_BYTE:
	case TYPE_DOUBLE_BYTE:
	case TYPE_DICT_BYTE:
	case TYPE_STRUCT_BYTE:
		return align8(base, off);
	case TYPE_BYTE_BYTE:
	case TYPE_SIGNATURE_BYTE:
	case TYPE_VARIANT_BYTE:
	default:
		return off;
	}
}

void append_raw(struct buffer *b, const char *sig, const void *p, unsigned len)
{
	unsigned off = alignx(b->base, b->off, *sig);
	unsigned end = off + len;
	if (end > b->cap || !is_signature(b->sig, sig)) {
		b->error = 1;
	} else {
		memcpy(b->base + off, p, len);
		b->off = end;
		b->sig += strlen(sig);
	}
}

void append_byte(struct buffer *b, uint8_t v)
{
	if (b->off == b->cap || *b->sig != TYPE_BYTE_BYTE) {
		b->error = 1;
	} else {
		*(uint8_t *)(b->base + b->off) = v;
		b->off++;
		b->sig++;
	}
}

void _append2(struct buffer *b, uint16_t u, char type)
{
	unsigned off = align2(b->base, b->off);
	if (off + 2 > b->cap || *b->sig != type) {
		b->error = 1;
	} else {
		*(uint16_t *)(b->base + off) = u;
		b->off = off + 2;
		b->sig++;
	}
}

void _append4(struct buffer *b, uint32_t u, char type)
{
	unsigned off = align4(b->base, b->off);
	if (off + 4 > b->cap || *b->sig != type) {
		b->error = 1;
	} else {
		*(uint32_t *)(b->base + off) = u;
		b->off = off + 4;
		b->sig++;
	}
}

void _append8(struct buffer *b, uint64_t u, char type)
{
	unsigned off = align8(b->base, b->off);
	if (off + 8 > b->cap || *b->sig != type) {
		b->error = 1;
	} else {
		*(uint64_t *)(b->base + off) = u;
		b->off = off + 8;
		b->sig++;
	}
}

void _append_string(struct buffer *b, slice_t str, char type)
{
	unsigned len_off = align4(b->base, b->off);
	unsigned data_off = len_off + 4;
	unsigned end = data_off + str.len + 1;
	if (end > b->cap || *b->sig != type) {
		b->error = 1;
	} else {
		*(uint32_t *)(b->base + len_off) = str.len;
		memcpy(b->base + data_off, str.p, str.len);
		b->base[end - 1] = 0;
		b->off = end;
		b->sig++;
	}
}

void _append_signature(struct buffer *b, const char *sig, char type)
{
	size_t sig_len = strlen(sig);
	unsigned len_off = b->off;
	unsigned data_off = len_off + 1;
	unsigned end = data_off + sig_len + 1;
	if (sig_len > 255 || end > b->cap || *b->sig != type) {
		b->error = 1;
	} else {
		*(uint8_t *)(b->base + len_off) = (uint8_t)sig_len;
		memcpy(b->base + data_off, sig, sig_len + 1);
		b->off = end;
		b->sig++;
	}
}

const char *start_variant(struct buffer *b, const char *sig)
{
	_append_signature(b, sig, TYPE_VARIANT_BYTE);
	const char *ret = b->sig;
	b->sig = sig;
	return ret;
}

void end_variant(struct buffer *b, const char *start)
{
	// should have consumed the signature
	b->error = b->error || *b->sig;
	b->sig = start;
}

void append_variant(struct buffer *b, const char *sig, const void *raw,
		    unsigned len)
{
	const char *nextsig = start_variant(b, sig);
	append_raw(b, sig, raw, len);
	end_variant(b, nextsig);
}

void start_struct(struct buffer *b)
{
	// alignment can't fail
	b->off = align8(b->base, b->off);
	if (*b->sig == TYPE_STRUCT_BYTE) {
		b->sig++;
	} else {
		b->error = 1;
	}
}

void end_struct(struct buffer *b)
{
	if (*b->sig == TYPE_STRUCT_END_BYTE) {
		b->sig++;
	} else {
		b->error = 1;
	}
}

void start_array(struct buffer *b, struct array_data *a)
{
	if (*b->sig != TYPE_ARRAY_BYTE) {
		goto error;
	}
	unsigned start = align4(b->base, b->off);
	unsigned data = alignx(b->base, start + 4, b->sig[1]);
	const char *nextsig = b->sig + 1;
	if (data > b->cap || skip_signature(&nextsig)) {
		goto error;
	}
	b->sig++;
	b->off = data;
	a->siglen = (uint8_t)(nextsig - b->sig);
	a->hdrlen = (uint8_t)(data - start);
	a->sig = b->sig;
	a->start = start;
	return;
error:
	// setup an error state with siglen = 0 and hdrlen = 0
	// so that next_in_array and end_array don't crash
	a->sig = "";
	a->start = 0;
	a->siglen = 0;
	a->hdrlen = 0;
	b->error = 1;
}

void next_in_array(struct buffer *b, struct array_data *a)
{
	// second or more array element, sig should be at the end
	if (b->off != a->start + a->hdrlen && b->sig != a->sig + a->siglen) {
		b->error = 1;
	}
	b->sig = a->sig;
}

void end_array(struct buffer *b, struct array_data *a)
{
	unsigned len = b->off - a->start - a->hdrlen;
	*(uint32_t *)(b->base + a->start) = len;
	if (!len) {
		// no elements added
		b->sig = a->sig + a->siglen;
	} else if (b->sig != a->sig + a->siglen) {
		// elements added, sig should be at the end
		b->error = 1;
	}
}

void start_dict(struct buffer *b, struct array_data *a)
{
	if (b->sig[0] != TYPE_ARRAY_BYTE || b->sig[1] != TYPE_DICT_BYTE) {
		goto error;
	}
	const char *nextsig = b->sig + 2 /*a{*/;
	unsigned start = align4(b->base, b->off);
	unsigned data = start + 4;
	// data is 0 or 4 (mod 8)
	if (data & 7U) {
		*(uint32_t *)(b->base + data) = 0;
		data += 4;
	}

	if (data > b->cap || skip_signature(&nextsig) ||
	    skip_signature(&nextsig) || *nextsig != TYPE_DICT_END_BYTE) {
		goto error;
	}

	b->sig += 2;
	b->off = data;
	a->siglen = (uint8_t)(nextsig - b->sig);
	a->hdrlen = (uint8_t)(data - start);
	a->sig = b->sig;
	a->start = start;
	return;
error:
	// setup an error state with siglen = 0 and hdrlen = 0
	// so that next_in_dict and end_dict don't crash
	a->sig = "}";
	a->start = 0;
	a->siglen = 0;
	a->hdrlen = 0;
	b->error = 1;
}

void end_dict(struct buffer *b, struct array_data *a)
{
	end_array(b, a);
	if (!b->error) {
		b->sig++; // }
	}
}
