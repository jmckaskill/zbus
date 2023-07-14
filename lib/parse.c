#include "parse.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>

#define MAX_DEPTH 32

static inline const char *align2(const char *n, const char *error)
{
	const char *a = ALIGN_PTR_UP(const char *, n, 2);
#ifndef NDEBUG
	if (n < a) {
		if (*(n++)) {
			return error;
		}
	}
#else
	(void)error;
#endif
	return a;
}

static inline const char *align4(const char *n, const char *error)
{
	const char *a = ALIGN_PTR_UP(const char *, n, 4);
#ifndef NDEBUG
	while (n < a) {
		if (*(n++)) {
			return error;
		}
	}
#else
	(void)error;
#endif
	return a;
}

static inline const char *align8(const char *n, const char *error)
{
	const char *a = ALIGN_PTR_UP(const char *, n, 8);
#ifndef NDEBUG
	while (n < a) {
		if (*(n++)) {
			return error;
		}
	}
#else
	(void)error;
#endif
	return a;
}

void align_iterator_8(struct iterator *p)
{
	const char *n = align8(p->n, p->e);
	if (n > p->e) {
		p->error = 1;
	} else {
		p->n = n;
	}
}

static const char *alignx(char type, const char *n, const char *error)
{
	switch (type) {
	case TYPE_BYTE_BYTE:
	case TYPE_SIGNATURE_BYTE:
	case TYPE_VARIANT_BYTE:
		return n;
	case TYPE_INT16_BYTE:
	case TYPE_UINT16_BYTE:
		return align2(n, error);
	case TYPE_BOOL_BYTE:
	case TYPE_INT32_BYTE:
	case TYPE_UINT32_BYTE:
	case TYPE_STRING_BYTE:
	case TYPE_PATH_BYTE:
	case TYPE_ARRAY_BYTE:
		return align4(n, error);
	case TYPE_INT64_BYTE:
	case TYPE_UINT64_BYTE:
	case TYPE_DOUBLE_BYTE:
	case TYPE_DICT_BYTE:
	case TYPE_STRUCT_BYTE:
		return align8(n, error);
	default:
		return error;
	}
}

static uint8_t parse1(struct iterator *p, char type)
{
	const char *n = p->n;
	if (n >= p->e || *p->sig != type) {
		p->error = 1;
		return 0;
	}
	p->n = n + 1;
	p->sig++;
	return *(uint8_t *)n;
}

static uint16_t parse2(struct iterator *p, char type)
{
	const char *n = align2(p->n, p->e);
	if (n + 2 > p->e || *p->sig != type) {
		p->error = 1;
		return 0;
	}
	p->n = n + 2;
	p->sig++;
	return *(uint16_t *)n;
}

static uint32_t parse4(struct iterator *p, char type)
{
	const char *n = align4(p->n, p->e);
	if (n + 4 > p->e || *p->sig != type) {
		p->error = 1;
		return 0;
	}
	p->n = n + 4;
	p->sig++;
	return *(uint32_t *)n;
}

static uint64_t parse8(struct iterator *p, char type)
{
	const char *n = align8(p->n, p->e);
	if (n + 4 > p->e || *p->sig != type) {
		p->error = 1;
		return 0;
	}
	p->n = n + 8;
	p->sig++;
	return *(uint64_t *)n;
}

uint8_t parse_byte(struct iterator *p)
{
	return parse1(p, TYPE_BYTE_BYTE);
}

int16_t parse_int16(struct iterator *p)
{
	union {
		uint16_t u;
		int16_t i;
	} u;
	u.u = parse2(p, TYPE_INT16_BYTE);
	return u.i;
}

uint16_t parse_uint16(struct iterator *p)
{
	return parse2(p, TYPE_UINT16_BYTE);
}

int32_t parse_int32(struct iterator *p)
{
	union {
		int32_t i;
		uint32_t u;
	} u;
	u.u = parse4(p, TYPE_INT32_BYTE);
	return u.i;
}

uint32_t parse_uint32(struct iterator *p)
{
	return parse4(p, TYPE_UINT32_BYTE);
}

bool parse_bool(struct iterator *p)
{
	uint32_t u = parse4(p, TYPE_UINT32_BYTE);
	if (u > 1) {
		p->error = 1;
	}
	return u != 0;
}

int64_t parse_int64(struct iterator *p)
{
	union {
		int64_t i;
		uint64_t u;
	} u;
	u.u = parse4(p, TYPE_INT64_BYTE);
	return u.i;
}

uint64_t parse_uint64(struct iterator *p)
{
	return parse4(p, TYPE_UINT64_BYTE);
}

int parse_double(struct iterator *p, double *pv)
{
	union {
		double d;
		uint64_t u;
	} u;
	u.u = parse4(p, TYPE_DOUBLE_BYTE);
	return u.d;
}

static slice_t parse_string_bytes(struct iterator *p, unsigned len)
{
	slice_t ret = MAKE_SLICE("");
	const char *n = p->n;
	const char *e = n + len + 1;
	// need no nul bytes in the string and nul termination
	if (e > p->e || memchr(n, len, 0) || n[len]) {
		p->error = 1;
		return ret;
	}
	ret.p = n;
	ret.len = len;
	p->n = e;
	return ret;
}

const char *parse_signature(struct iterator *p)
{
	uint8_t len = parse1(p, TYPE_SIGNATURE_BYTE);
	slice_t str = parse_string_bytes(p, len);
	return str.p;
}

slice_t parse_string(struct iterator *p)
{
	uint32_t len = parse4(p, TYPE_STRING_BYTE);
	return parse_string_bytes(p, len);
}

slice_t parse_path(struct iterator *p)
{
	uint32_t len = parse4(p, TYPE_PATH_BYTE);
	slice_t str = parse_string_bytes(p, len);
	const char *s = str.p;
	if (*(s++) != '/') {
		// path must begin with / and can not be the empty string
		p->error = 1;
		return str;
	}
	if (!*s) {
		// trailing / only allowed if the path is "/"
		return str;
	}
	const char *segment = s;
	for (;;) {
		// only [A-Z][a-z][0-9]_ are allowed
		// / and \0 are not allowed as the first char of a segment
		// this rejects multiple / in sequence and a trailing /
		// respectively
		if (('A' <= *s && *s <= 'Z') || ('a' <= *s && *s <= 'z') ||
		    ('0' <= *s && *s <= '9') || *s == '_') {
			s++;
		} else if (s > segment && *s == '/') {
			segment = ++s;
		} else if (s > segment && *s == '\0') {
			return str;
		} else {
			p->error = 1;
			return str;
		}
	}
}

static void parse_variant_data(struct iterator *p, union variant_union *pu)
{
	char type = *p->sig;
	switch (type) {
	case TYPE_BYTE_BYTE:
		pu->u8 = parse_byte(p);
		break;
	case TYPE_INT16_BYTE:
	case TYPE_UINT16_BYTE:
		pu->u16 = parse2(p, type);
		break;
	case TYPE_BOOL_BYTE:
		pu->b = parse_bool(p);
		break;
	case TYPE_INT32_BYTE:
	case TYPE_UINT32_BYTE:
		pu->u32 = parse4(p, type);
		break;
	case TYPE_INT64_BYTE:
	case TYPE_UINT64_BYTE:
	case TYPE_DOUBLE_BYTE:
		pu->u64 = parse8(p, type);
		break;
	case TYPE_STRING_BYTE:
		pu->str = parse_string(p);
		break;
	case TYPE_PATH_BYTE:
		pu->path = parse_path(p);
		break;
	case TYPE_SIGNATURE_BYTE:
		pu->sig = parse_signature(p);
		break;
	case TYPE_VARIANT_BYTE: {
		struct variant v = parse_variant(p);
		pu->data = v.data;
		break;
	}
	case TYPE_ARRAY_BYTE:
		pu->data = skip_array(p);
		break;
	case TYPE_STRUCT_BYTE:
		pu->data = skip_struct(p);
		break;
	case TYPE_DICT_BYTE:
		// Can only occur as an array element. So there is never a need
		// to skip just a dict entry.
	default:
		p->error = 1;
		break;
	}
}

int skip_value(struct iterator *p)
{
	union variant_union u;
	parse_variant_data(p, &u);
	return p->error;
}

struct variant parse_variant(struct iterator *p)
{
	uint8_t len = parse1(p, TYPE_VARIANT_BYTE);
	slice_t sig = parse_string_bytes(p, len);

	struct variant ret;
	ret.data.n = p->n;
	ret.data.e = p->n;
	ret.data.sig = "";
	ret.data.depth = ++p->depth;
	ret.data.error = 1;
	ret.sig = TYPE_INVALID;

	const char *nextsig = p->sig;
	p->sig = sig.p;

	if (p->depth < MAX_DEPTH) {
		parse_variant_data(p, &ret.u);
		if (*p->sig || p->error) {
			p->error = 1;
		} else {
			ret.sig = sig.p;
			ret.data.sig = sig.p;
			ret.data.error = 0;
			ret.data.e = p->n;
		}
	}

	p->sig = nextsig;
	p->depth--;

	return ret;
}

struct iterator skip_array(struct iterator *p)
{
	uint32_t len = parse4(p, TYPE_ARRAY_BYTE);
	const char *n = alignx(*p->sig, p->n, p->e + 1);

	struct iterator ret;
	ret.n = n;
	ret.e = n;
	ret.depth = p->depth;
	ret.sig = p->sig;
	ret.error = 1;

	if (p->error || n + len > p->e || skip_signature(&p->sig)) {
		p->error = 1;
	} else {
		p->n = n + len;
		ret.e = p->n;
		ret.error = 0;
	}
	return ret;
}

static void _parse_struct(struct iterator *p, char type)
{
	const char *n = align8(p->n, p->e);
	if (!p->error && p->depth < MAX_DEPTH && n <= p->e && *p->sig == type) {
		p->sig++;
		p->depth++;
		p->n = n;
	} else {
		p->error = 1;
	}
}

void parse_struct_begin(struct iterator *p)
{
	_parse_struct(p, TYPE_STRUCT_BYTE);
}

void parse_dict_begin(struct iterator *p)
{
	_parse_struct(p, TYPE_DICT_BYTE);
}

void parse_dict_end(struct iterator *p)
{
	if (!p->error && *p->sig == TYPE_DICT_END_BYTE) {
		p->sig++;
		p->depth--;
	} else {
		p->error = 1;
	}
}

void parse_struct_end(struct iterator *p)
{
	do {
		skip_value(p);
	} while (*p->sig != TYPE_STRUCT_END_BYTE && !p->error);
	p->sig++;
	p->depth--;
}

struct iterator skip_struct(struct iterator *p)
{
	struct iterator ret;
	parse_struct_begin(p);
	ret.n = p->n;
	ret.e = p->n;
	ret.depth = p->depth;
	ret.sig = p->sig;
	parse_struct_end(p);
	ret.error = p->error;
	if (!p->error) {
		ret.e = p->n;
	}
	return ret;
}

bool parse_array_next(struct iterator *p, const char **psig)
{
	if (p->n >= p->e) {
		return false; // end of array data
	} else if (*psig) {
		p->sig = *psig;
		return true; // 2nd or later call
	} else {
		*psig = p->sig; // 1st call
		return true;
	}
}

int skip_signature(const char **psig)
{
	switch (*((*psig)++)) {
	case TYPE_BYTE_BYTE:
	case TYPE_BOOL_BYTE:
	case TYPE_INT16_BYTE:
	case TYPE_UINT16_BYTE:
	case TYPE_INT32_BYTE:
	case TYPE_UINT32_BYTE:
	case TYPE_INT64_BYTE:
	case TYPE_UINT64_BYTE:
	case TYPE_DOUBLE_BYTE:
	case TYPE_STRING_BYTE:
	case TYPE_PATH_BYTE:
	case TYPE_SIGNATURE_BYTE:
	case TYPE_VARIANT_BYTE:
		return 0;
	case TYPE_ARRAY_BYTE:
		return skip_signature(psig);
	case TYPE_DICT_BYTE:
		return skip_signature(psig) || skip_signature(psig) ||
		       *((*psig)++) != TYPE_DICT_END_BYTE;
	case TYPE_STRUCT_BYTE:
		do {
			if (skip_signature(psig)) {
				return -1;
			}
		} while (**psig != TYPE_STRUCT_END_BYTE);
		(*psig)++;
		return 0;
	default:
		return -1;
	}
}

#ifndef NDEBUG
void TEST_parse()
{
	fprintf(stderr, "TEST_parse\n");
	struct iterator p;
	static const uint8_t test1[] __attribute__((aligned(8))) = {
		1, // byte
		0, 2, 0, // u16
		3, 0, 0, 0, // u32
	};
	init_iterator(&p, "yqu", test1, sizeof(test1));
	assert(parse_byte(&p) == 1 && !p.error);
	assert(parse_uint16(&p) == 2 && !p.error);
	assert(parse_uint32(&p) == 3 && !p.error);
	assert(parse_byte(&p) == 0 && p.error);
}
#endif
