#include "parse.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>

#define MAX_DEPTH 32

int compare_string_x(const char *ap, unsigned alen, const char *bp,
		     unsigned blen)
{
	unsigned clen = alen < blen ? alen : blen;
	int c = memcmp(ap, bp, clen);
	return c ? c : ((int)alen - (int)blen);
}

int compare_string_p(const void *ca, const void *cb)
{
	const struct string *a = ca;
	const struct string *b = cb;
	return compare_string_x(a->p, a->len, b->p, b->len);
}

static inline const char *align2(const char *n, const char *error)
{
	const char *a = (const char *)(((uintptr_t)n + 1) & (~(uintptr_t)1));
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
	const char *a = (const char *)(((uintptr_t)n + 3) & (~(uintptr_t)3));
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
	const char *a = (const char *)(((uintptr_t)n + 7) & (~(uintptr_t)7));
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

static const char *alignx(char type, const char *n, const char *error)
{
	switch (type) {
	case TYPE_BYTE:
	case TYPE_SIGNATURE:
	case TYPE_VARIANT:
		return n;
	case TYPE_INT16:
	case TYPE_UINT16:
		return align2(n, error);
	case TYPE_BOOL:
	case TYPE_INT32:
	case TYPE_UINT32:
	case TYPE_STRING:
	case TYPE_PATH:
	case TYPE_ARRAY:
		return align4(n, error);
	case TYPE_INT64:
	case TYPE_UINT64:
	case TYPE_DOUBLE:
	case TYPE_DICT_BEGIN:
	case TYPE_STRUCT_BEGIN:
		return align8(n, error);
	default:
		return error;
	}
}

static uint8_t parse1(struct parser *p, char type)
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

static uint16_t parse2(struct parser *p, char type)
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

static uint32_t parse4(struct parser *p, char type)
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

static uint64_t parse8(struct parser *p, char type)
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

uint8_t parse_byte(struct parser *p)
{
	return parse1(p, TYPE_BYTE);
}

int16_t parse_int16(struct parser *p)
{
	union {
		uint16_t u;
		int16_t i;
	} u;
	u.u = parse2(p, TYPE_INT16);
	return u.i;
}

uint16_t parse_uint16(struct parser *p)
{
	return parse2(p, TYPE_UINT16);
}

int32_t parse_int32(struct parser *p)
{
	union {
		int32_t i;
		uint32_t u;
	} u;
	u.u = parse4(p, TYPE_INT32);
	return u.i;
}

uint32_t parse_uint32(struct parser *p)
{
	return parse4(p, TYPE_UINT32);
}

bool parse_bool(struct parser *p)
{
	uint32_t u = parse4(p, TYPE_UINT32);
	if (u > 1) {
		p->error = 1;
	}
	return u != 0;
}

int64_t parse_int64(struct parser *p)
{
	union {
		int64_t i;
		uint64_t u;
	} u;
	u.u = parse4(p, TYPE_INT64);
	return u.i;
}

uint64_t parse_uint64(struct parser *p)
{
	return parse4(p, TYPE_UINT64);
}

int parse_double(struct parser *p, double *pv)
{
	union {
		double d;
		uint64_t u;
	} u;
	u.u = parse4(p, TYPE_DOUBLE);
	return u.d;
}

static struct string parse_string_bytes(struct parser *p, unsigned len)
{
	struct string ret = INIT_STRING;
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

const char *parse_signature(struct parser *p)
{
	uint8_t len = parse1(p, TYPE_SIGNATURE);
	struct string str = parse_string_bytes(p, len);
	return str.p;
}

struct string parse_string(struct parser *p)
{
	uint32_t len = parse4(p, TYPE_STRING);
	return parse_string_bytes(p, len);
}

struct string parse_path(struct parser *p)
{
	uint32_t len = parse4(p, TYPE_PATH);
	struct string str = parse_string_bytes(p, len);
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

static char parse_variant_data(struct parser *p, union variant_union *pu)
{
	char type = *p->sig;
	switch (type) {
	case TYPE_BYTE:
		pu->u8 = parse_byte(p);
		return TYPE_BYTE;
	case TYPE_INT16:
	case TYPE_UINT16:
		pu->u16 = parse2(p, type);
		return type;
	case TYPE_BOOL:
		pu->b = parse_bool(p);
		return TYPE_BOOL;
	case TYPE_INT32:
	case TYPE_UINT32:
		pu->u32 = parse4(p, type);
		return type;
	case TYPE_INT64:
	case TYPE_UINT64:
	case TYPE_DOUBLE:
		pu->u64 = parse8(p, type);
		return type;
	case TYPE_STRING:
		pu->str = parse_string(p);
		return TYPE_STRING;
	case TYPE_PATH:
		pu->path = parse_path(p);
		return TYPE_PATH;
	case TYPE_SIGNATURE:
		pu->sig = parse_signature(p);
		return TYPE_SIGNATURE;
	case TYPE_VARIANT: {
		struct variant v = parse_variant(p);
		pu->data = v.data;
		return TYPE_VARIANT;
	}
	case TYPE_ARRAY:
		pu->data = skip_array(p);
		return TYPE_ARRAY;
	case TYPE_STRUCT_BEGIN:
		pu->data = skip_struct(p);
		return TYPE_RECORD;
	case TYPE_DICT_BEGIN:
		// Can only occur as an array element. So there is never a need
		// to skip just a dict entry.
	default:
		p->error = 1;
		return TYPE_INVALID;
	}
}

int skip_value(struct parser *p)
{
	union variant_union u;
	parse_variant_data(p, &u);
	return p->error;
}

struct variant parse_variant(struct parser *p)
{
	uint8_t len = parse1(p, TYPE_VARIANT);
	struct string sig = parse_string_bytes(p, len);

	struct variant ret;
	ret.data.n = p->n;
	ret.data.e = p->n;
	ret.data.sig = "";
	ret.data.depth = ++p->depth;
	ret.data.error = 1;
	ret.type = TYPE_INVALID;

	const char *nextsig = p->sig;
	p->sig = sig.p;

	if (p->depth < MAX_DEPTH) {
		char type = parse_variant_data(p, &ret.u);
		if (*p->sig || p->error) {
			p->error = 1;
		} else {
			ret.type = type;
			ret.data.sig = sig.p;
			ret.data.error = 0;
			ret.data.e = p->n;
		}
	}

	p->sig = nextsig;
	p->depth--;

	return ret;
}

struct parser skip_array(struct parser *p)
{
	uint32_t len = parse4(p, TYPE_ARRAY);
	const char *n = alignx(*p->sig, p->n, p->e + 1);

	struct parser ret;
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

static void _parse_struct(struct parser *p, char type)
{
	const char *n = ALIGN_PTR_UP(const char *, p->n, 8);
	if (!p->error && p->depth < MAX_DEPTH && n <= p->e) {
		p->sig++;
		p->depth++;
		p->n = n;
	} else {
		p->error = 1;
	}
}

void parse_struct_begin(struct parser *p)
{
	_parse_struct(p, TYPE_STRUCT_BEGIN);
}

void parse_dict_begin(struct parser *p)
{
	_parse_struct(p, TYPE_STRUCT_END);
}

void parse_dict_end(struct parser *p)
{
	if (!p->error && *p->sig == TYPE_DICT_END) {
		p->sig++;
		p->depth--;
	} else {
		p->error = 1;
	}
}

void parse_struct_end(struct parser *p)
{
	do {
		skip_value(p);
	} while (*p->sig != TYPE_STRUCT_END && !p->error);
	p->sig++;
	p->depth--;
}

struct parser skip_struct(struct parser *p)
{
	struct parser ret;
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

bool parse_array_next(struct parser *p, const char **psig)
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
	case TYPE_BYTE:
	case TYPE_BOOL:
	case TYPE_INT16:
	case TYPE_UINT16:
	case TYPE_INT32:
	case TYPE_UINT32:
	case TYPE_INT64:
	case TYPE_UINT64:
	case TYPE_DOUBLE:
	case TYPE_STRING:
	case TYPE_PATH:
	case TYPE_SIGNATURE:
	case TYPE_VARIANT:
		return 0;
	case TYPE_ARRAY:
		return skip_signature(psig);
	case TYPE_DICT_BEGIN:
		return skip_signature(psig) || skip_signature(psig) ||
		       *((*psig)++) != TYPE_DICT_END;
	case TYPE_STRUCT_BEGIN:
		do {
			if (skip_signature(psig)) {
				return -1;
			}
		} while (**psig != TYPE_STRUCT_END);
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
	struct parser p;
	static const uint8_t test1[] __attribute__((aligned(8))) = {
		1, // byte
		0, 2, 0, // u16
		3, 0, 0, 0, // u32
	};
	init_parser(&p, "yqu", test1, sizeof(test1));
	assert(parse_byte(&p) == 1 && !p.error);
	assert(parse_uint16(&p) == 2 && !p.error);
	assert(parse_uint32(&p) == 3 && !p.error);
	assert(parse_byte(&p) == 0 && p.error);
}
#endif
