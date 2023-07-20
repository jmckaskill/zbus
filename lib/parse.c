#include "parse.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdalign.h>

#define MAX_DEPTH 32

static inline int align2(const char *base, uint32_t off, uint32_t error)
{
	uint32_t aligned = ALIGN_UINT_UP(off, 2);
#ifndef NDEBUG
	if (off < aligned) {
		if (base[off++]) {
			return error;
		}
	}
#else
	(void)error;
#endif
	return aligned;
}

static inline int align4(const char *base, uint32_t off, uint32_t error)
{
	uint32_t aligned = ALIGN_UINT_UP(off, 4);
#ifndef NDEBUG
	while (off < aligned) {
		if (base[off++]) {
			return error;
		}
	}
#else
	(void)error;
#endif
	return aligned;
}

static inline int align8(const char *base, uint32_t off, uint32_t error)
{
	uint32_t aligned = ALIGN_UINT_UP(off, 8);
#ifndef NDEBUG
	while (off < aligned) {
		if (base[off++]) {
			return error;
		}
	}
#else
	(void)error;
#endif
	return aligned;
}

void align_iterator_8(struct iterator *p)
{
	uint32_t n = align8(p->base, p->next, p->end);
	if (n > p->end) {
		p->next = p->end + 1;
	} else {
		p->next = n;
	}
}

static uint32_t alignx(char type, const char *base, uint32_t off,
		       uint32_t error)
{
	switch (type) {
	case TYPE_BYTE:
	case TYPE_SIGNATURE:
	case TYPE_VARIANT:
		return off;
	case TYPE_INT16:
	case TYPE_UINT16:
		return align2(base, off, error);
	case TYPE_BOOL:
	case TYPE_INT32:
	case TYPE_UINT32:
	case TYPE_STRING:
	case TYPE_PATH:
	case TYPE_ARRAY:
		return align4(base, off, error);
	case TYPE_INT64:
	case TYPE_UINT64:
	case TYPE_DOUBLE:
	case TYPE_DICT:
	case TYPE_STRUCT:
		return align8(base, off, error);
	default:
		return error;
	}
}

static uint8_t parse1(struct iterator *p, char type)
{
	uint32_t n = p->next;
	if (n >= p->end || *p->sig != type) {
		p->next = p->end + 1;
		return 0;
	}
	p->next++;
	p->sig++;
	return *(uint8_t *)(p->base + n);
}

static uint16_t parse2(struct iterator *p, char type)
{
	uint32_t n = align2(p->base, p->next, p->end);
	if (n + 2 > p->end || *p->sig != type) {
		p->next = p->end + 1;
		return 0;
	}
	p->next = n + 2;
	p->sig++;
	return read_native_2(p->base + n);
}

static uint32_t parse4(struct iterator *p, char type)
{
	uint32_t n = align4(p->base, p->next, p->end);
	if (n + 4 > p->end || *p->sig != type) {
		p->next = p->end + 1;
		return 0;
	}
	p->next = n + 4;
	p->sig++;
	return read_native_4(p->base + n);
}

static uint64_t parse8(struct iterator *p, char type)
{
	uint32_t n = align8(p->base, p->next, p->end);
	if (n + 8 > p->end || *p->sig != type) {
		p->next = p->end + 1;
		return 0;
	}
	p->next = n + 8;
	p->sig++;
	return read_native_8(p->base + n);
}

uint8_t parse_byte(struct iterator *p)
{
	return parse1(p, TYPE_BYTE);
}

int16_t parse_int16(struct iterator *p)
{
	return (int16_t)parse2(p, TYPE_INT16);
}

uint16_t parse_uint16(struct iterator *p)
{
	return parse2(p, TYPE_UINT16);
}

int32_t parse_int32(struct iterator *p)
{
	return (int32_t)parse4(p, TYPE_INT32);
}

uint32_t parse_uint32(struct iterator *p)
{
	return parse4(p, TYPE_UINT32);
}

bool parse_bool(struct iterator *p)
{
	uint32_t u = parse4(p, TYPE_UINT32);
	if (u > 1) {
		p->next = p->end + 1;
	}
	return u != 0;
}

int64_t parse_int64(struct iterator *p)
{
	return (int64_t)parse8(p, TYPE_INT64);
}

uint64_t parse_uint64(struct iterator *p)
{
	return parse8(p, TYPE_UINT64);
}

int parse_double(struct iterator *p, double *pv)
{
	union {
		double d;
		uint64_t u;
	} u;
	u.u = parse8(p, TYPE_DOUBLE);
	return u.d;
}

int check_string(slice_t s)
{
	// need no nul bytes in the string and nul termination
	return memchr(s.p, 0, s.len) || s.p[s.len];
}

static slice_t parse_string_bytes(struct iterator *p, uint32_t len)
{
	slice_t ret = MAKE_SLICE("");
	ret.p = p->base + p->next;
	ret.len = len;
	uint32_t n = p->next + len + 1;
	if (len > MAX_ARRAY_SIZE || n > p->end || check_string(ret)) {
		p->next = p->end + 1;
		return ret;
	}
	p->next = n;
	return ret;
}

const char *parse_signature(struct iterator *p)
{
	uint8_t len = parse1(p, TYPE_SIGNATURE);
	slice_t str = parse_string_bytes(p, len);
	return str.p;
}

slice_t parse_string(struct iterator *p)
{
	uint32_t len = parse4(p, TYPE_STRING);
	return parse_string_bytes(p, len);
}

int check_path(const char *s)
{
	if (*(s++) != '/') {
		// path must begin with / and can not be the empty string
		return -1;
	}
	if (!*s) {
		// trailing / only allowed if the path is "/"
		return 0;
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
			return 0;
		} else {
			return -1;
		}
	}
}

slice_t parse_path(struct iterator *p)
{
	uint32_t len = parse4(p, TYPE_PATH);
	slice_t str = parse_string_bytes(p, len);
	if (check_path(str.p)) {
		p->next = p->end + 1;
	}
	return str;
}

struct variant parse_variant(struct iterator *p)
{
	uint8_t len = parse1(p, TYPE_VARIANT);
	slice_t sig = parse_string_bytes(p, len);

	struct variant ret;
	ret.sig = sig.p;

	const char *nextsig = p->sig;
	p->sig = sig.p;

	char type = *p->sig;
	switch (type) {
	case TYPE_BYTE:
		ret.u.u8 = parse_byte(p);
		break;
	case TYPE_INT16:
	case TYPE_UINT16:
		ret.u.u16 = parse2(p, type);
		break;
	case TYPE_BOOL:
		ret.u.b = parse_bool(p);
		break;
	case TYPE_INT32:
	case TYPE_UINT32:
		ret.u.u32 = parse4(p, type);
		break;
	case TYPE_INT64:
	case TYPE_UINT64:
	case TYPE_DOUBLE:
		ret.u.u64 = parse8(p, type);
		break;
	case TYPE_STRING:
		ret.u.str = parse_string(p);
		break;
	case TYPE_PATH:
		ret.u.path = parse_path(p);
		break;
	case TYPE_SIGNATURE:
		ret.u.sig = parse_signature(p);
		break;
	case TYPE_VARIANT:
	case TYPE_STRUCT_BEGIN:
		ret.u.record = skip_value(p);
		break;
	case TYPE_ARRAY:
		ret.u.array = skip_array(p);
		break;
	case TYPE_DICT_BEGIN:
		// Can only occur as an array element. So there is never a need
		// to skip just a dict entry.
	default:
		p->end = p->next + 1;
		break;
	}

	if (iter_error(p)) {
		ret.sig = "";
	}

	p->sig = nextsig;
	return ret;
}

struct iterator skip_array(struct iterator *p)
{
	uint32_t len = parse4(p, TYPE_ARRAY);
	uint32_t start = alignx(*p->sig, p->base, p->next, p->end);

	struct iterator ret;
	ret.base = p->base;
	ret.next = start;
	ret.end = start + len;
	ret.sig = p->sig;

	if (len > MAX_ARRAY_SIZE || start + len > p->end ||
	    skip_signature(&p->sig, true)) {
		ret.next = ret.end + 1;
	} else {
		p->next = ret.end;
	}

	return ret;
}

static void _parse_struct(struct iterator *p, char type)
{
	uint32_t n = align8(p->base, p->next, p->end);
	if (n > p->end || *p->sig != type) {
		p->next = p->end + 1;
	} else {
		p->sig++;
		p->next = n;
	}
}

void parse_struct_begin(struct iterator *p)
{
	_parse_struct(p, TYPE_STRUCT_BEGIN);
}

void parse_dict_begin(struct iterator *p)
{
	_parse_struct(p, TYPE_DICT_BEGIN);
}

void parse_dict_end(struct iterator *p)
{
	if (*p->sig == TYPE_DICT_END) {
		p->sig++;
	} else {
		p->next = p->end + 1;
	}
}

void parse_struct_end(struct iterator *p)
{
	for (;;) {
		skip_value(p);
		if (iter_error(p)) {
			return;
		}
		if (*p->sig == TYPE_STRUCT_END) {
			p->sig++;
			return;
		}
	}
}

bool parse_array_next(struct iterator *p, const char **psig)
{
	if (p->next >= p->end) {
		return false; // end of array data
	} else if (*psig) {
		p->sig = *psig;
		return true; // 2nd or later call
	} else {
		*psig = p->sig; // 1st call
		return true;
	}
}

struct iterator skip_value(struct iterator *p)
{
	const char *base = p->base;
	uint32_t next = p->next;
	uint32_t end = p->end;
	const char *sig = p->sig;
	const char *stack[MAX_DEPTH];
	int stackn = 0;

	struct iterator ret;
	ret.base = p->base;
	ret.sig = sig;
	ret.next = next;

	if (*sig) {
		goto error;
	}

	for (;;) {
		switch (*(sig++)) {
		case '\0':
			if (stackn) {
				// we've reached the end of the variant
				sig = stack[--stackn];
				continue;
			}
			goto success;

		case TYPE_BYTE:
			next++;
			break;

		case TYPE_INT16:
		case TYPE_UINT16:
			next = ALIGN_UINT_UP(next, 2) + 2;
			break;

		case TYPE_BOOL:
		case TYPE_INT32:
		case TYPE_UINT32:
			next = ALIGN_UINT_UP(next, 4) + 4;
			break;

		case TYPE_INT64:
		case TYPE_UINT64:
		case TYPE_DOUBLE:
			next = ALIGN_UINT_UP(next, 8) + 8;
			break;

		case TYPE_STRING:
		case TYPE_PATH: {
			next = ALIGN_UINT_UP(next, 4) + 4;
			if (next > end) {
				goto error;
			}
			uint32_t len = read_native_4(base + next - 4);
			next += len + 1;
			break;
		}

		case TYPE_SIGNATURE: {
			if (next == end) {
				goto error;
			}
			uint8_t len = *(uint8_t *)(base + next);
			next += 1 + len + 1;
			break;
		}

		case TYPE_ARRAY: {
			next = ALIGN_UINT_UP(next, 4) + 4;
			if (next > end) {
				goto error;
			}
			uint32_t len = read_native_4(base + next - 4);
			next = alignx(*sig, base, next, end) + len;
			if (skip_signature(&sig, true)) {
				goto error;
			}
			break;
		}

		case TYPE_STRUCT_BEGIN:
			next = ALIGN_UINT_UP(next, 8);
			break;

		case TYPE_VARIANT: {
			// Need to save the current signature to a stack.
			const char **psig = &stack[stackn++];
			if (psig == stack + sizeof(stack) || next == end) {
				goto error;
			}
			// parse to get the new signature from the data
			slice_t s;
			s.len = *(uint8_t *)(base + next);
			s.p = base + next + 1;
			next += 1 + s.len + 1;
			if (next > end || check_string(s)) {
				goto error;
			}

			// and then push the current signature onto the stack
			*psig = sig;
			sig = s.p;
			break;
		}

		case TYPE_DICT_BEGIN:
			// dict can not exist outside an array
		default:
			goto error;
		}

		if (next > end) {
			goto error;
		}
	}
success:
	ret.end = next;
	p->next = next;
	return ret;
error:
	ret.end = 0;
	ret.next = 1;
	p->next = end + 1;
	return ret;
}

int skip_signature(const char **psig, bool in_array)
{
	char s[32];
	char *p = s;
	char *e = s + sizeof(s) - 1;
	*p = 0;

	if (in_array) {
		*(p++) = TYPE_ARRAY;
		*p = 0;
	}

	for (;;) {
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
			break;

		case TYPE_ARRAY:
			if (p == e) {
				return -1;
			}
			*(p++) = TYPE_ARRAY;
			*p = 0;
			// loop around to consume another item
			continue;

		case TYPE_DICT_BEGIN:
			if (p == s || p[-1] != TYPE_ARRAY) {
				return -1;
			}
			// transform the array into a dict
			p[-1] = TYPE_DICT;
			break;

		case TYPE_STRUCT_BEGIN:
			if (p == e) {
				return -1;
			}
			*(p++) = TYPE_STRUCT;
			*p = 0;
			break;

		case TYPE_STRUCT_END:
			if (p == s || p[-1] != TYPE_STRUCT) {
				return -1;
			}
			*(--p) = 0;
			break;

		case TYPE_DICT_END:
			if (p == s || p[-1] != TYPE_DICT_END) {
				return -1;
			}
			*(--p) = 0;
			break;
		default:
			(*psig)--;
			return -1;
		}

		if (p > s) {
			switch (p[-1]) {
			case TYPE_ARRAY:
				// We've consumed the array data and it was not
				// a dict. Otherwise the type code would have
				// been changed.
				*(--p) = 0;
				break;

			case TYPE_DICT:
				// we've consumed one item in the dict
				p[-1] = TYPE_DICT_BEGIN;
				break;

			case TYPE_DICT_BEGIN:
				// we've consumed both items in the dict
				p[-1] = TYPE_DICT_END;
				break;

			case TYPE_DICT_END:
				// we expected a closing brace but didn't get
				// one
				return -1;
			}
		}

		if (p == s) {
			// we've consumed an item and have nothing on the stack
			return 0;
		}
	}
}

#ifndef NDEBUG
void TEST_parse()
{
	fprintf(stderr, "TEST_parse\n");
	struct iterator p;
	static const alignas(8) uint8_t test1[] = {
		1, // byte
		0, 2, 0, // u16
		3, 0, 0, 0, // u32
	};
	init_iterator(&p, "yqu", test1, 0, sizeof(test1));
	assert(parse_byte(&p) == 1 && !iter_error(&p));
	assert(parse_uint16(&p) == 2 && !iter_error(&p));
	assert(parse_uint32(&p) == 3 && !iter_error(&p));
	assert(parse_byte(&p) == 0 && iter_error(&p));
}
#endif
