#include "internal.h"

#define MAX_DEPTH 32

ZB_INLINE int_fast32_t align2(char *base, int_fast32_t off, int_fast32_t error)
{
	int_fast32_t aligned = ZB_ALIGN_UP(off, 2);
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

ZB_INLINE int_fast32_t align4(char *base, int_fast32_t off, int_fast32_t error)
{
	int_fast32_t aligned = ZB_ALIGN_UP(off, 4);
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

ZB_INLINE int_fast32_t align8(char *base, int_fast32_t off, int_fast32_t error)
{
	int_fast32_t aligned = ZB_ALIGN_UP(off, 8);
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

static int_fast32_t alignx(char type, char *base, int_fast32_t off,
			   int_fast32_t error)
{
	switch (type) {
	case ZB_BYTE:
	case ZB_SIGNATURE:
	case ZB_VARIANT:
		return off;
	case ZB_INT16:
	case ZB_UINT16:
		return align2(base, off, error);
	case ZB_BOOL:
	case ZB_INT32:
	case ZB_UINT32:
	case ZB_STRING:
	case ZB_PATH:
	case ZB_ARRAY:
		return align4(base, off, error);
	case ZB_INT64:
	case ZB_UINT64:
	case ZB_DOUBLE:
	case ZB_DICT:
	case ZB_STRUCT:
		return align8(base, off, error);
	default:
		return error;
	}
}

static uint8_t parse1(struct zb_iterator *p, char type)
{
	int_fast32_t n = p->next;
	if (n >= p->end || *p->nextsig != type) {
		p->next = p->end + 1;
		return 0;
	}
	p->next++;
	p->nextsig++;
	return *(uint8_t *)(p->base + n);
}

static uint16_t parse2(struct zb_iterator *p, char type)
{
	int_fast32_t n = align2(p->base, p->next, p->end);
	if (n + 2 > p->end || *p->nextsig != type) {
		p->next = p->end + 1;
		return 0;
	}
	uint16_t ret;
	memcpy(&ret, p->base + n, 2);
	p->next = n + 2;
	p->nextsig++;
	return ret;
}

static uint32_t parse4(struct zb_iterator *p, char type)
{
	int_fast32_t n = align4(p->base, p->next, p->end);
	if (n + 4 > p->end || *p->nextsig != type) {
		p->next = p->end + 1;
		return 0;
	}
	uint32_t ret;
	memcpy(&ret, p->base + n, 4);
	p->next = n + 4;
	p->nextsig++;
	return ret;
}

static uint64_t parse8(struct zb_iterator *p, char type)
{
	int_fast32_t n = align8(p->base, p->next, p->end);
	if (n + 8 > p->end || *p->nextsig != type) {
		p->next = p->end + 1;
		return 0;
	}
	uint64_t ret;
	memcpy(&ret, p->base + n, 4);
	p->next = n + 8;
	p->nextsig++;
	return ret;
}

uint8_t zb_parse_byte(struct zb_iterator *p)
{
	return parse1(p, ZB_BYTE);
}

int16_t zb_parse_i16(struct zb_iterator *p)
{
	return (int16_t)parse2(p, ZB_INT16);
}

uint16_t zb_parse_u16(struct zb_iterator *p)
{
	return parse2(p, ZB_UINT16);
}

int32_t zb_parse_i32(struct zb_iterator *p)
{
	return (int32_t)parse4(p, ZB_INT32);
}

uint32_t zb_parse_u32(struct zb_iterator *p)
{
	return parse4(p, ZB_UINT32);
}

bool zb_parse_bool(struct zb_iterator *p)
{
	uint32_t u = parse4(p, ZB_UINT32);
	if (u > 1) {
		p->next = p->end + 1;
	}
	return u != 0;
}

int64_t zb_parse_i64(struct zb_iterator *p)
{
	return (int64_t)parse8(p, ZB_INT64);
}

uint64_t zb_parse_u64(struct zb_iterator *p)
{
	return parse8(p, ZB_UINT64);
}

double zb_parse_double(struct zb_iterator *p)
{
	union {
		double d;
		uint64_t u;
	} u;
	u.u = parse8(p, ZB_DOUBLE);
	return u.d;
}

static char *parse_string_bytes(struct zb_iterator *p, uint32_t len)
{
	char *ret = p->base + p->next;
	int_fast32_t n = p->next + len + 1;
	if (len > ZB_MAX_VALUE_SIZE || n > p->end || ret[len]) {
		p->next = p->end + 1;
		return NULL;
	}
	p->next = n;
	return ret;
}

static const char *parse_signature_no_sig_check(struct zb_iterator *ii)
{
	if (ii->next >= ii->end) {
		return "";
	}
	char *plen = ii->base + ii->next++;
	char *ret = plen + 1;
	uint8_t len = *(uint8_t *)plen;
	ii->next += len + 1;
	if (ii->next > ii->end || ret[len] || memchr(ret, 0, len)) {
		ii->next = ii->end + 1;
		return "";
	}
	return ret;
}

const char *zb_parse_signature(struct zb_iterator *p)
{
	if (*p->nextsig != ZB_SIGNATURE) {
		p->next = p->end + 1;
		return "";
	}
	p->nextsig++;
	return parse_signature_no_sig_check(p);
}

char *zb_parse_string(struct zb_iterator *p, size_t *psz)
{
	uint32_t len = parse4(p, ZB_STRING);
	*psz = len;
	return parse_string_bytes(p, len);
}

char *zb_parse_path(struct zb_iterator *p, size_t *psz)
{
	uint32_t len = parse4(p, ZB_PATH);
	*psz = len;
	return parse_string_bytes(p, len);
}

static zb_str8 *parse_str8_no_sig_check(struct zb_iterator *p,
					int_fast32_t aligned)
{
	assert(!(aligned & 3U));
	char *plen = p->base + aligned;
	if (aligned + 5 > p->end) {
		goto error;
	}
	uint32_t len;
	memcpy(&len, plen, 4);
	zb_str8 *s = (zb_str8 *)(plen + 3);
	int_fast32_t next = aligned + 4 + len + 1;
	if (len > UINT8_MAX || next > p->end || p->base[next - 1]) {
		goto error;
	}
#if !defined __BYTE_ORDER__ || __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
	s->len = (uint8_t)len;
#endif
	p->next = next;
	return s;
error:
	p->next = p->end + 1;
	return NULL;
}

const zb_str8 *zb_parse_str8(struct zb_iterator *p)
{
	if (*p->nextsig != ZB_STRING) {
		p->next = p->end + 1;
		return NULL;
	}
	p->nextsig++;
	int_fast32_t n = align4(p->base, p->next, p->end);
	return parse_str8_no_sig_check(p, n);
}

void zb_parse_variant(struct zb_iterator *p, struct zb_variant *pv)
{
	uint8_t len = parse1(p, ZB_VARIANT);
	char *sig = parse_string_bytes(p, len);

	pv->sig = sig;

	const char *nextsig = p->nextsig;
	p->nextsig = sig;

	char type = *p->nextsig;
	switch (type) {
	case ZB_BYTE:
		pv->u.u8 = zb_parse_byte(p);
		break;
	case ZB_INT16:
	case ZB_UINT16:
		pv->u.u16 = parse2(p, type);
		break;
	case ZB_BOOL:
		pv->u.b = zb_parse_bool(p);
		break;
	case ZB_INT32:
	case ZB_UINT32:
		pv->u.u32 = parse4(p, type);
		break;
	case ZB_INT64:
	case ZB_UINT64:
	case ZB_DOUBLE:
		pv->u.u64 = parse8(p, type);
		break;
	case ZB_STRING:
		pv->u.str.p = zb_parse_string(p, &pv->u.str.len);
		break;
	case ZB_PATH:
		pv->u.path.p = zb_parse_path(p, &pv->u.path.len);
		break;
	case ZB_SIGNATURE:
		pv->u.sig = zb_parse_signature(p);
		break;
	case ZB_VARIANT:
	case ZB_STRUCT_BEGIN:
	case ZB_ARRAY:
		zb_skip(p, &pv->u.record);
		break;
	case ZB_DICT_BEGIN:
		// Can only occur as an array element. So there is never a need
		// to skip just a dict entry.
	default:
		p->end = p->next + 1;
		break;
	}

	if (zb_get_iter_error(p)) {
		pv->sig = "";
	}

	p->nextsig = nextsig;
}

struct iter_array {
	const char *sig_start;
	int_fast32_t prev_end;
	uint8_t siglen;
	uint8_t first_entry;
};

static_assert(sizeof(struct iter_array) <= sizeof(struct zb_scope), "");

void zb_enter_array(struct zb_iterator *p, struct zb_scope *s)
{
	struct iter_array *a = (void *)s;
	uint32_t len = parse4(p, ZB_ARRAY);
	int_fast32_t start = alignx(*p->nextsig, p->base, p->next, p->end);
	int_fast32_t end = start + len;

	// step back so that zb_skip_signature can pick up that we're in an
	// array
	const char *nextsig = p->nextsig - 1;

	if (len > ZB_MAX_VALUE_SIZE || end > p->end ||
	    zb_skip_signature(&nextsig)) {
		zb_set_iter_error(p);
	} else {
		a->sig_start = p->nextsig;
		a->siglen = (uint8_t)(nextsig - a->sig_start);
		a->prev_end = p->end;
		a->first_entry = 1;
		p->next = start;
		p->end = end;
	}
}

void zb_exit_array(struct zb_iterator *p, struct zb_scope *s)
{
	struct iter_array *a = (void *)s;
	if (!zb_get_iter_error(p)) {
		p->nextsig = a->sig_start + a->siglen;
		p->next = p->end;
		p->end = a->prev_end;
	}
}

bool zb_array_has_more(struct zb_iterator *p, struct zb_scope *s)
{
	struct iter_array *a = (void *)s;
	if (zb_get_iter_error(p)) {
		return false;
	}

	const char *sigstart = a->sig_start;
	const char *sigend = a->sig_start + a->siglen;

	// check that the signature is where we expect it to be
	if (p->nextsig != (a->first_entry ? sigstart : sigend)) {
		zb_set_iter_error(p);
		return false;
	}

	if (p->next == p->end) {
		// We've reached the end of the array. Update the iterator to
		// the next item after the array
		p->nextsig = sigend;
		p->next = p->end;
		p->end = a->prev_end;
		return false;
	} else {
		// There are further items
		p->nextsig = sigstart;
		a->first_entry = 0;
		return true;
	}
}

static void _parse_struct(struct zb_iterator *p, char type)
{
	int_fast32_t n = align8(p->base, p->next, p->end);
	if (n > p->end || *p->nextsig != type) {
		p->next = p->end + 1;
	} else {
		p->nextsig++;
		p->next = n;
	}
}

void zb_enter_struct(struct zb_iterator *p)
{
	_parse_struct(p, ZB_STRUCT_BEGIN);
}

void zb_enter_dict_entry(struct zb_iterator *p)
{
	_parse_struct(p, ZB_DICT_BEGIN);
}

void zb_exit_dict_entry(struct zb_iterator *p)
{
	if (*p->nextsig == ZB_DICT_END) {
		p->nextsig++;
	} else {
		p->next = p->end + 1;
	}
}

void zb_exit_struct(struct zb_iterator *p)
{
	for (;;) {
		if (zb_get_iter_error(p)) {
			return;
		} else if (*p->nextsig == ZB_STRUCT_END) {
			p->nextsig++;
			return;
		}
		zb_skip(p, NULL);
	}
}

void zb_skip(struct zb_iterator *p, struct zb_iterator *pval)
{
	const char *stack[MAX_DEPTH];
	int stackn = 0;

	if (!*p->nextsig) {
		goto error;
	}

	if (pval) {
		pval->base = p->base;
		pval->next = p->next;
		pval->nextsig = p->nextsig;
	}

	for (;;) {
		switch (*(p->nextsig++)) {
		case '\0':
			if (stackn) {
				// we've reached the end of the variant
				p->nextsig = stack[--stackn];
				continue;
			}
			goto success;

		case ZB_BYTE:
			p->next++;
			break;

		case ZB_INT16:
		case ZB_UINT16:
			p->next = ZB_ALIGN_UP(p->next, 2) + 2;
			break;

		case ZB_BOOL:
		case ZB_INT32:
		case ZB_UINT32:
			p->next = ZB_ALIGN_UP(p->next, 4) + 4;
			break;

		case ZB_INT64:
		case ZB_UINT64:
		case ZB_DOUBLE:
			p->next = ZB_ALIGN_UP(p->next, 8) + 8;
			break;

		case ZB_STRING:
		case ZB_PATH: {
			p->next = ZB_ALIGN_UP(p->next, 4) + 4;
			if (p->next > p->end) {
				goto error;
			}
			uint32_t len;
			memcpy(&len, p->base + p->next - 4, 4);
			if (len > ZB_MAX_VALUE_SIZE) {
				// protect against overflow
				goto error;
			}
			p->next += len + 1;
			break;
		}

		case ZB_SIGNATURE: {
			if (p->next == p->end) {
				goto error;
			}
			uint8_t len = *(uint8_t *)(p->base + p->next);
			p->next += 1 + len + 1;
			break;
		}

		case ZB_ARRAY: {
			p->next = ZB_ALIGN_UP(p->next, 4) + 4;
			if (p->next > p->end) {
				goto error;
			}
			uint32_t len;
			memcpy(&len, p->base + p->next - 4, 4);
			if (len > ZB_MAX_VALUE_SIZE) {
				// protect against overflow
				goto error;
			}
			p->next =
				alignx(*p->nextsig, p->base, p->next, p->end) +
				len;
			// step back so that zb_skip_signature knows
			// we're in an array
			p->nextsig--;
			if (zb_skip_signature(&p->nextsig)) {
				goto error;
			}
			break;
		}

		case ZB_STRUCT_BEGIN:
			p->next = ZB_ALIGN_UP(p->next, 8);
			break;

		case ZB_VARIANT: {
			// Need to save the current signature to a
			// stack.
			const char **psig = &stack[stackn++];
			if (psig == stack + sizeof(stack) / sizeof(stack[0])) {
				goto error;
			}
			*psig = p->nextsig;
			p->nextsig = parse_signature_no_sig_check(p);
			break;
		}

		case ZB_DICT_BEGIN:
			// dict can not exist outside an array
		default:
			goto error;
		}

		if (p->next > p->end) {
			goto error;
		}
	}
success:
	if (pval) {
		pval->end = p->next;
	}
	return;
error:
	if (pval) {
		pval->end = 0;
		pval->next = 1;
	}
	p->next = p->end + 1;
}

int zb_skip_signature(const char **psig)
{
	int d = 0; // current stack entry index
	char s[32]; // type code stack

	s[d] = 0;

	for (;;) {
		switch (*((*psig)++)) {
		case ZB_BYTE:
		case ZB_BOOL:
		case ZB_INT16:
		case ZB_UINT16:
		case ZB_INT32:
		case ZB_UINT32:
		case ZB_INT64:
		case ZB_UINT64:
		case ZB_DOUBLE:
		case ZB_STRING:
		case ZB_PATH:
		case ZB_SIGNATURE:
		case ZB_VARIANT:
			break;

		case ZB_ARRAY:
			if (++d == sizeof(s)) {
				return -1;
			}
			s[d] = ZB_ARRAY;
			// loop around to consume another item
			continue;

		case ZB_DICT_BEGIN:
			if (s[d] != ZB_ARRAY) {
				return -1;
			}
			// transform the array into a dict
			s[d] = ZB_DICT;
			break;

		case ZB_STRUCT_BEGIN:
			if (++d == sizeof(s)) {
				return -1;
			}
			s[d] = ZB_STRUCT;
			break;

		case ZB_STRUCT_END:
			if (s[d] != ZB_STRUCT) {
				return -1;
			}
			d--;
			break;

		case ZB_DICT_END:
			if (s[d] != ZB_DICT_END) {
				return -1;
			}
			d--;
			break;
		default:
			// did we go off the end of the string?
			(*psig)--;
			return -1;
		}

		if (d) {
			switch (s[d]) {
			case ZB_ARRAY:
				// We've consumed the array data and it
				// was not a dict. Otherwise the type
				// code would have been changed.
				d--;
				break;

			case ZB_DICT:
				// we've consumed one item in the dict
				s[d] = ZB_DICT_BEGIN;
				break;

			case ZB_DICT_BEGIN:
				// we've consumed both items in the dict
				s[d] = ZB_DICT_END;
				break;

			case ZB_DICT_END:
				// we expected a closing brace but
				// didn't get one
				return -1;
			}
		}

		if (d == 0) {
			// we've consumed an item and have nothing on
			// the stack
			return 0;
		}
	}
}

//////////////////////////////
// Message parsing

void zb_init_message(struct zb_message *m, enum zb_msg_type type,
		     uint32_t serial)
{
	m->path = NULL;
	m->interface = NULL;
	m->member = NULL;
	m->error = NULL;
	m->destination = NULL;
	m->sender = NULL;
	m->signature = "";
	m->fdnum = 0;
	m->reply_serial = 0;
	m->serial = serial;
	m->flags = 0;
	m->type = type;
}

static_assert(sizeof(struct raw_header) == 16, "");

ZB_INLINE uint32_t swap32(uint32_t u32)
{
	union {
		uint32_t u;
		uint8_t b[4];
	} u;
	u.u = u32;
	uint8_t b0 = u.b[0];
	uint8_t b1 = u.b[1];
	u.b[0] = u.b[3];
	u.b[1] = u.b[2];
	u.b[2] = b1;
	u.b[3] = b0;
	return u.u;
}

int zb_parse_size(char *p, size_t *phdr, size_t *pbody)
{
	struct raw_header *h = (struct raw_header *)p;
	if ((h->endian != 'l' && h->endian != 'B') ||
	    h->version != DBUS_VERSION) {
		return -1;
	}
	uint32_t flen, blen;
	memcpy(&flen, &h->field_len, 4);
	memcpy(&blen, &h->body_len, 4);
	if (h->endian != native_endian()) {
		flen = swap32(flen);
		blen = swap32(blen);
	}
	uint32_t fpadded = ZB_ALIGN_UP(flen, 8);
	if (fpadded > ZB_MAX_VALUE_SIZE || blen > ZB_MAX_MSG_SIZE ||
	    fpadded + blen > ZB_MAX_MSG_SIZE) {
		// need to protect against overflows
		return -1;
	}
	*phdr = sizeof(struct raw_header) + (int)fpadded;
	*pbody = blen;
	return 0;
}

ZB_INLINE uint32_t read_little_4(const char *n)
{
#if defined __BYTE_ORDER__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint32_t u;
	memcpy(&u, n, 4);
	return u;
#else
	const uint8_t *u = n;
	return ((uint32_t)u[0]) | (((uint32_t)u[1]) << 8) |
	       (((uint32_t)u[2]) << 16) | (((uint32_t)u[3]) << 24);
#endif
}

static uint32_t parse_uint32_field(struct zb_iterator *ii)
{
	// we should still be aligned from the beginning of this field
	assert((ii->next & 7U) == 4U);
	char *pval = ii->base + ii->next;
	ii->next += 4;
	if (ii->next > ii->end) {
		return 0;
	}
	uint32_t val;
	memcpy(&val, pval, 4);
	return val;
}

static void parse_field(struct zb_message *msg, struct zb_iterator *ii)
{
	int_fast32_t n = align8(ii->base, ii->next, ii->end);

	// Min field size is 5 for a field of type byte: XX 01 'y' 00 YY
	if (n + 5 > ii->end) {
		goto error;
	}

	uint8_t ftype = *(uint8_t *)(ii->base + n);

	if (ftype > ZB_FIELD_LAST) {
		ii->next = n + 1;
		ii->nextsig = "v";
		zb_skip(ii, NULL);
	} else {
		uint32_t ftag = read_little_4(ii->base + n);
		ii->next = n + 4;

		switch (ftag) {
		case FTAG_REPLY_SERIAL:
			msg->reply_serial = parse_uint32_field(ii);
			break;

		case FTAG_UNIX_FDS:
			msg->fdnum = parse_uint32_field(ii);
			break;

		case FTAG_PATH:
			msg->path = parse_str8_no_sig_check(ii, ii->next);
			break;

		case FTAG_INTERFACE:
			msg->interface = parse_str8_no_sig_check(ii, ii->next);
			break;

		case FTAG_MEMBER:
			msg->member = parse_str8_no_sig_check(ii, ii->next);
			break;

		case FTAG_ERROR_NAME:
			msg->error = parse_str8_no_sig_check(ii, ii->next);
			break;

		case FTAG_DESTINATION:
			msg->destination =
				parse_str8_no_sig_check(ii, ii->next);
			break;

		case FTAG_SENDER:
			msg->sender = parse_str8_no_sig_check(ii, ii->next);
			break;

		case FTAG_SIGNATURE:
			msg->signature = parse_signature_no_sig_check(ii);
			break;

		default:
			// unexpected field signature
			goto error;
		}
	}
	return;
error:
	ii->next = ii->end + 1;
}

int zb_parse_header(struct zb_message *msg, char *p)
{
	// h may not be 4 byte aligned so copy the values
	// over
	const struct raw_header *h = (const struct raw_header *)p;
	if (h->endian != native_endian()) {
		return -1;
	}

	uint32_t bsz, fsz, serial;
	memcpy(&bsz, &h->body_len, 4);
	memcpy(&fsz, &h->field_len, 4);
	memcpy(&serial, &h->serial, 4);
	zb_init_message(msg, h->type, serial);
	msg->flags = h->flags;
	msg->serial = serial;

	struct zb_iterator ii;
	zb_init_iterator(&ii, "", (char *)(h + 1), fsz);

	while (ii.next < ii.end) {
		parse_field(msg, &ii);
	}

	if (ii.next > ii.end || !msg->serial) {
		return -1;
	}

	switch (msg->type) {
	case ZB_METHOD:
		return !msg->path || !msg->interface || !msg->member;
	case ZB_SIGNAL:
		return !msg->path || !msg->interface || !msg->member;
	case ZB_REPLY:
		return !msg->reply_serial;
	case ZB_ERROR:
		return !msg->reply_serial || !msg->error;
	default:
		return -1;
	}
}
