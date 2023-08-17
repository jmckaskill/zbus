#include "zbus.h"

#define ZB_ALIGN_UP(VAL, BOUNDARY) \
	(((VAL) + (BOUNDARY - 1)) & (~(BOUNDARY - 1)))

#define FTAG_PATH UINT32_C(0x006F0101) // BYTE: 01 SIG: "o"
#define FTAG_INTERFACE UINT32_C(0x00730102) // BYTE: 02 SIG: "s"
#define FTAG_MEMBER UINT32_C(0x00730103) // BYTE: 03 SIG: "s"
#define FTAG_ERROR_NAME UINT32_C(0x00730104) // BYTE: 04 SIG: "s"
#define FTAG_REPLY_SERIAL UINT32_C(0x00750105) // BYTE: 05 SIG: "u"
#define FTAG_DESTINATION UINT32_C(0x00730106) // BYTE: 06 SIG: "s"
#define FTAG_SENDER UINT32_C(0x00730107) // BYTE: 07 SIG: "s"
#define FTAG_SIGNATURE UINT32_C(0x00670108) // BYTE: 08 SIG: "g"
#define FTAG_UNIX_FDS UINT32_C(0x00750109) // BYTE: 09 SIG: "u"

#define DBUS_VERSION 1

#define MAX_DEPTH 32

struct raw_header {
	uint8_t endian;
	uint8_t type;
	uint8_t flags;
	uint8_t version;
	uint8_t body_len[4];
	uint8_t serial[4];
	uint8_t field_len[4];
};

ZB_INLINE uint8_t native_endian(void)
{
	union test {
		uint16_t u;
		uint8_t b[2];
	} test;
	test.u = 0x426C; // "Bl"
	return test.b[0];
}

/////////////////////////////////////////
// Authentication

static char *append(char *out, char *end, const void *str, size_t len)
{
	if (out + len > end) {
		return end + 1;
	}
	memcpy(out, str, len);
	return out + len;
}

static char *append_hex(char *out, char *end, const uint8_t *data, size_t sz)
{
	static const char hexdigits[] = "0123456789abcdef";
	if (out + (sz * 2) > end) {
		return end + 1;
	}
	for (size_t i = 0; i < sz; i++) {
		*(out++) = hexdigits[data[i] >> 4];
		*(out++) = hexdigits[data[i] & 15];
	}
	return out;
}

static const char hello[] = "\0\x01\0\x01\0\0\0\0" // hdr & body len
			    "\0\0\0\0\0\0\0\0" // serial & field len
			    "\x01\x01o\0\0\0\0\0" // path
			    "/org/fre"
			    "edesktop"
			    "/DBus\0\0\0"
			    "\x02\x01s\0\0\0\0\0" // interface
			    "org.free"
			    "desktop."
			    "DBus\0\0\0\0"
			    "\x03\01s\0\0\0\0\0" // member
			    "Hello\0\0\0"
			    "\x06\x01s\0\0\0\0\0" // destination
			    "org.free"
			    "desktop."
			    "DBus\0\0\0\0";

static_assert(sizeof(hello) - 1 == 128, "");

ZB_INLINE void write32(void *p, uint32_t u)
{
	memcpy(p, &u, 4);
}

int zb_write_auth_external(char *buf, size_t bufsz, const char *uid,
			   uint32_t serial)
{
	char *out = buf;
	char *end = buf + bufsz;
	out = append(out, end, "\0", 1);
	out = append(out, end, "AUTH EXTERNAL ", strlen("AUTH EXTERNAL "));
	out = append_hex(out, end, (uint8_t *)uid, strlen(uid));
	out = append(out, end, "\r\nBEGIN\r\n", strlen("\r\nBEGIN\r\n"));
	char *msg = out;
	out = append(out, end, hello, sizeof(hello) - 1);

	if (out > end) {
		return -1;
	}

	msg[0] = native_endian();
	zb_set_serial(msg, serial);
	write32(msg + 12, 128 - 16 /*raw header*/ - 3 /*end padding*/);
	write32(msg + 20, 21); // path len
	write32(msg + 52, 20); // interface len
	write32(msg + 84, 5); // member len
	write32(msg + 100, 20); // destination len

	return (int)(out - buf);
}

int zb_decode_auth_reply(char *buf, size_t sz)
{
	if (sz < strlen("OK ")) {
		return 0;
	}

	char *nl = memchr(buf, '\n', sz);
	if (!nl) {
		return 0;
	}

	// ignore bus id for now
	if (strncmp(buf, "OK ", 3)) {
		return -1;
	}

	return (int)(nl - buf);
}

////////////////////////////////////////
// String Checking

int zb_check_path(const char *s, size_t len)
{
	if (!len || len > 255 || *s != '/') {
		// path must begin with / and can not be the empty string
		return -1;
	}
	if (len == 1) {
		// trailing / only allowed if the path is "/"
		return 0;
	}
	const char *p = s + 1;
	const char *end = s + len;
	const char *segment = p;
	while (p < end) {
		// only [A-Z][a-z][0-9]_ are allowed
		// / and \0 are not allowed as the first char of a segment
		// this rejects multiple / in sequence and a trailing /
		// respectively
		if (('A' <= *p && *p <= 'Z') || ('a' <= *p && *p <= 'z') ||
		    ('0' <= *p && *p <= '9') || *p == '_') {
			p++;
		} else if (p > segment && *p == '/') {
			segment = ++p;
		} else {
			return -1;
		}
	}

	// trailing / not allowed
	return p == segment;
}

int zb_check_member(const char *s, size_t len)
{
	if (!len || len > 255) {
		return -1;
	}
	const char *p = s;
	const char *begin = p;
	const char *end = p + len;
	while (p < end) {
		// must be composed of [A-Z][a-z][0-9]_ and must not start with
		// a digit
		if (('A' <= *p && *p <= 'Z') || ('a' <= *p && *p <= 'z') ||
		    *p == '_' || (p > begin && '0' <= *p && *p <= '9')) {
			p++;
		} else {
			return -1;
		}
	}
	return 0;
}

int zb_check_interface(const char *s, size_t len)
{
	if (len > 255) {
		return -1;
	}
	int have_dot = 0;
	const char *p = s;
	const char *segment = s;
	const char *end = s + len;
	while (p < end) {
		// must be composed of [A-Z][a-z][0-9]_ and must not start with
		// a digit segments can not be zero length ie no two dots in a
		// row nor a leading dot the name as a whole must comprise at
		// least two segments ie have a dot and must not be longer than
		// the requested size
		if (('A' <= *p && *p <= 'Z') || ('a' <= *p && *p <= 'z') ||
		    *p == '_' || (p > segment && '0' <= *p && *p <= '9')) {
			p++;
		} else if (p > segment && *p == '.') {
			segment = ++p;
			have_dot = 1;
		} else {
			return -1;
		}
	}

	return p == segment || !have_dot;
}

int zb_check_unique_address(const char *s, size_t len)
{
	if (!len || *s != ':' || len > 255) {
		return -1;
	}
	const char *p = s + 1;
	const char *end = s + len;
	int have_dot = 0;
	const char *segment = p;
	while (p < end) {
		// must start with a :
		// must be composed of at least two segments separated by a dot
		// segments must be composed of [A-Z][a-z][0-9]_
		// segments can not be zero length
		if (('A' <= *p && *p <= 'Z') || ('a' <= *p && *p <= 'z') ||
		    *p == '_' || ('0' <= *p && *p <= '9')) {
			p++;
		} else if (p > segment && *p == '.') {
			segment = ++p;
			have_dot = 1;
		} else {
			return -1;
		}
	}

	return p == segment || !have_dot;
}

int zb_check_address(const char *s, size_t len)
{
	return zb_check_unique_address(s, len) &&
	       zb_check_known_address(s, len);
}

/////////////////////////////////////////////
// Argument Decoding

ZB_INLINE int_fast32_t align_iter2(char *base, int_fast32_t off,
				   int_fast32_t error)
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

ZB_INLINE int_fast32_t align_iter4(char *base, int_fast32_t off,
				   int_fast32_t error)
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

ZB_INLINE int_fast32_t align_iter8(char *base, int_fast32_t off,
				   int_fast32_t error)
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

static int_fast32_t align_iter(char type, char *base, int_fast32_t off,
			       int_fast32_t error)
{
	switch (type) {
	case ZB_BYTE:
	case ZB_SIGNATURE:
	case ZB_VARIANT:
		return off;
	case ZB_INT16:
	case ZB_UINT16:
		return align_iter2(base, off, error);
	case ZB_BOOL:
	case ZB_INT32:
	case ZB_UINT32:
	case ZB_STRING:
	case ZB_PATH:
	case ZB_ARRAY:
		return align_iter4(base, off, error);
	case ZB_INT64:
	case ZB_UINT64:
	case ZB_DOUBLE:
	case ZB_DICT:
	case ZB_STRUCT:
		return align_iter8(base, off, error);
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
	int_fast32_t n = align_iter2(p->base, p->next, p->end);
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
	int_fast32_t n = align_iter4(p->base, p->next, p->end);
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
	int_fast32_t n = align_iter8(p->base, p->next, p->end);
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
	int_fast32_t n = align_iter4(p->base, p->next, p->end);
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
	int_fast32_t start = align_iter(*p->nextsig, p->base, p->next, p->end);
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
	int_fast32_t n = align_iter8(p->base, p->next, p->end);
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
			p->next = align_iter(*p->nextsig, p->base, p->next,
					     p->end) +
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
// Message Decoding

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
	int_fast32_t n = align_iter8(ii->base, ii->next, ii->end);

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

/////////////////////////////////
// Builder Alignment

static int_fast32_t align_build2(char *base, int_fast32_t off)
{
	int_fast32_t mod = off & 1U;
	if (!mod) {
		return off;
	}
	base[off] = 0;
	return off + 1;
}

static int_fast32_t align_build4(char *base, int_fast32_t off)
{
	int_fast32_t aligned = ZB_ALIGN_UP(off, 4);
	while (off < aligned) {
		base[off++] = 0;
	}
	return off;
}

static int_fast32_t align_build8(char *base, int_fast32_t off)
{
	int_fast32_t aligned = ZB_ALIGN_UP(off, 8);
	while (off < aligned) {
		base[off++] = 0;
	}
	return off;
}

static int_fast32_t align_buildx(char *base, int_fast32_t off, char type)
{
	switch (type) {
	case ZB_INT16:
	case ZB_UINT16:
		return align_build2(base, off);
	case ZB_BOOL:
	case ZB_INT32:
	case ZB_UINT32:
	case ZB_STRING:
	case ZB_PATH:
	case ZB_ARRAY:
		return align_build4(base, off);
	case ZB_INT64:
	case ZB_UINT64:
	case ZB_DOUBLE:
	case ZB_DICT_BEGIN:
	case ZB_STRUCT_BEGIN:
		return align_build8(base, off);
	case ZB_BYTE:
	case ZB_SIGNATURE:
	case ZB_VARIANT:
	default:
		return off;
	}
}

///////////////////////////////
// Argument Encoding

void zb_add_raw(struct zb_builder *b, const char *sig, const void *p,
		size_t len)
{
	assert(len < ZB_MAX_MSG_SIZE);
	int_fast32_t off = align_buildx(b->base, b->next, *sig);
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
	int_fast32_t off = align_build2(b->base, b->next);
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
	int_fast32_t off = align_build4(b->base, b->next);
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
	int_fast32_t off = align_build8(b->base, b->next);
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
	int_fast32_t lenoff = align_build4(b->base, b->next);
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
	int_fast32_t lenoff = align_build4(b->base, b->next);
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
		b->next = align_build8(b->base, b->next);
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
	int_fast32_t lenoff = align_build4(b->base, b->next);
	b->next = align_buildx(b->base, lenoff + 4, sig[1]);
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

	int_fast32_t lenoff = align_build4(b->base, b->next);
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
// Message Encoding

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

static int_fast32_t add_uint32_field(struct zb_builder *b, uint32_t tag,
				     uint32_t v)
{
	assert(!(b->next & 7));
	int_fast32_t tagoff = b->next;
	int_fast32_t valoff = tagoff + 4;
	b->next = valoff + 4;
	if (b->next <= b->end) {
		write_little_4(b->base + tagoff, tag);
		memcpy(b->base + valoff, &v, 4);
	}
	return b->next;
}

static int_fast32_t add_string_field(struct zb_builder *b, uint32_t tag,
				     const zb_str8 *str)
{
	assert(!(b->next & 7));
	int_fast32_t tagoff = b->next;
	int_fast32_t lenoff = tagoff + 4;
	int_fast32_t stroff = lenoff + 4;
	int_fast32_t padoff = stroff + str->len + 1;
	b->next = ZB_ALIGN_UP(padoff, 8);
	if (b->next <= b->end) {
		uint32_t len32 = str->len;
		write_little_4(b->base + tagoff, tag);
		memcpy(b->base + lenoff, &len32, 4);
		memcpy(b->base + stroff, str->p, str->len + 1);
		memset(b->base + padoff, 0, b->next - padoff);
	}
	return padoff;
}

static int_fast32_t add_signature_field(struct zb_builder *b, uint32_t tag,
					const char *sig)
{
	assert(!(b->next & 7));
	size_t len = strlen(sig);
	if (len > 255) {
		b->next = b->end + 1;
		return b->next;
	}
	int_fast32_t tagoff = b->next;
	int_fast32_t lenoff = tagoff + 4;
	int_fast32_t stroff = lenoff + 1;
	int_fast32_t padoff = stroff + (uint8_t)len + 1;
	b->next = ZB_ALIGN_UP(padoff, 8);
	if (b->next <= b->end) {
		write_little_4(b->base + tagoff, tag);
		*(uint8_t *)(b->base + lenoff) = (uint8_t)len;
		memcpy(b->base + stroff, sig, len + 1);
		memset(b->base + padoff, 0, b->next - padoff);
	}
	return padoff;
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
	// type and variant signature in one go. These functions leave the
	// buffer 8 byte aligned but return the actual data end for the field
	// array size.

	int_fast32_t fend = b->next;
	if (m->reply_serial) {
		fend = add_uint32_field(b, FTAG_REPLY_SERIAL, m->reply_serial);
	}
	if (m->fdnum) {
		fend = add_uint32_field(b, FTAG_UNIX_FDS, m->fdnum);
	}
	if (*m->signature) {
		fend = add_signature_field(b, FTAG_SIGNATURE, m->signature);
	}
	if (m->path) {
		fend = add_string_field(b, FTAG_PATH, m->path);
	}
	if (m->interface) {
		fend = add_string_field(b, FTAG_INTERFACE, m->interface);
	}
	if (m->member) {
		fend = add_string_field(b, FTAG_MEMBER, m->member);
	}
	if (m->error) {
		fend = add_string_field(b, FTAG_ERROR_NAME, m->error);
	}
	if (m->destination) {
		fend = add_string_field(b, FTAG_DESTINATION, m->destination);
	}
	if (m->sender) {
		fend = add_string_field(b, FTAG_SENDER, m->sender);
	}

	struct raw_header *h = (struct raw_header *)(b->base + start);
	h->endian = native_endian();
	h->type = m->type;
	h->flags = m->flags;
	h->version = DBUS_VERSION;
	uint32_t serial = m->serial;
	uint32_t flen32 = (uint32_t)(fend - start - sizeof(*h));
	uint32_t blen32 = (uint32_t)blen;
	memcpy(h->serial, &serial, 4);
	memcpy(h->body_len, &blen32, 4);
	memcpy(h->field_len, &flen32, 4);

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

////////////////////////////////////////
// Receive Stream

void zb_init_stream(struct zb_stream *s, size_t msgsz, size_t hdrsz)
{
	assert((msgsz & (msgsz - 1)) == 0);
	assert(hdrsz >= ZB_MIN_MSG_SIZE);

	s->cap = msgsz;
	s->defrag = hdrsz;
	s->have = 0;
	s->used = 0;
}

void zb_get_stream_recvbuf(struct zb_stream *s, char **p1, size_t *n1,
			   char **p2, size_t *n2)
{
	// shouldn't be possible to overflow the buffer
	assert(s->have <= s->used + s->cap);

	// Cases (+ = unparsed data, - = buffer room to fill)
	// 1. used > have - skipping data
	// 2. used == have - empty buffer - |-----EB---|
	// 3. begin < end - good data in one section - |--B++++E---|
	// 4. begin > end - good data in two sections - |++E---B++|
	// 5. begin == end - full buffer - |+++EB++++|

	size_t cap = s->cap;
	size_t mask = s->cap - 1;
	size_t used = s->used;
	size_t have = s->have;
	size_t begin = used & mask;
	size_t end = have & mask;

	if (have < used) {
		// 1. used > have - skipping data
		// Read full buffer lengths up until used == have. We'll then
		// fall in to case #2 and reset the offsets.
		*p1 = s->buf;
		*n1 = used - have;
		if (*n1 > cap) {
			*n1 = cap;
		}
		*n2 = 0;
	} else if (have == used) {
		// 2. used == have - empty buffer - |-----EB---|
		// Reset the offsets to reduce fragementation.
		s->used = 0;
		s->have = 0;
		*p1 = s->buf;
		*n1 = cap;
		*n2 = 0;
	} else if (begin < end) {
		// 3. begin < end - good data in one section - |--B++++E---|
		*p1 = s->buf + end;
		*n1 = cap - end;
		*p2 = s->buf;
		*n2 = begin;
	} else {
		// 4. begin > end - good data in two sections - |++E---B++|
		// 5. begin == end - full buffer - |+++EB++++|
		*p1 = s->buf + end;
		*n1 = begin - end;
		*n2 = 0;
	}
}

int zb_read_auth(struct zb_stream *s)
{
	assert(!s->used);
	int rd = zb_decode_auth_reply(s->buf, s->have);
	if (!rd && s->have == s->cap) {
		return -1;
	} else if (rd <= 0) {
		return rd;
	}
	s->used += rd;
	return 1;
}

int zb_read_message(struct zb_stream *s, struct zb_message *msg)
{
	for (;;) {
		size_t used = s->used;
		size_t have = s->have;

		if (used + ZB_MIN_MSG_SIZE > have) {
			return 0;
		}

		size_t cap = s->cap;
		size_t mask = s->cap - 1;
		size_t begin = s->used & mask;
		size_t end = s->have & mask;

		// defragment the fixed header
		char *buf = s->buf;
		char *hdr = buf + begin;
		if (begin + ZB_MIN_MSG_SIZE > cap) {
			size_t n = (begin + ZB_MIN_MSG_SIZE) & mask;
			memcpy(buf + cap, buf, n);
		}

		// parse the fixed header
		size_t hsz, bsz;
		if (zb_parse_size(hdr, &hsz, &bsz)) {
			return -1;
		}
		size_t msz = hsz + bsz;
		if (msz > cap || hsz > s->defrag) {
			// message is too long, will need to skip it
			s->used += msz;
			continue;
		}
		if (used + msz > have) {
			return 0;
		}

		// defragment the rest of the header
		if (begin + hsz > cap) {
			size_t n = (begin + hsz) & mask;
			memcpy(buf + cap, buf, n);
		}

		// parse the full header
		if (zb_parse_header(msg, hdr)) {
			// drop the message and continue
			s->used += msz;
			continue;
		}

		// find the body
		begin = (used + hsz) & mask;
		end = (used + msz) & mask;
		s->body = buf + begin;
		s->used += msz;

		if (begin <= end) {
			/* |  B+++E  | */
			s->bsz[0] = bsz;
			s->bsz[1] = 0;
		} else {
			/* |++E    B++| */
			s->bsz[0] = cap - begin;
			s->bsz[1] = end;
		}

		return 1;
	}
}

int zb_defragment_body(struct zb_stream *s, struct zb_message *msg,
		       struct zb_iterator *ii)
{
	if (s->bsz[0] + s->bsz[1] > s->defrag) {
		return -1;
	}
	if (s->bsz[1]) {
		// Second part should be at the beginning of the buffer.
		// We're going to copy it to the end in the defrag portion.
		memcpy(s->buf + s->cap, s->buf, s->bsz[1]);
	}
	zb_init_iterator(ii, msg->signature, s->body, s->bsz[0] + s->bsz[1]);
	return 0;
}
