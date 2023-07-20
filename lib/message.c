#include "message.h"
#include "multipart.h"
#include <assert.h>
#include <limits.h>
#include <stdlib.h>

struct raw_header {
	uint8_t endian;
	uint8_t type;
	uint8_t flags;
	uint8_t version;
	uint32_t body_len;
	uint32_t serial;
	uint32_t field_len;
};

static_assert(sizeof(struct raw_header) == MIN_MESSAGE_SIZE, "");

union endian_test {
	uint16_t u;
	uint8_t b[2];
};

static const union endian_test g_native_endian = { 0x426C }; // "Bl"

static inline uint8_t native_endian()
{
	return g_native_endian.b[0];
}

int check_member(const char *p)
{
	if (!*p) {
		return -1;
	}
	const char *begin = p;
	while (*p) {
		// must be composed of [A-Z][a-z][0-9]_ and must not start with
		// a digit
		if (('A' <= *p && *p <= 'Z') || ('a' <= *p && *p <= 'z') ||
		    *p == '_' || (p > begin && '0' <= *p && *p <= '9')) {
			p++;
		} else {
			return -1;
		}
	}
	return p - begin > 255;
}

int check_interface(const char *p)
{
	int have_dot = 0;
	const char *begin = p;
	const char *segment = p;
	for (;;) {
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
		} else if (p > segment && have_dot && *p == '\0' &&
			   p - begin <= 255) {
			return 0;
		} else {
			return -1;
		}
	}
}

int check_unique_address(const char *p)
{
	const char *begin = p;
	if (*(p++) != ':') {
		return -1;
	}
	int have_dot = 0;
	const char *segment = p;
	for (;;) {
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
		} else if (p > segment && have_dot && *p == '\0' &&
			   p - begin <= 255) {
			return 0;
		} else {
			return -1;
		}
	}
}

int check_address(const char *p)
{
	return check_unique_address(p) && check_known_address(p);
}

///////////////////////////////////////////////////
// message reading

void init_message(struct message *m, enum msg_type type, uint32_t serial)
{
	m->path = make_slice("");
	m->interface = make_slice("");
	m->member = make_slice("");
	m->error = make_slice("");
	m->destination = make_slice("");
	m->sender = make_slice("");
	m->signature = "";
	m->fdnum = 0;
	m->field_len = 0;
	m->body_len = 0;
	m->reply_serial = 0;
	m->serial = serial;
	m->flags = 0;
	m->type = type;
}

static int compact_parts(str_t *dst, str_t *src, uint32_t len)
{
	// work through the parts before the last one
	while (len > src->len) {
		// skip over empty parts
		while (!src->len) {
			src++;
		}

		// copy the source part as a base
		len -= src->len;
		*dst = *(src++);

		// and then pull bytes from the next one to make it 8 byte
		// aligned
		if (dst->len & 7) {
			uint32_t tocopy = 8 - (dst->len & 7);
			if (tocopy > len) {
				// there's not enough bytes remaining to fully 8
				// byte align this part
				tocopy = len;
			}
			if (dst->len + tocopy > dst->cap) {
				return -1;
			}
			src = defragment(dst->p + dst->len, src, tocopy);
			dst->len += tocopy;
		}
		dst++;
	}

	// copy the final part, it can be any length
	*dst = *src;
	return 0;
}

static void copy_remainder(str_t *dst, str_t *src, uint32_t off, uint32_t len)
{
	src->cap -= off;
	src->len -= off;
	src->p += off;
	while (src->len < len) {
		len -= src->len;
		*(dst++) = *(src++);
	}
	*dst = *src;
}

int parse_header(struct message *m, str_t *parts)
{
	struct raw_header h;
	defragment((char *)&h, parts, sizeof(h));

	if (h.endian != native_endian()) {
		return -1;
	}

	uint32_t field_len = h.field_len;
	uint32_t body_len = h.body_len;
	uint32_t field_off = MIN_MESSAGE_SIZE;
	uint32_t field_end = field_off + field_len;
	uint32_t body_end = ALIGN_UINT_UP(field_end, 8) + body_len;
	if (body_end > MAX_MESSAGE_SIZE) {
		return -1;
	}
	init_message(m, h.type, h.serial);
	m->flags = h.flags;
	m->body_len = body_len;
	m->field_len = field_len;
	return (int)body_end;
}

static int parse_field(struct message *msg, struct multipart *mi)
{
	// Min possible field size is 5 for a field of type byte: \xx
	// \01 'y' \00 \yy. We can always grab 5 bytes more in the
	// current part as each part is 8 byte aligned and mi->next is
	// always < mi->end
	unsigned pad = padding_8(mi->m_off);
	if (mi->m_off + pad + 5 > mi->m_end) {
		return -1;
	}
	skip_multipart_bytes(mi, pad);

	uint8_t ftype = *(uint8_t *)mi->p_next;

	if (ftype > FIELD_LAST) {
		// Unknown header, need to find the end.
		skip_multipart_bytes(mi, 1);
		mi->sig = "v";
		return skip_multipart_value(mi);

	} else {
		uint32_t ftag = read_little_4(mi->p_next);
		skip_multipart_bytes(mi, 4);

		switch (ftag) {
		case FTAG_REPLY_SERIAL:
			if (mi->m_off + 4 > mi->m_end) {
				return -1;
			}
			msg->reply_serial = read_little_4(mi->p_next);
			skip_multipart_bytes(mi, 4);
			return 0;

		case FTAG_UNIX_FDS:
			if (mi->m_off + 4 > mi->m_end) {
				return -1;
			}
			msg->fdnum = read_little_4(mi->p_next);
			skip_multipart_bytes(mi, 4);
			return 0;

		case FTAG_PATH:
			mi->sig = "s";
			return parse_multipart_string(mi, &msg->path) ||
			       check_path(msg->path.p);

		case FTAG_INTERFACE:
			mi->sig = "s";
			return parse_multipart_string(mi, &msg->interface) ||
			       check_interface(msg->interface.p);

		case FTAG_MEMBER:
			mi->sig = "s";
			return parse_multipart_string(mi, &msg->member) ||
			       check_member(msg->member.p);

		case FTAG_ERROR_NAME:
			mi->sig = "s";
			return parse_multipart_string(mi, &msg->error) ||
			       check_error_name(msg->error.p);

		case FTAG_DESTINATION:
			mi->sig = "s";
			return parse_multipart_string(mi, &msg->destination) ||
			       check_address(msg->destination.p);

		case FTAG_SENDER:
			mi->sig = "s";
			return parse_multipart_string(mi, &msg->sender) ||
			       check_unique_address(msg->sender.p);

		case FTAG_SIGNATURE:
			mi->sig = "g";
			return parse_multipart_signature(mi, &msg->signature);

		default:
			// unexpected field signature
			return -1;
		}
	}
}

int parse_message(struct message *msg, str_t *parts)
{
	uint32_t field_off = 0; // the header has already been consumed
	uint32_t field_len = msg->field_len;
	uint32_t field_end = field_off + field_len;
	uint32_t field_pad = padding_8(field_end);
	uint32_t body_off = field_end + field_pad;
	uint32_t body_end = body_off + msg->body_len;

#ifndef NDEBUG
	uint32_t left = body_end;
	str_t *p = parts;
	while (left > p->len) {
		assert(p->cap - p->len >= MULTIPART_WORKING_SPACE);
		p++;
	}
#endif

	// compact and align the part lengths so that each part (except for the
	// last) contains at least 8 bytes and is 8 byte aligned
	if (compact_parts(parts, parts, body_end)) {
		return -1;
	}

	struct multipart mi;
	init_multipart(&mi, parts, field_end, "");

	while (mi.m_off < field_end) {
		if (parse_field(msg, &mi)) {
			return -1;
		}
	}

	if (mi.m_off != field_end) {
		return -1;
	}

	// find the first chunk of the body
	str_t *body = mi.p;
	unsigned off = mi.p_next - body->p + field_pad;
	if (mi.p_next + field_pad == mi.p_end) {
		// end of header was aligned with end of the part
		body++;
		off = 0;
	}

	// copy the body parts into the parts variable
	copy_remainder(parts, body, off, msg->body_len);

	return 0;
}

bool is_reply(const struct message *request, const struct message *reply)
{
	return reply->reply_serial == request->serial &&
	       slice_eqs(reply->sender, request->destination);
}

////////////////////////////////////////////////////////
// message writing

static void append_uint32_field(struct builder *b, uint32_t tag, uint32_t v)
{
	// should be called first so that we are still aligned
	assert(!((uintptr_t)b->next & 3U));
	char *ptag = b->next;
	char *pval = ptag + 4;
	b->next = pval + 4;
	if (b->next <= b->end) {
		write_little_4(ptag, tag);
		*(uint32_t *)pval = v;
	}
}

static void append_string_field(struct builder *b, uint32_t tag, slice_t str)
{
	align_buffer_8(b);
	char *ptag = b->next;
	char *plen = ptag + 4;
	char *pstr = plen + 4;
	char *pnul = pstr + str.len;
	b->next = pnul + 1;
	if (b->next <= b->end) {
		write_little_4(ptag, tag);
		*(uint32_t *)plen = str.len;
		memcpy(pstr, str.p, str.len);
		pnul[0] = 0;
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
	char *ptag = b->next;
	char *plen = ptag + 4;
	char *pstr = plen + 1;
	b->next = pstr + len + 1;
	if (b->next <= b->end) {
		write_little_4(ptag, tag);
		*(uint8_t *)plen = (uint8_t)len;
		memcpy(pstr, sig, len + 1);
	}
}

struct builder start_message(const struct message *m, void *buf, size_t bufsz)
{
	struct builder b;
	init_builder(&b, buf, bufsz);

	if (bufsz < MIN_MESSAGE_SIZE) {
		b.end = b.next + 1;
		return b;
	}

	b.next += MIN_MESSAGE_SIZE;

	// unwrap the standard marshalling functions to add the field
	// type and variant signature in one go

	// fixed length fields go first so we can maintain 8 byte alignment
	if (m->reply_serial) {
		append_uint32_field(&b, FTAG_REPLY_SERIAL, m->reply_serial);
	}
	if (m->fdnum) {
		append_uint32_field(&b, FTAG_UNIX_FDS, m->fdnum);
	}
	if (*m->signature) {
		append_signature_field(&b, FTAG_SIGNATURE, m->signature);
	}
	if (m->path.len) {
		append_string_field(&b, FTAG_PATH, m->path);
	}
	if (m->interface.len) {
		append_string_field(&b, FTAG_INTERFACE, m->interface);
	}
	if (m->member.len) {
		append_string_field(&b, FTAG_MEMBER, m->member);
	}
	if (m->error.len) {
		append_string_field(&b, FTAG_ERROR_NAME, m->error);
	}
	if (m->destination.len) {
		append_string_field(&b, FTAG_DESTINATION, m->destination);
	}
	if (m->sender.len) {
		append_string_field(&b, FTAG_SENDER, m->sender);
	}

	struct raw_header *h = (struct raw_header *)buf;
	h->endian = native_endian();
	h->type = m->type;
	h->flags = m->flags;
	h->version = DBUS_VERSION;
	h->body_len = m->body_len;
	h->serial = m->serial;
	h->field_len = b.next - b.base - MIN_MESSAGE_SIZE;

	// align the end of the fields
	align_buffer_8(&b);
	b.sig = m->signature;
	return b;
}

int end_message(struct builder b)
{
	if (buffer_error(b) || *b.sig) {
		// error during marshalling or missing arguments
		return -1;
	}
	struct raw_header *h = (struct raw_header *)b.base;
	uint32_t field_len = h->field_len;
	uint32_t start = MIN_MESSAGE_SIZE + ALIGN_UINT_UP(field_len, 8);
	h->body_len = b.next - b.base - start;
	return (int)(b.next - b.base);
}

int write_message_header(const struct message *m, void *buf, size_t bufsz)
{
	struct builder b = start_message(m, buf, bufsz);
	return buffer_error(b) ? -1 : (int)(b.next - b.base);
}
