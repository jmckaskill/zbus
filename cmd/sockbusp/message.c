#include "message.h"
#include <assert.h>
#include <stdlib.h>

union endian_test {
	uint16_t u;
	uint8_t b[2];
};

static union endian_test g_native_endian = { 0x426C }; // "Bl"

uint8_t native_endian()
{
	return g_native_endian.b[0];
}

static_assert(sizeof(struct msg_header) == 12, "invalid packing");

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

static int check_name(const char *p, size_t maxsz)
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
			   p - begin <= maxsz) {
			return 0;
		} else {
			return -1;
		}
	}
}

int check_unique_address(const char *p)
{
	return *p != ':' || check_name(p + 1, 254);
}

int check_address(const char *p)
{
	return check_unique_address(p) && check_known_address(p);
}

int check_interface(const char *p)
{
	return check_name(p, 255);
}

///////////////////////////////////////////////////
// message reading

static const uint32_t *parse_aligned_4(struct iterator *p)
{
	static const uint32_t errret = 0;
	const char *n = p->n;
	// pointer should already be aligned call
	assert(ALIGN_PTR_UP(const char *, n, 4) == n);
	if (n + 4 > p->e) {
		p->error = 1;
		return &errret;
	}
	// skip over the field byte and variant
	p->n += 4;
	return (uint32_t *)n;
}

static inline uint32_t read_little_4(const uint32_t *n)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return *n;
#else
	const uint8_t *u = (const uint8_t *)n;
	return ((uint32_t)u[0]) | (((uint32_t)u[1]) << 8) |
	       (((uint32_t)u[2]) << 16) | (((uint32_t)u[3]) << 24);
#endif
}

void init_message(struct message *m)
{
	m->hdr.endian = native_endian();
	m->hdr.type = MSG_INVALID;
	m->hdr.flags = 0;
	m->hdr.version = DBUS_VERSION;
	m->hdr.body_len = 0;
	m->hdr.serial = 0;
	m->reply_serial = -1;
	m->path = to_string("");
	m->interface = to_string("");
	m->member = to_string("");
	m->error = to_string("");
	m->destination = to_string("");
	m->sender = to_string("");
	m->signature = "";
	m->fdnum = 0;
}

int parse_message(const char *p, struct message *msg, struct iterator *body)
{
	assert(ALIGN_PTR_UP(const char *, p, 8) == p);

	const struct msg_header *hdr = (const struct msg_header *)p;
	init_message(msg);
	msg->hdr = *hdr;

	unsigned field_len_off = sizeof(struct msg_header);
	unsigned field_len = *(uint32_t *)(p + field_len_off);
	unsigned field_off = field_len_off + 4;
	unsigned field_end = field_off + field_len;
	unsigned body_off = ALIGN_UINT_UP(field_end, 8);

	struct iterator ii;
	init_iterator(&ii, "{yv}", p + field_off, field_len);

	while (ii.n < ii.e) {
		align_iterator_8(&ii);

		uint32_t tag = read_little_4(parse_aligned_4(&ii));

		switch (tag) {
		case FTAG_PATH:
			ii.sig = TYPE_PATH;
			msg->path = parse_path(&ii);
			break;
		case FTAG_INTERFACE:
			ii.sig = TYPE_STRING;
			msg->interface = parse_string(&ii);
			if (check_interface(msg->interface.p)) {
				return -1;
			}
			break;
		case FTAG_MEMBER:
			ii.sig = TYPE_STRING;
			msg->member = parse_string(&ii);
			if (check_member(msg->member.p)) {
				return -1;
			}
			break;
		case FTAG_ERROR_NAME:
			ii.sig = TYPE_STRING;
			msg->error = parse_string(&ii);
			if (check_error_name(msg->error.p)) {
				return -1;
			}
			break;
		case FTAG_DESTINATION:
			ii.sig = TYPE_STRING;
			msg->destination = parse_string(&ii);
			if (check_address(msg->destination.p)) {
				return -1;
			}
			break;
		case FTAG_SENDER:
			ii.sig = TYPE_STRING;
			msg->sender = parse_string(&ii);
			if (check_unique_address(msg->sender.p)) {
				return -1;
			}
			break;
		case FTAG_SIGNATURE:
			ii.sig = TYPE_SIGNATURE;
			msg->signature = parse_signature(&ii);
			break;
		case FTAG_REPLY_SERIAL: {
			const uint32_t *n = parse_aligned_4(&ii);
			msg->reply_serial = *n;
			break;
		}
		case FTAG_UNIX_FDS: {
			const uint32_t *n = parse_aligned_4(&ii);
			msg->fdnum = *n;
			break;
		}
		default: {
			// unknown header, need to back out and use the generic
			// version
			ii.n -= 4;
			ii.sig = "yv";
			uint8_t type = parse_byte(&ii);
			parse_variant(&ii);
			if (type <= FIELD_LAST) {
				// the field tag should have captured these
				// this means someone sent a type we understand
				// but with the wrong signature
				return -1;
			}
			break;
		}
		}
	}

	if (ii.error) {
		return -1;
	}

	init_iterator(body, msg->signature, p + body_off, hdr->body_len);
	return 0;
}

int raw_message_len(const char *p)
{
	const struct msg_header *h = (const struct msg_header *)p;
	if (h->endian != native_endian()) {
		return -1;
	}
	unsigned field_off = sizeof(struct msg_header) + 4;
	unsigned field_len = *(uint32_t *)(h + 1);
	unsigned field_end = field_off + field_len;
	unsigned len = ALIGN_UINT_UP(field_end, 8) + h->body_len;
	if (len > MAX_MESSAGE_SIZE) {
		return -1;
	}
	return (int)len;
}

////////////////////////////////////////////////////////
// message writing

static inline void write_aligned_L4(char *p, uint32_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	*(uint32_t *)(p) = v;
#else
	*(uint8_t *)(p) = (uint8_t)(v);
	*(uint8_t *)(p + 1) = (uint8_t)(v >> 8);
	*(uint8_t *)(p + 2) = (uint8_t)(v >> 16);
	*(uint8_t *)(p + 3) = (uint8_t)(v >> 24);
#endif
}

static void append_uint32_field(struct buffer *b, uint32_t tag, uint32_t v)
{
	// should be called first so that we are still aligned
	assert(ALIGN_UINT_UP(b->off, 4) == b->off);
	unsigned off = b->off + 8;
	if (off > b->cap) {
		b->error = 1;
	} else {
		write_aligned_L4(b->base + b->off, tag);
		*(uint32_t *)(b->base + b->off + 4) = v;
		b->off = off;
	}
}

static void append_string_field(struct buffer *b, uint32_t tag,
				struct string str)
{
	align_buffer_8(b);
	unsigned tag_off = b->off;
	unsigned len_off = tag_off + 4;
	unsigned str_off = len_off + 4;
	unsigned end = str_off + str.len + 1;
	if (end > b->cap) {
		b->error = 1;
	} else {
		write_aligned_L4(b->base + tag_off, tag);
		*(uint32_t *)(b->base + len_off) = str.len;
		memcpy(b->base + str_off, str.p, str.len);
		b->base[end - 1] = 0;
		b->off = end;
	}
}

static void append_signature_field(struct buffer *b, uint32_t tag,
				   const char *sig)
{
	align_buffer_8(b);
	if (b->off + 4 > b->cap) {
		b->error = 1;
	} else {
		write_aligned_L4(b->base + b->off, tag);
		b->off += 4;
		b->sig = TYPE_SIGNATURE;
		append_signature(b, sig);
	}
}

void start_message(struct buffer *b, const struct message *m,
		   struct message_data *data)
{
	align_buffer_8(b);
	data->start = b->off;

	b->sig = "yyyyuua{yv}";
	append_raw(b, "yyyyuu", &m->hdr, sizeof(m->hdr));

	// unwrap the standard marshalling functions to add the field type and
	// variant signature in one go

	struct array_data array;
	start_dict(b, &array);
	// fixed length fields go first so we can maintain 8 byte alignment
	if (m->reply_serial) {
		append_uint32_field(b, FTAG_REPLY_SERIAL, m->reply_serial);
	}
	if (m->fdnum) {
		append_uint32_field(b, FTAG_UNIX_FDS, m->fdnum);
	}
	if (*m->signature) {
		append_signature_field(b, FTAG_SIGNATURE, m->signature);
	}
	if (m->path.len) {
		append_string_field(b, FTAG_PATH, m->path);
	}
	if (m->interface.len) {
		append_string_field(b, FTAG_INTERFACE, m->interface);
	}
	if (m->member.len) {
		append_string_field(b, FTAG_MEMBER, m->member);
	}
	if (m->error.len) {
		append_string_field(b, FTAG_ERROR_NAME, m->error);
	}
	if (m->destination.len) {
		append_string_field(b, FTAG_DESTINATION, m->destination);
	}
	if (m->sender.len) {
		append_string_field(b, FTAG_SENDER, m->sender);
	}
	b->sig = array.sig + 2; // point to } in a{yv}
	end_dict(b, &array);

	// align the end of the fields
	align_buffer_8(b);
	data->body = b->off;
	b->sig = m->signature;
}

void end_message(struct buffer *b, struct message_data *data)
{
	if (b->error) {
		return;
	}
	struct msg_header *h = (struct msg_header *)(b->base + data->start);
	h->body_len = b->off - data->body;
	if (*b->sig) {
		// did you forget to add some arguments?
		b->error = 1;
	}
}
