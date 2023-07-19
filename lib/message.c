#include "message.h"
#include <assert.h>
#include <limits.h>
#include <stdlib.h>

struct raw_header {
	uint8_t endian;
	uint8_t type;
	uint8_t flags;
	uint8_t version;
	char body_len[4];
	char serial[4];
	char field_len[4];
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

struct multipart_iterator {
	str_t *p; // current part
	char *p_next; // next data byte in current part
	char *p_end; // end of current part
	uint32_t m_off; // offset within message
	uint32_t m_end; // offset where the iterator ends
	// if m_off < m_end then p_next < p_end
	// even if p_next is the start of a part
};

static void init_multipart(struct multipart_iterator *mi, str_t *parts,
			   uint32_t len)
{
	mi->p = parts;
	mi->p_next = parts->p;
	mi->p_end = parts->p + parts->len;
	mi->m_off = 0;
	mi->m_end = len;
}

static void skip_multipart(struct multipart_iterator *mi, uint32_t len)
{
	mi->m_off += len;
	if (mi->m_off > mi->m_end) {
		return;
	}
	for (;;) {
		mi->p_next += len;
		if (mi->p_next < mi->p_end) {
			// next data is in this part
			return;
		}

		// consume the overflow bytes in the next part
		len = mi->p_next - mi->p_end;
		mi->p++;
		mi->p_next = mi->p->p;
		mi->p_end = mi->p->p + mi->p->len;
	}
}

static inline void align_multipart_2(struct multipart_iterator *mi)
{
	uint32_t pad = mi->m_off & 1;
	mi->m_off += pad;
	mi->p_next += pad;
}

static inline void align_multipart_4(struct multipart_iterator *mi)
{
	uint32_t pad = (4 - (mi->m_off & 3)) & 3;
	mi->m_off += pad;
	mi->p_next += pad;
}

static inline void align_multipart_8(struct multipart_iterator *mi)
{
	uint32_t pad = (8 - (mi->m_off & 7)) & 7;
	mi->m_off += pad;
	mi->p_next += pad;
}

static str_t *copy_into_working(str_t *dst, str_t *src, uint32_t len)
{
	char *end = dst->p + dst->len;
	dst->len += len;
	assert(dst->len <= dst->cap);

	// copy complete parts
	while (src->len >= len) {
		memcpy(end, src->p, src->len);
		end += src->len;
		len -= src->len;
		src++;
	}
	// copy partial part
	memcpy(end, src->p, len);
	src->p += len;
	src->len -= len;
	src->cap -= len;
	return src;
}

static void compact_parts(str_t *dst, str_t *src, uint32_t len)
{
	// work through the parts before the last one
	while (src->len < len) {
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
				tocopy = len;
			}
			src = copy_into_working(dst, src, tocopy);
		}
		dst++;
	}

	// copy the final part, it can be any length
	*dst = *src;
}

static void copy_remainder(str_t *dst, struct multipart_iterator *mi,
			   uint32_t len)
{
	str_t *src = mi->p;
	src->cap -= mi->p_next - src->p;
	src->len -= mi->p_next - src->p;
	src->p = mi->p_next;
	while (src->len < len) {
		len -= src->len;
		*(dst++) = *(src++);
	}
	*dst = *src;
}

static slice_t compact_string(struct multipart_iterator *mi, uint32_t len)
{
	char *ret = mi->p_next;
	mi->m_off += len + 1;
	mi->p_next += len + 1;

	if (mi->p_next >= mi->p_end) {
		uint32_t need = mi->p_next - mi->p_end;
		str_t *n = copy_into_working(mi->p, mi->p + 1, need);
		mi->p = n;
		mi->p_next = n->p;
		mi->p_end = n->p + n->len;
	}

	return make_slice2(ret, len);
}

static int get_multipart_string(struct multipart_iterator *mi, slice_t *pslice)
{
	if (mi->m_off + 4 > mi->m_end) {
		return -1;
	}
	uint32_t len = read_native_4(mi->p_next);
	if (mi->m_off + 4 + len + 1 > mi->m_end) {
		return -1;
	}
	mi->m_off += 4;
	mi->p_next += 4;
	*pslice = compact_string(mi, len);
	return check_string(*pslice);
}

static const char *get_multipart_signature(struct multipart_iterator *mi)
{
	assert(mi->m_off + 1 <= mi->m_end);
	uint8_t len = *(uint8_t *)(mi->p_next);
	if (mi->m_off + 1 + len + 1 > mi->m_end) {
		return NULL;
	}
	mi->m_off++;
	mi->p_next++;
	slice_t slice = compact_string(mi, len);
	return check_string(slice) ? NULL : slice.p;
}

static uint32_t array_padding(uint32_t off, char type)
{
	switch (type) {
	case TYPE_INT16:
	case TYPE_UINT16:
		return off & 1;

	case TYPE_INT32:
	case TYPE_UINT32:
	case TYPE_BOOL:
	case TYPE_ARRAY:
	case TYPE_STRING:
		return (4 - (off & 3)) & 3;

	case TYPE_INT64:
	case TYPE_UINT64:
	case TYPE_DOUBLE:
	case TYPE_DICT_BEGIN:
	case TYPE_STRUCT_BEGIN:
		return (8 - (off & 7)) & 7;

	case TYPE_BYTE:
	case TYPE_SIGNATURE:
	case TYPE_VARIANT:
	default:
		return 0;
	}
}

static int skip_multipart_variant(struct multipart_iterator *mi,
				  const char *sig)
{
	// We're about to filter out this data, so we don't need to validate it.
	// Instead we're just trying to skip over the data assuming it's valid.
	// If the data is invalid then we just need to not crash.
	const char *stack[16];
	int stackn = 0;

	for (;;) {
		switch (*(sig++)) {
		case '\0':
			if (stackn) {
				// we've reached the end of the variant
				sig = stack[--stackn];
				continue;
			}
			return 0;

		case TYPE_BYTE:
			skip_multipart(mi, 1);
			break;

		case TYPE_INT16:
		case TYPE_UINT16:
			align_multipart_2(mi);
			skip_multipart(mi, 2);
			break;

		case TYPE_BOOL:
		case TYPE_INT32:
		case TYPE_UINT32:
			align_multipart_4(mi);
			skip_multipart(mi, 4);
			break;

		case TYPE_INT64:
		case TYPE_UINT64:
		case TYPE_DOUBLE:
			align_multipart_8(mi);
			skip_multipart(mi, 8);
			break;

		case TYPE_STRING:
		case TYPE_PATH: {
			align_multipart_4(mi);
			if (mi->m_off + 4 > mi->m_end) {
				return -1;
			}
			uint32_t len = read_native_4(mi->p_next);
			skip_multipart(mi, 4 + len + 1);
			break;
		}

		case TYPE_SIGNATURE: {
			if (mi->m_off >= mi->m_end) {
				return -1;
			}
			uint8_t len = *(uint8_t *)mi->p_next;
			skip_multipart(mi, 1 + len + 1);
			break;
		}

		case TYPE_ARRAY: {
			align_multipart_4(mi);
			if (mi->m_off + 4 > mi->m_end) {
				return -1;
			}
			uint32_t len = read_native_4(mi->p_next);
			uint32_t pad = array_padding(mi->m_off + 4, *sig);
			skip_multipart(mi, 4 + pad + len);
			if (skip_signature(&sig, true)) {
				return -1;
			}
			break;
		}

		case TYPE_STRUCT_BEGIN:
			align_multipart_8(mi);
			break;

		case TYPE_VARIANT: {
			// A nested variant could legitimitely exist within a
			// struct within the header field. Need to save the
			// current signature to a stack.
			const char **psig = &stack[stackn++];
			if (psig == stack + sizeof(stack)) {
				return -1;
			}
			// save the current signature to the stack and get the
			// new one from the data
			*psig = sig;
			sig = get_multipart_signature(mi);
			if (sig == NULL) {
				return -1;
			}
			break;
		}

		case TYPE_DICT_BEGIN:
			// dict can not exist outside an array
		default:
			return -1;
		}

		if (mi->m_off > mi->m_end) {
			return -1;
		}
	}
}

int parse_header(struct message *m, const char *p)
{
	const struct raw_header *h = (const struct raw_header *)p;
	if (h->endian != native_endian()) {
		return -1;
	}

	uint32_t field_len = read_native_4(h->field_len);
	uint32_t body_len = read_native_4(h->body_len);
	uint32_t field_off = MIN_MESSAGE_SIZE;
	uint32_t field_end = field_off + field_len;
	uint32_t body_end = ALIGN_UINT_UP(field_end, 8) + body_len;
	if (body_end > MAX_MESSAGE_SIZE) {
		return -1;
	}
	init_message(m, h->type, read_native_4(h->serial));
	m->flags = h->flags;
	m->body_len = body_len;
	m->field_len = field_len;
	return (int)body_end;
}

int parse_message(struct message *msg, str_t *parts)
{
	uint32_t field_off = MIN_MESSAGE_SIZE;
	uint32_t field_len = msg->field_len;
	uint32_t field_end = field_off + field_len;
	uint32_t body_off = ALIGN_UINT_UP(field_end, 8);
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
	compact_parts(parts, parts, body_end);

	struct multipart_iterator mi;
	init_multipart(&mi, parts, field_end);
	skip_multipart(&mi, MIN_MESSAGE_SIZE);

	while (mi.m_off < field_end) {
		// Min possible field size is 5 for a field of type byte: \xx
		// \01 'y' \00 \yy. We can always grab 5 bytes more in the
		// current part as each part is 8 byte aligned and mi->next is
		// always < mi->end
		align_multipart_8(&mi);
		if (mi.m_off + 5 > field_end) {
			return -1;
		}

		assert(mi.p_next + 5 <= mi.p_end);

		uint32_t ftag = read_little_4(mi.p_next);
		mi.p_next += 4;
		mi.m_off += 4;

		switch (ftag) {
		case FTAG_REPLY_SERIAL: {
			if (mi.m_off + 4 > mi.m_end) {
				return -1;
			}
			msg->reply_serial = *(uint32_t *)mi.p_next;
			mi.p_next += 4;
			mi.m_off += 4;
			break;
		}
		case FTAG_UNIX_FDS: {
			if (mi.m_off + 4 > mi.m_end) {
				return -1;
			}
			msg->fdnum = *(uint32_t *)mi.p_next;
			mi.p_next += 4;
			mi.m_off += 4;
			break;
		}
		case FTAG_PATH:
			if (get_multipart_string(&mi, &msg->path) ||
			    check_path(msg->path.p)) {
				return -1;
			}
			break;
		case FTAG_INTERFACE:
			if (get_multipart_string(&mi, &msg->interface) ||
			    check_interface(msg->interface.p)) {
				return -1;
			}
			break;
		case FTAG_MEMBER:
			if (get_multipart_string(&mi, &msg->member) ||
			    check_member(msg->member.p)) {
				return -1;
			}
			break;
		case FTAG_ERROR_NAME:
			if (get_multipart_string(&mi, &msg->error) ||
			    check_error_name(msg->error.p)) {
				return -1;
			}
			break;
		case FTAG_DESTINATION:
			if (get_multipart_string(&mi, &msg->destination) ||
			    check_address(msg->destination.p)) {
				return -1;
			}
			break;
		case FTAG_SENDER:
			if (get_multipart_string(&mi, &msg->sender) ||
			    check_unique_address(msg->sender.p)) {
				return -1;
			}
			break;
		case FTAG_SIGNATURE:
			msg->signature = get_multipart_signature(&mi);
			if (msg->signature == NULL) {
				return -1;
			}
			break;
		default: {
			// Unknown header, need to find the end. The signature
			// could be longer than 2 bytes, so put the signature
			// back and parse it properly.
			mi.p_next -= 3;
			mi.m_off -= 3;
			const char *sig = get_multipart_signature(&mi);
			if (skip_multipart_variant(&mi, sig)) {
				return -1;
			}
			break;
		}
		}
	}

	if (mi.m_off != field_end) {
		return -1;
	}

	// align to the beginning of the body
	mi.m_end = body_off;
	align_multipart_8(&mi);

	// copy the body parts into the parts variable
	copy_remainder(parts, &mi, msg->body_len);

	return 0;
}

bool is_reply(const struct message *request, const struct message *reply)
{
	return reply->reply_serial == request->serial &&
	       slice_eqs(reply->sender, request->destination);
}

////////////////////////////////////////////////////////
// message writing

static void append_uint32_field(struct buffer *b, uint32_t tag, uint32_t v)
{
	// should be called first so that we are still aligned
	assert(ALIGN_UINT_UP(b->off, 4) == b->off);
	b->off += 8;
	if (b->off <= b->cap) {
		write_little_4(b->base + b->off - 8, tag);
		write_native_4(b->base + b->off - 4, v);
	}
}

static void append_string_field(struct buffer *b, uint32_t tag, slice_t str)
{
	align_buffer_8(b);
	uint32_t tag_off = b->off;
	uint32_t len_off = tag_off + 4;
	uint32_t str_off = len_off + 4;
	uint32_t nul_off = str_off + str.len;
	b->off = nul_off + 1;
	if (b->off <= b->cap) {
		write_little_4(b->base + tag_off, tag);
		write_native_4(b->base + len_off, str.len);
		memcpy(b->base + str_off, str.p, str.len);
		b->base[nul_off] = 0;
	}
}

static void append_signature_field(struct buffer *b, uint32_t tag,
				   const char *sig)
{
	align_buffer_8(b);
	size_t slen = strlen(sig);
	if (slen > 255) {
		b->off = b->cap + 1;
		return;
	}
	uint32_t tag_off = b->off;
	uint32_t len_off = tag_off + 4;
	uint32_t str_off = len_off + 1;
	b->off = str_off + slen + 1;
	if (b->off <= b->cap) {
		write_little_4(b->base + tag_off, tag);
		b->base[len_off] = (uint8_t)slen;
		memcpy(b->base + str_off, sig, slen + 1);
	}
}

struct buffer start_message(const struct message *m, void *buf, size_t bufsz)
{
	struct buffer b;
	init_buffer(&b, buf, bufsz);

	if (MIN_MESSAGE_SIZE > b.cap) {
		b.off = UINT_MAX;
		return b;
	}

	b.off = MIN_MESSAGE_SIZE;

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

	// align the end of the fields

	struct raw_header hdr;
	hdr.endian = native_endian();
	hdr.type = m->type;
	hdr.flags = m->flags;
	hdr.version = DBUS_VERSION;
	write_native_4(hdr.body_len, 0);
	write_native_4(hdr.serial, m->serial);
	write_native_4(hdr.field_len, b.off - MIN_MESSAGE_SIZE);

	memcpy(buf, &hdr, sizeof(hdr));

	align_buffer_8(&b);
	b.sig = m->signature;
	return b;
}

int end_message(struct buffer b)
{
	if (b.off > b.cap || *b.sig) {
		// did you forget to add some arguments?
		return -1;
	}
	struct raw_header *h = (struct raw_header *)b.base;
	uint32_t field_len = read_native_4(h->field_len);
	uint32_t start = MIN_MESSAGE_SIZE + ALIGN_UINT_UP(field_len, 8);
	write_native_4(h->body_len, b.off - start);
	return 0;
}
