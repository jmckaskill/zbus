#include "message.h"
#include "parse.h"
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

static_assert(sizeof(struct msg_header) == 16, "invalid packing");

char *message_data(struct msg_header *h)
{
	return ((char *)(h + 1)) + ALIGN_UINT_UP(h->header_len, 8);
}

int raw_message_length(const struct msg_header *h)
{
	if (h->endian != native_endian()) {
		return -1;
	}
	unsigned len = sizeof(struct msg_header) +
		       ALIGN_UINT_UP(h->header_len, 8) + h->body_len;
	if (len > MAX_MESSAGE_SIZE) {
		return -1;
	}
	return (int)len;
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

int parse_header_fields(struct msg_fields *f, const struct msg_header *h)
{
	struct string null = INIT_STRING;
	f->reply_serial = -1;
	f->fdnum = 0;
	f->path = null;
	f->interface = null;
	f->member = null;
	f->error = null;
	f->destination = null;
	f->sender = null;
	f->signature = null;

	const char *array = NULL;
	struct parser p;
	init_parser(&p, "{yv}", (char *)(h + 1), h->header_len);
	while (parse_array_next(&p, &array)) {
		parse_dict_begin(&p);
		uint8_t type = parse_byte(&p);
		struct variant value = parse_variant(&p);
		parse_dict_end(&p);
		if (p.error) {
			return -1;
		}
		switch (type) {
		case HEADER_PATH:
			if (value.type != TYPE_PATH) {
				return -1;
			}
			f->path = value.u.path;
			break;
		case HEADER_INTERFACE:
			if (value.type != TYPE_STRING ||
			    check_interface(value.u.str.p)) {
				return -1;
			}
			f->interface = value.u.str;
			break;
		case HEADER_MEMBER:
			if (value.type != TYPE_STRING ||
			    check_member(value.u.str.p)) {
				return -1;
			}
			f->member = value.u.str;
			break;
		case HEADER_ERROR_NAME:
			if (value.type != TYPE_STRING ||
			    check_error_name(value.u.str.p)) {
				return -1;
			}
			f->error = value.u.str;
			break;
		case HEADER_DESTINATION:
			if (value.type != TYPE_STRING ||
			    check_address(value.u.str.p)) {
				return -1;
			}
			f->destination = value.u.str;
			break;
		case HEADER_SENDER:
			if (value.type != TYPE_STRING ||
			    check_unique_address(value.u.str.p)) {
				return -1;
			}
			f->sender = value.u.str;
			break;
		case HEADER_SIGNATURE:
			if (value.type != TYPE_SIGNATURE) {
				return -1;
			}
			f->signature = value.u.str;
			break;
		case HEADER_REPLY_SERIAL:
			if (value.type != TYPE_UINT32) {
				return -1;
			}
			f->reply_serial = value.u.u32;
			break;
		case HEADER_UNIX_FDS:
			if (value.type != TYPE_UINT32) {
				return -1;
			}
			f->fdnum = value.u.u32;
			break;
		}
	}

	return 0;
}
