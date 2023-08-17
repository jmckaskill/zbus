#include "internal.h"

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

int zb_encode_auth_request(char *buf, size_t bufsz, const char *uid,
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
