#include "auth.h"
#include "decode.h"
#include "encode.h"
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define BUS_DESTINATION S8("\024org.freedesktop.DBus")
#define BUS_INTERFACE S8("\024org.freedesktop.DBus")
#define BUS_PATH S8("\025/org/freedesktop/DBus")
#define HELLO S8("\005Hello")

static bool begins_with(char *line, char *end, const char *test)
{
	size_t len = strlen(test);
	return (size_t)(end - line) >= len && !memcmp(line, test, len);
}

static bool equals(char *line, char *end, const char *test)
{
	size_t len = strlen(test);
	return (end - line) == len && !memcmp(line, test, len);
}

static int split_line(char **pin, char *end, char **pstart, char **pend)
{
	char *start = *pin;
	char *nl = memchr(start, '\n', end - start);
	if (!nl) {
		return AUTH_READ_MORE;
	}
	if (nl == start || nl[-1] != '\r' || memchr(start, 0, nl - start)) {
		return AUTH_ERROR;
	}
	*pin = nl + 1;
	*pstart = start;
	*pend = nl;
	nl[-1] = ' ';
	nl[0] = '\0';
	return 0;
}

static char *append(char *out, char *end, const void *str, size_t len)
{
	if (out + len > end) {
		return end + 1;
	}
	memcpy(out, str, len);
	return out + len;
}

static inline char *append_cstr(char *out, char *end, const char *str)
{
	return append(out, end, str, strlen(str));
}

static inline char *append_char(char *out, char *end, char ch)
{
	if (out < end) {
		*(out++) = ch;
	}
	return out;
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

enum {
	SERVER_WAIT_FOR_NUL = 0,
	SERVER_WAIT_FOR_AUTH,
	SERVER_WAIT_FOR_BEGIN,
	SERVER_WAIT_FOR_HELLO,
};

int step_server_auth(int *pstate, char **pin, char *ie, char **pout, char *oe,
		     const char *busid, uint32_t *pserial)
{
	char *in = *pin;
	char *out = *pout;

	switch (*pstate) {
	case SERVER_WAIT_FOR_NUL:
		if (in == ie) {
			return AUTH_READ_MORE;
		}
		if (*in) {
			return AUTH_ERROR;
		}
		in++;
		goto wait_for_auth;

	wait_for_auth:
		*pin = in;
		*pout = out;
		*pstate = SERVER_WAIT_FOR_AUTH;
	case SERVER_WAIT_FOR_AUTH: {
		char *line, *nl;
		int err = split_line(&in, ie, &line, &nl);
		if (err) {
			return err;
		}

		if (!begins_with(line, nl, "AUTH ")) {
			// unexpected command
			out = append_cstr(out, oe, "ERROR\r\n");
			if (out > oe) {
				return AUTH_SEND_MORE;
			}
			goto wait_for_auth;
		}

		if (!begins_with(line, nl, "AUTH EXTERNAL ")) {
			// unsupported auth type
			out = append_cstr(out, oe, "REJECTED EXTERNAL\r\n");
			if (out > oe) {
				return AUTH_SEND_MORE;
			}
			goto wait_for_auth;
		}

		// for now ignore the argument
		out = append_cstr(out, oe, "OK ");
		out = append_cstr(out, oe, busid);
		out = append_cstr(out, oe, "\r\n");
		if (out > oe) {
			return AUTH_SEND_MORE;
		}
		goto wait_for_begin;
	}

	wait_for_begin:
		*pin = in;
		*pout = out;
		*pstate = SERVER_WAIT_FOR_BEGIN;
	case SERVER_WAIT_FOR_BEGIN: {
		char *line, *nl;
		int err = split_line(&in, ie, &line, &nl);
		if (err) {
			return err;
		}
		if (equals(line, nl, "BEGIN ")) {
			goto wait_for_hello;
		} else if (equals(line, nl, "NEGOTIATE_UNIX_FD ")) {
			out = append_cstr(out, oe, "AGREE_UNIX_FD\r\n");
			if (out > oe) {
				return AUTH_SEND_MORE;
			}
			goto wait_for_begin;
		} else {
			out = append_cstr(out, oe, "ERROR\r\n");
			if (out > oe) {
				return AUTH_SEND_MORE;
			}
			goto wait_for_begin;
		}
	}

	wait_for_hello:
		*pin = in;
		*pout = out;
		*pstate = SERVER_WAIT_FOR_HELLO;
	case SERVER_WAIT_FOR_HELLO: {
		// process the Hello header

		size_t hsz, bsz;
		if (in + DBUS_MIN_MSG_SIZE > ie) {
			return AUTH_READ_MORE;
		} else if (parse_message_size(in, &hsz, &bsz)) {
			return AUTH_ERROR;
		} else if (in + hsz + bsz > ie) {
			return AUTH_READ_MORE;
		}

		// verify the fields
		// method fields always have serial, path & member
		struct message m;
		if (parse_header(&m, in) || m.type != MSG_METHOD ||
		    !m.destination || !str8eq(m.destination, BUS_DESTINATION) ||
		    !str8eq(m.path, BUS_PATH) || !m.interface ||
		    !str8eq(m.interface, BUS_INTERFACE) ||
		    !str8eq(m.member, HELLO)) {
			return AUTH_ERROR;
		}

		*pserial = m.serial;
		*pin = in + hsz + bsz;
		return AUTH_FINISHED;
	}
	default:
		return AUTH_ERROR;
	}
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

static inline void write32(void *p, uint32_t u)
{
	memcpy(p, &u, 4);
}

int write_client_auth(char *buf, size_t bufsz, const char *uid, uint32_t serial)
{
	char *out = buf;
	char *end = buf + bufsz;
	out = append_char(out, end, '\0');
	out = append_cstr(out, end, "AUTH EXTERNAL ");
	out = append_hex(out, end, (uint8_t *)uid, strlen(uid));
	out = append_cstr(out, end, "\r\nBEGIN\r\n");
	char *msg = out;
	out = append(out, end, hello, sizeof(hello) - 1);

	if (out > end) {
		return -1;
	}

	msg[0] = native_endian();
	set_serial(msg, serial);
	write32(msg + 12, 128 - 16 /*raw header*/ - 3 /*end padding*/);
	write32(msg + 20, 21); // path len
	write32(msg + 52, 20); // interface len
	write32(msg + 84, 5); // member len
	write32(msg + 100, 20); // destination len

	return (int)(out - buf);
}

int read_client_auth(char *buf, size_t sz)
{
	char *in = buf;
	char *end = in + sz;
	char *line, *nl;
	int err = split_line(&in, end, &line, &nl);
	if (err) {
		return err;
	}

	// ignore bus id for now
	if (!begins_with(line, nl, "OK ")) {
		return AUTH_ERROR;
	}

	return (int)(in - buf);
}
