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

static int append(char **pout, char *oute, const char *str)
{
	size_t len = strlen(str);
	if (*pout + len > oute) {
		return -1;
	}
	memcpy(*pout, str, len);
	*pout += len;
	return 0;
}

static int append_char(char **pout, char *oute, char ch)
{
	if (*pout >= oute) {
		return -1;
	}
	*((*pout)++) = ch;
	return 0;
}

static int append_hex(char **pout, char *oute, const uint8_t *data, size_t sz)
{
	static const char hexdigits[] = "0123456789abcdef";
	if (*pout + (sz * 2) > oute) {
		return -1;
	}
	for (size_t i = 0; i < sz; i++) {
		*((*pout)++) = hexdigits[data[i] >> 4];
		*((*pout)++) = hexdigits[data[i] & 15];
	}
	return 0;
}

enum {
	SERVER_WAIT_FOR_NUL = 0,
	SERVER_WAIT_FOR_AUTH,
	SERVER_WAIT_FOR_BEGIN,
	SERVER_WAIT_FOR_HELLO,
};

int step_server_auth(int *pstate, char **pin, int insz, char **pout, int outsz,
		     const char *busid, uint32_t *pserial)
{
	char *ine = *pin + insz;
	char *oute = *pout + outsz;

	switch (*pstate) {
	case SERVER_WAIT_FOR_NUL:
		if ((*pin) == ine) {
			return AUTH_READ_MORE;
		}
		if (**pin) {
			return AUTH_ERROR;
		}
		(*pin)++;
		goto wait_for_auth;

	wait_for_auth:
		*pstate = SERVER_WAIT_FOR_AUTH;
	case SERVER_WAIT_FOR_AUTH: {
		char *line, *nl;
		int err = split_line(pin, ine, &line, &nl);
		if (err) {
			return err;
		}

		if (!begins_with(line, nl, "AUTH ")) {
			// unexpected command
			if (append(pout, oute, "ERROR\r\n")) {
				return AUTH_ERROR;
			}
			goto wait_for_auth;
		}

		if (!begins_with(line, nl, "AUTH EXTERNAL ")) {
			// unsupported auth type
			if (append(pout, oute, "REJECTED EXTERNAL\r\n")) {
				return AUTH_ERROR;
			}
			goto wait_for_auth;
		}

		// for now ignore the argument
		if (append(pout, oute, "OK ") || append(pout, oute, busid) ||
		    append(pout, oute, "\r\n")) {
			return AUTH_ERROR;
		}
		goto wait_for_begin;
	}

	wait_for_begin:
		*pstate = SERVER_WAIT_FOR_BEGIN;
	case SERVER_WAIT_FOR_BEGIN: {
		char *line, *nl;
		int err = split_line(pin, ine, &line, &nl);
		if (err) {
			return err;
		}
		if (equals(line, nl, "BEGIN ")) {
			goto wait_for_hello;
		} else if (equals(line, nl, "NEGOTIATE_UNIX_FD ")) {
			if (append(pout, oute, "AGREE_UNIX_FD\r\n")) {
				return AUTH_ERROR;
			}
			goto wait_for_begin;
		} else {
			if (append(pout, oute, "ERROR\r\n")) {
				return AUTH_ERROR;
			}
			goto wait_for_begin;
		}
	}

	wait_for_hello:
		*pstate = SERVER_WAIT_FOR_HELLO;
	case SERVER_WAIT_FOR_HELLO: {
		// process the Hello header

		size_t hsz, bsz;
		if (*pin + DBUS_MIN_MSG_SIZE > ine) {
			return AUTH_READ_MORE;
		} else if (parse_message_size(*pin, &hsz, &bsz)) {
			return AUTH_ERROR;
		} else if (*pin + hsz + bsz > ine) {
			return AUTH_READ_MORE;
		}

		// verify the fields
		// method fields always have serial, path & member
		struct message m;
		if (parse_header(&m, *pin) || m.type != MSG_METHOD ||
		    !m.destination || !str8eq(m.destination, BUS_DESTINATION) ||
		    !str8eq(m.path, BUS_PATH) || !m.interface ||
		    !str8eq(m.interface, BUS_INTERFACE) ||
		    !str8eq(m.member, HELLO)) {
			return AUTH_ERROR;
		}

		*pin += hsz + bsz;
		*pserial = m.serial;
		return AUTH_OK;
	}
	default:
		return AUTH_ERROR;
	}
}

enum {
	CLIENT_SEND_NUL,
	CLIENT_WAIT_FOR_OK,
};

int step_client_auth(int *pstate, char **pin, int insz, char **pout, int outsz,
		     const char *uid, uint32_t *pserial)
{
	char *ine = *pin + insz;
	char *oute = *pout + outsz;

	switch (*pstate) {
	case CLIENT_SEND_NUL:
		if (append_char(pout, oute, '\0') ||
		    append(pout, oute, "AUTH EXTERNAL ") ||
		    append_hex(pout, oute, (uint8_t *)uid, strlen(uid)) ||
		    append(pout, oute, "\r\n")) {
			return AUTH_ERROR;
		}
		goto wait_for_ok;

	wait_for_ok:
		*pstate = CLIENT_WAIT_FOR_OK;
	case CLIENT_WAIT_FOR_OK: {
		char *line, *nl;
		int err = split_line(pin, ine, &line, &nl);
		if (err) {
			return err;
		}

		// ignore bus id for now
		if (!begins_with(line, nl, "OK ")) {
			return AUTH_ERROR;
		}
		if (append(pout, oute, "BEGIN\r\n")) {
			return AUTH_ERROR;
		}
		struct message m;
		init_message(&m, MSG_METHOD, 1);
		m.destination = BUS_DESTINATION;
		m.path = BUS_PATH;
		m.interface = BUS_INTERFACE;
		m.member = HELLO;

		struct builder b = start_message(*pout, oute - *pout, &m);
		int sz = end_message(b);
		if (sz < 0) {
			return AUTH_ERROR;
		}
		*pout += sz;
		*pserial = 1;
		return AUTH_OK;
	}
	default:
		return AUTH_ERROR;
	}
}
