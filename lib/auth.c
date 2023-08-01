#include "auth.h"
#include "decode.h"
#include "encode.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define BUS_DESTINATION S("org.freedesktop.DBus")
#define BUS_INTERFACE S("org.freedesktop.DBus")
#define BUS_PATH S("/org/freedesktop/DBus")
#define HELLO S("Hello")

static int split_line(slice_t *pin, slice_t *pline)
{
	if (split_slice(*pin, '\n', pline, pin)) {
		return AUTH_READ_MORE;
	}
	if (!pline->len || pline->p[pline->len - 1] != '\r') {
		return AUTH_ERROR;
	}
	pline->len--;
	return 0;
}

static int append(char *buf, size_t bufsz, size_t *plen, slice_t s)
{
	if (*plen + s.len > bufsz) {
		return -1;
	}
	memcpy(buf + *plen, s.p, s.len);
	*plen += s.len;
	return 0;
}

enum {
	SERVER_WAIT_FOR_NUL = 0,
	SERVER_WAIT_FOR_AUTH,
	SERVER_WAIT_FOR_BEGIN,
	SERVER_WAIT_FOR_HELLO,
};

int step_server_auth(int *pstate, slice_t *pin, char *out, size_t *poutsz,
		     slice_t busid, uint32_t *pserial)
{
	size_t cap = *poutsz;
	*poutsz = 0;

	switch (*pstate) {
	case SERVER_WAIT_FOR_NUL:
		if (!pin->len) {
			return AUTH_READ_MORE;
		}
		if (pin->p[0]) {
			return AUTH_ERROR;
		}
		pin->p++;
		pin->len--;
		goto wait_for_auth;

	wait_for_auth:
		*pstate = SERVER_WAIT_FOR_AUTH;
	case SERVER_WAIT_FOR_AUTH: {
		slice_t line;
		int err = split_line(pin, &line);
		if (err) {
			return err;
		}

		slice_t arg0, arg1, arg2;
		if (split_slice(line, ' ', &arg0, &line) ||
		    split_slice(line, ' ', &arg1, &arg2) ||
		    !slice_eq(arg0, S("AUTH"))) {
			// unexpected command
			if (append(out, cap, poutsz, S("ERROR\r\n"))) {
				return AUTH_ERROR;
			}
			goto wait_for_auth;
		}

		if (!slice_eq(arg1, S("EXTERNAL"))) {
			// unsupported auth type
			if (append(out, cap, poutsz,
				   S("REJECTED EXTERNAL\r\n"))) {
				return AUTH_ERROR;
			}
			goto wait_for_auth;
		}

		// for now ignore the argument
		if (append(out, cap, poutsz, S("OK ")) ||
		    append(out, cap, poutsz, busid) ||
		    append(out, cap, poutsz, S("\r\n"))) {
			return AUTH_ERROR;
		}
		goto wait_for_begin;
	}

	wait_for_begin:
		*pstate = SERVER_WAIT_FOR_BEGIN;
	case SERVER_WAIT_FOR_BEGIN: {
		slice_t line;
		int err = split_line(pin, &line);
		if (err) {
			return err;
		} else if (slice_eq(line, S("BEGIN"))) {
			goto wait_for_hello;
		} else if (slice_eq(line, S("NEGOTIATE_UNIX_FD"))) {
			if (append(out, cap, poutsz, S("AGREE_UNIX_FD\r\n"))) {
				return AUTH_ERROR;
			}
			goto wait_for_begin;
		} else {
			if (append(out, cap, poutsz, S("ERROR\r\n"))) {
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
		if (pin->len < DBUS_MIN_MSG_SIZE) {
			return AUTH_READ_MORE;
		} else if (parse_message_size(pin->p, &hsz, &bsz)) {
			return AUTH_ERROR;
		} else if (hsz + bsz < pin->len) {
			return AUTH_READ_MORE;
		}

		// verify the fields

		struct message msg;
		if (parse_header(&msg, pin->p) || !msg.serial ||
		    msg.type != MSG_METHOD ||
		    !slice_eq(msg.destination, BUS_DESTINATION) ||
		    !slice_eq(msg.path, BUS_PATH) ||
		    !slice_eq(msg.interface, BUS_INTERFACE) ||
		    !slice_eq(msg.member, HELLO)) {
			return AUTH_ERROR;
		}

		*pserial = msg.serial;
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

int step_client_auth(int *pstate, slice_t *pin, char *out, size_t *poutsz,
		     slice_t uid, uint32_t *pserial)
{
	static const char hexdigits[] = "0123456789abcdef";
	size_t cap = *poutsz;
	*poutsz = 0;

	switch (*pstate) {
	case CLIENT_SEND_NUL:
		if (append(out, cap, poutsz,
			   make_slice("\0AUTH EXTERNAL ", 15))) {
			return AUTH_ERROR;
		}
		if (*poutsz + uid.len * 2 + 2 > cap) {
			return AUTH_ERROR;
		}
		for (int i = 0; i < uid.len; i++) {
			out[(*poutsz)++] =
				hexdigits[*(uint8_t *)(uid.p + i) >> 4];
			out[(*poutsz)++] =
				hexdigits[*(uint8_t *)(uid.p + i) & 15];
		}
		out[(*poutsz)++] = '\r';
		out[(*poutsz)++] = '\n';
		goto wait_for_ok;

	wait_for_ok:
		*pstate = CLIENT_WAIT_FOR_OK;
	case CLIENT_WAIT_FOR_OK: {
		slice_t line;
		int err = split_line(pin, &line);
		if (err) {
			return err;
		}

		slice_t cmd, arg;
		if (split_slice(line, ' ', &cmd, &arg) ||
		    !slice_eq(cmd, S("OK"))) {
			return AUTH_ERROR;
		}

		// ignore bus id for now
		(void)arg;
		if (append(out, cap, poutsz, S("BEGIN\r\n"))) {
			return AUTH_ERROR;
		}
		struct message msg;
		init_message(&msg, MSG_METHOD, 1);
		msg.destination = BUS_DESTINATION;
		msg.path = BUS_PATH;
		msg.interface = BUS_INTERFACE;
		msg.member = HELLO;

		struct builder b =
			start_message(out + *poutsz, cap - *poutsz, &msg);
		int sz = end_message(b);
		if (sz < 0) {
			return AUTH_ERROR;
		}
		*poutsz += sz;
		*pserial = 1;
		return AUTH_OK;
	}
	default:
		return AUTH_ERROR;
	}
}
