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

static char *split_after_space(char *line)
{
	static char empty[] = { 0 };
	char *space = strchr(line, ' ');
	if (space) {
		*space = 0;
		return space + 1;
	} else {
		return empty;
	}
}

static int split_line(buf_t *s, char **pline, int *pnext)
{
	int n = 0;
	for (;;) {
		if (n + 2 > s->len) {
			return AUTH_READ_MORE;
		}
		char ch0 = s->p[n];
		char ch1 = s->p[n + 1];

		if (ch0 == '\r' && ch1 == '\n') {
			// return the line, removing the \r\n
			s->p[n] = 0;
			*pline = s->p;
			*pnext = n + 2;
			return AUTH_OK;
		}
		// only ASCII non control characters are allowed
		if (ch0 < 0 || ch0 < ' ' || ch0 > '~') {
			return AUTH_ERROR;
		}
		n++;
	}
}

static void remove_data(buf_t *s, int off)
{
	memmove(s->p, s->p + off, s->len - off);
	s->len -= off;
}

enum auth_phase {
	AUTH_WAIT_FOR_NUL = 0,
	AUTH_WAIT_FOR_AUTH,
	AUTH_WAIT_FOR_BEGIN,
	AUTH_WAIT_FOR_HELLO,
};

int step_server_auth(buf_t *in, buf_t *out, slice_t busid, slice_t unique_addr,
		     uint32_t *pserial)
{
	// pserial is used as both a state variable and to hold the input
	// message serial when we are done
	int remove = 0;

	switch (*pserial) {
	case AUTH_WAIT_FOR_NUL:
		if (!in->len) {
			return AUTH_READ_MORE;
		}
		if (in->p[0]) {
			return AUTH_ERROR;
		}
		remove = 1;
		goto wait_for_auth;

	wait_for_auth:
	case AUTH_WAIT_FOR_AUTH: {
		*pserial = AUTH_WAIT_FOR_AUTH;
		remove_data(in, remove);

		char *arg0;
		int err = split_line(in, &arg0, &remove);
		if (err) {
			return err;
		}
		char *arg1 = split_after_space(arg0);
		char *arg2 = split_after_space(arg1);

		if (strcmp(arg0, "AUTH")) {
			// unknown command
			if (buf_add(out, S("ERROR\r\n"))) {
				return AUTH_ERROR;
			}
			goto wait_for_auth;
		}

		if (strcmp(arg1, "EXTERNAL")) {
			// unsupported auth type
			if (buf_add(out, S("REJECTED EXTERNAL\r\n"))) {
				return AUTH_ERROR;
			}
			goto wait_for_auth;
		}

		// for now ignore the argument
		(void)arg2;
		if (buf_addf(out, "OK %.*s\r\n", busid.len, busid.p)) {
			return AUTH_ERROR;
		}
		goto wait_for_begin;
	}

	wait_for_begin:
	case AUTH_WAIT_FOR_BEGIN: {
		*pserial = AUTH_WAIT_FOR_BEGIN;
		remove_data(in, remove);

		char *line;
		int err = split_line(in, &line, &remove);
		if (err) {
			return err;

		} else if (!strcmp(line, "BEGIN")) {
			goto wait_for_hello;

		} else if (!strcmp(line, "NEGOTIATE_UNIX_FD")) {
			if (buf_add(out, S("AGREE_UNIX_FD\r\n"))) {
				return AUTH_ERROR;
			}
			goto wait_for_begin;

		} else {
			if (buf_add(out, S("ERROR\r\n"))) {
				return AUTH_ERROR;
			}
			goto wait_for_begin;
		}
	}

	wait_for_hello:
	case AUTH_WAIT_FOR_HELLO: {
		*pserial = AUTH_WAIT_FOR_HELLO;
		remove_data(in, remove);

		if (out->len) {
			// we shouldn't have any pending send data at this point
			// as the remote should have consumed everything before
			// sending BEGIN
			return AUTH_ERROR;
		}

		struct message msg;

		// process the Hello header

		int hsz = parse_header_size(to_slice(*in));
		if (hsz < 0 || hsz > in->cap) {
			return AUTH_ERROR;
		} else if (!hsz) {
			return AUTH_READ_MORE;
		}

		// verify the fields

		if (parse_header(&msg, to_slice(*in)) || msg.body_len ||
		    !msg.serial || msg.type != MSG_METHOD ||
		    !slice_eq(msg.destination, S("org.freedesktop.DBus")) ||
		    !slice_eq(msg.path, S("/org/freedesktop/DBus")) ||
		    !slice_eq(msg.interface, S("org.freedesktop.DBus")) ||
		    !slice_eq(msg.member, S("Hello")) || msg.signature[0]) {
			return AUTH_ERROR;
		}

		remove_data(in, hsz);
		*pserial = msg.serial;
		return AUTH_OK;
	}
	}

	return AUTH_ERROR;
}