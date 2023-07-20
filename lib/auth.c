#include "auth.h"
#include "log.h"
#include "message.h"
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

static int split_line(str_t *s, char **pline, int *pnext)
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
			return 1;
		}
		// only ASCII non control characters are allowed
		if (ch0 < 0 || ch0 < ' ' || ch0 > '~') {
			return AUTH_ERROR;
		}
		n++;
	}
}

static void remove_data(str_t *s, int off)
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

int step_server_auth(str_t *in, str_t *out, slice_t busid, slice_t unique_addr,
		     int *pstate)
{
	int remove = 0;

	switch (*pstate) {
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
		*pstate = AUTH_WAIT_FOR_AUTH;
		remove_data(in, remove);

		char *arg0;
		int sts = split_line(in, &arg0, &remove);
		if (sts <= 0) {
			return sts;
		}
		char *arg1 = split_after_space(arg0);
		char *arg2 = split_after_space(arg1);

		if (strcmp(arg0, "AUTH")) {
			// unknown command
			if (str_add(out, "ERROR\r\n")) {
				return AUTH_ERROR;
			}
			goto wait_for_auth;
		}

		if (strcmp(arg1, "EXTERNAL")) {
			// unsupported auth type
			if (str_add(out, "REJECTED EXTERNAL\r\n")) {
				return AUTH_ERROR;
			}
			goto wait_for_auth;
		}

		// for now ignore the argument
		(void)arg2;
		if (str_addf(out, "OK %.*s\r\n", busid.len, busid.p)) {
			return AUTH_ERROR;
		}
		goto wait_for_begin;
	}

	wait_for_begin:
	case AUTH_WAIT_FOR_BEGIN: {
		*pstate = AUTH_WAIT_FOR_BEGIN;
		remove_data(in, remove);

		char *line;
		int sts = split_line(in, &line, &remove);
		if (sts <= 0) {
			return sts;
		}

		if (!strcmp(line, "BEGIN")) {
			remove_data(in, remove);
			goto wait_for_hello;

		} else if (!strcmp(line, "NEGOTIATE_UNIX_FD")) {
			if (str_add(out, "AGREE_UNIX_FD\r\n")) {
				return AUTH_ERROR;
			}
			goto wait_for_begin;

		} else {
			if (str_add(out, "ERROR\r\n")) {
				return AUTH_ERROR;
			}
			goto wait_for_begin;
		}
	}

	wait_for_hello:
	case AUTH_WAIT_FOR_HELLO: {
		*pstate = AUTH_WAIT_FOR_HELLO;
		if (out->len) {
			// we shouldn't have any pending send data at this point
			// as the remote should have consumed everything before
			// sending BEGIN
			return AUTH_ERROR;
		}
		if (in->len < MIN_MESSAGE_SIZE) {
			return AUTH_READ_MORE;
		}

		// copy the input str as parse_header & parse_message
		// modify the str as they consume it
		str_t s[2];
		s[0] = *in;
		s[1].p = NULL;
		s[1].len = 0;
		s[1].cap = 0;

		struct message msg;
		int msgsz = parse_header(&msg, s);
		if (in->len < msgsz) {
			return AUTH_READ_MORE;
		}
		if (parse_message(&msg, s)) {
			return AUTH_ERROR;
		}
		if (!msg.serial || msg.type != MSG_METHOD ||
		    !slice_eq(msg.destination, "org.freedesktop.DBus") ||
		    !slice_eq(msg.interface, "org.freedesktop.DBus") ||
		    !slice_eq(msg.member, "Hello")) {
			return AUTH_ERROR;
		}

		struct message reply;
		init_message(&reply, MSG_REPLY, 1);
		reply.sender = MAKE_SLICE("org.freedesktop.DBus");
		reply.reply_serial = msg.serial;
		reply.signature = "s";

		struct builder b = start_message(&reply, out->p, out->cap);
		append_string(&b, unique_addr);
		int sz = end_message(b);
		if (sz < 0) {
			return AUTH_ERROR;
		}

		out->len = sz;
		return msgsz;
	}
	}

	return AUTH_ERROR;
}