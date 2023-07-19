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

static int split_line(str_t *s, char **pline, unsigned *pnext)
{
	unsigned n = 0;
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

static void writes(int fd, const char *str)
{
	size_t sz = strlen(str);
	if (sz > 2) {
		dlog("write auth: '%.*s'", (int)(sz - 2), str);
		write(fd, str, sz);
	}
}

static int peek_byte(int fd, str_t *s, unsigned idx)
{
	if (idx == s->len) {
		if (idx > s->cap) {
			return -1;
		}

	try_again:
		int r = read(fd, s->p + s->len, s->cap - s->len);
		if (r < 0 && errno == EINTR) {
			goto try_again;
		} else if (r <= 0) {
			return -1;
		}

		s->len += r;
	}

	return *(uint8_t *)(s->p + idx);
}

static int read_byte(int fd, str_t *s)
{
	int ch = peek_byte(fd, s, 0);
	if (ch >= 0) {
		memmove(s->p, s->p + 1, s->len - 1);
	}
	return ch;
}

static void remove_data(str_t *s, unsigned off)
{
	memmove(s->p, s->p + off, s->len - off);
	s->len -= off;
}

static int read_line(int fd, str_t *s, char **pline, unsigned *pnext)
{
	unsigned n = 0;

	for (;;) {
		int ch = peek_byte(fd, s, n);
		// look for a terminating \r\n
		if (ch == '\r') {
			if (peek_byte(fd, s, n + 1) != '\n') {
				return -1;
			}
			// return the line, removing the \r\n
			char *line = s->p;
			line[n] = 0;
			*pline = line;
			*pnext = n + 2;
			return 0;
		}
		// only ASCII non control characters are allowed
		if (ch < 0 || ch < ' ' || ch > '~') {
			return -1;
		}
		n++;
	}
}

int perform_auth(int fd, const char *busid, str_t *buf)
{
	// first read the credentials nul
	if (read_byte(fd, buf) != 0) {
		return -1;
	}

	unsigned next = 1;

	// the auth portion
	// we look for AUTH EXTERNAL xxxx that we like
	// ends with us sending OK <busid>
	for (;;) {
		remove_data(buf, next);

		char *arg0;
		if (read_line(fd, buf, &arg0, &next)) {
			return -1;
		}
		char *arg1 = split_after_space(arg0);
		char *arg2 = split_after_space(arg1);
		if (strcmp(arg0, "AUTH")) {
			// unknown command
			writes(fd, "ERROR\r\n");
		} else if (strcmp(arg1, "EXTERNAL")) {
			// unsupported auth type
			writes(fd, "REJECTED EXTERNAL\r\n");
		} else {
			// for now ignore the argument
			(void)arg2;
			char buf[32];
			str_t s = MAKE_STR(buf);
			if (str_addf(&s, "OK %s\r\n", busid)) {
				return -1;
			}
			writes(fd, s.p);
			break;
		}
	}

	// now the post auth portion
	// finishes with the client sending BEGIN
	for (;;) {
		remove_data(buf, next);
		char *line;
		if (read_line(fd, buf, &line, &next)) {
			return -1;
		}

		if (!strcmp(line, "BEGIN")) {
			break;
		} else if (!strcmp(line, "NEGOTIATE_UNIX_FD")) {
			writes(fd, "AGREE_UNIX_FD\r\n");
		} else {
			writes(fd, "ERROR\r\n");
		}
	}

	remove_data(buf, next);
	return 0;
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
	unsigned remove = 0;

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

		struct message msg;
		int msgsz = parse_header(&msg, in->p);
		if (in->len < msgsz) {
			return AUTH_READ_MORE;
		}

		str_t s;
		s.p = in->p;
		s.len = msgsz;
		s.cap = msgsz;
		if (parse_message(&msg, &s)) {
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

		struct buffer b = start_message(&reply, out->p, out->cap);
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