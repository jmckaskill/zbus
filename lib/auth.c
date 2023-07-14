#include "auth.h"
#include "log.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static char *split_first_space(char *line)
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

static void writev(int fd, const char *format, ...)
{
	char buf[256];
	va_list ap;
	va_start(ap, format);
	int n = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	if (2 < n && n < sizeof(buf)) {
		dlog("write auth: '%.*s'", n - 2, buf);
		write(fd, buf, n);
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

int perform_auth(struct stream *in, int out, const char *busid)
{
	// first read the credentials nul
	if (read_char(in) != 0) {
		return -1;
	}

	// the auth portion
	// we look for AUTH EXTERNAL xxxx that we like
	// ends with us sending OK <busid>
	for (;;) {
		char *arg0 = read_crlf_line(in);
		if (!arg0) {
			return -1;
		}
		char *arg1 = split_first_space(arg0);
		char *arg2 = split_first_space(arg1);
		if (strcmp(arg0, "AUTH")) {
			// unknown command
			writes(out, "ERROR\r\n");
		} else if (strcmp(arg1, "EXTERNAL")) {
			// unsupported auth type
			writes(out, "REJECTED EXTERNAL\r\n");
		} else {
			// for now ignore the argument
			(void)arg2;
			writev(out, "OK %s\r\n", busid);
			break;
		}
	}

	// now the post auth portion
	// finishes with the client sending BEGIN
	for (;;) {
		char *line = read_crlf_line(in);
		if (!strcmp(line, "BEGIN")) {
			return 0;
		} else if (!strcmp(line, "NEGOTIATE_UNIX_FD")) {
			writes(out, "AGREE_UNIX_FD\r\n");
		} else {
			writes(out, "ERROR\r\n");
		}
	}
}
