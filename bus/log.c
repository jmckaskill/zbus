#include "log.h"
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

int verbose = 0;

void elog(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

void dlog(const char *fmt, ...)
{
	if (verbose) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fputc('\n', stderr);
	}
}

static char ascii(unsigned char ch)
{
	return (' ' <= ch && ch <= '~') ? ch : '.';
}

void log_data(const void *p, size_t len, const char *fmt, ...)
{
	if (!verbose) {
		return;
	}
	const unsigned char *u = p;
	if (*fmt) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fputc('\n', stderr);
	}
	while (len >= 8) {
		fprintf(stderr,
			"    %02x%02x%02x%02x %02x%02x%02x%02x"
			"    %c%c%c%c %c%c%c%c"
			"    %10u %10u\n",
			u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
			ascii(u[0]), ascii(u[1]), ascii(u[2]), ascii(u[3]),
			ascii(u[4]), ascii(u[5]), ascii(u[6]), ascii(u[7]),
			*(uint32_t *)u, *(uint32_t *)(u + 4));
		u += 8;
		len -= 8;
	}
	if (!len) {
		return;
	}
	fputs("    ", stderr);
	size_t wr = 0;
	for (size_t i = 0; i < len; i++) {
		fprintf(stderr, "%02x", u[i]);
		wr += 2;
		if (i == 3) {
			fputc(' ', stderr);
			wr += 1;
		}
	}
	while (wr < 17) {
		fputc(' ', stderr);
		wr++;
	}
	fputs("    ", stderr);
	wr = 0;
	for (size_t i = 0; i < len; i++) {
		fputc(ascii(u[i]), stderr);
		wr++;
		if (i == 3) {
			fputc(' ', stderr);
			wr++;
		}
	}
	while (wr < 9) {
		fputc(' ', stderr);
		wr++;
	}
	fputs("    ", stderr);
	if (len >= 4) {
		fprintf(stderr, "%10u", *(uint32_t *)u);
	}
	fputc('\n', stderr);
}
