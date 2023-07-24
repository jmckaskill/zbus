#include "log.h"
#include "str.h"
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <threads.h>
#include <unistd.h>

int log_verbose = 0;
int log_quiet = 0;

void log_vfmt(enum log_level lvl, const char *fmt, va_list ap)
{
	static const slice_t levels[] = {
		SLICE_INIT("ERROR "),
		SLICE_INIT(""),
		SLICE_INIT("DBG "),
	};
	char buf[256];
	buf_t s = MAKE_BUF(buf);
	buf_add(&s, levels[lvl]);
	buf_vaddf(&s, fmt, ap);
	if (s.len && s.p[s.len - 1] != '\n') {
		buf_addch(&s, '\n');
	}
	write(2, s.p, s.len);
}

int log_fmt(enum log_level lvl, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_vfmt(lvl, fmt, ap);
	va_end(ap);
	return 0;
}

static char ascii(unsigned char ch)
{
	return (' ' <= ch && ch <= '~') ? ch : '.';
}

int log_data(slice_t data, const char *fmt, ...)
{
	size_t lines = (data.len + 7U) / 8U;
	size_t hexlen = 4 + 8 + 1 + 8;
	size_t asclen = 4 + 4 + 1 + 4;
	size_t uintlen = 4 + 10 + 1 + 10 + 1;
	size_t linelen = hexlen + asclen + uintlen;
	size_t bufsz = lines * linelen + 256;
	buf_t s = make_buf(malloc(bufsz), bufsz);

	// print the header line
	buf_add(&s, S("DBG "));
	va_list ap;
	va_start(ap, fmt);
	buf_vaddf(&s, fmt, ap);
	va_end(ap);
	buf_addch(&s, '\n');

	// print full 8 byte chunks
	const unsigned char *u = (uint8_t *)data.p;
	int len = data.len;
	while (len >= 8) {
		buf_addf(&s,
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
	// print the tail
	if (len) {
		char val[8];
		memcpy(&val, u, len);
		// use the fact that sprintf ignores extra arguments to make
		// printing the tail a bit simpler
		const char *hexfmt, *ascfmt, *uintfmt = "\n";
		switch (len) {
		case 1:
			hexfmt = "    %02x               ";
			ascfmt = "    %c";
			break;
		case 2:
			hexfmt = "    %02x%02x             ";
			ascfmt = "    %c%c";
			break;

		case 3:
			hexfmt = "    %02x%02x%02x           ";
			ascfmt = "    %c%c%c\n";
			break;
		case 4:
			hexfmt = "    %02x%02x%02x%02x         ";
			ascfmt = "    %c%c%c%c     ";
			uintfmt = "    %10u\n";
			break;
		case 5:
			hexfmt = "    %02x%02x%02x%02x %02x      ";
			ascfmt = "    %c%c%c%c %c   ";
			uintfmt = "    %10u\n";
			break;
		case 6:
			hexfmt = "    %02x%02x%02x%02x %02x%02x    ";
			ascfmt = "    %c%c%c%c %c%c  ";
			uintfmt = "    %10u\n";
			break;
		case 7:
			hexfmt = "    %02x%02x%02x%02x %02x%02x%02x  ";
			ascfmt = "    %c%c%c%c %c%c%c ";
			uintfmt = "    %10u\n";
			break;
		}
		buf_addf(&s, hexfmt, u[0], u[1], u[2], u[3], u[4], u[5], u[6],
			 u[7]);
		buf_addf(&s, ascfmt, ascii(u[0]), ascii(u[1]), ascii(u[2]),
			 ascii(u[3]), ascii(u[4]), ascii(u[5]), ascii(u[6]),
			 ascii(u[7]));
		buf_addf(&s, uintfmt, *(uint32_t *)u, *(uint32_t *)(u + 4));
	}

	write(2, s.p, s.len);
	free(s.p);
	return 0;
}
