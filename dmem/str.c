#include "str.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

int buf_add(buf_t *s, slice_t src)
{
	int sn = src.len;
	if (s->len + sn > s->cap) {
		sn = s->cap - s->len;
	}
	memcpy(s->p + s->len, src.p, sn);
	s->len += sn;
	return s->len == s->cap;
}

int buf_vaddf(buf_t *s, const char *fmt, va_list ap)
{
	// snprintf takes the buffer size as input (incl nul)
	// and returns the string size as output (excl nul)
	int bufsz = s->cap - s->len;
	int n = vsnprintf(s->p + s->len, bufsz, fmt, ap);
	va_end(ap);
	if (n < 0) {
		return -1;
	} else if (n >= bufsz) {
		s->len = s->cap;
		return 1;
	} else {
		s->len += n;
		return 0;
	}
}

int buf_addf(buf_t *s, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int ret = buf_vaddf(s, fmt, ap);
	va_end(ap);
	return ret;
}
