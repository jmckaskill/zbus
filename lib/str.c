#include "str.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

int str_add(str_t *s, slice_t src)
{
	int sn = src.len;
	if (s->len + sn + 1 > s->cap) {
		sn = s->cap - 1 - s->len;
	}
	memcpy(s->p + s->len, src.p, sn);
	s->len += sn;
	s->p[s->len] = 0;
	return s->len + 1 == s->cap;
}

int str_vaddf(str_t *s, const char *fmt, va_list ap)
{
	// snprintf takes the buffer size as input (incl nul)
	// and returns the string size as output (excl nul)
	int bufsz = s->cap - s->len;
	int n = vsnprintf(s->p + s->len, bufsz, fmt, ap);
	va_end(ap);
	if (n < 0) {
		return -1;
	} else if (n >= bufsz) {
		s->len = s->cap - 1;
		s->p[s->len] = 0;
		return 1;
	} else {
		s->len += n;
		return 0;
	}
}

int str_addf(str_t *s, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int ret = str_vaddf(s, fmt, ap);
	va_end(ap);
	return ret;
}
