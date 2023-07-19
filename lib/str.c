#include "str.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

int str_add2(str_t *s, const char *src, int sn)
{
	if (s->len + sn + 1 > s->cap) {
		sn = s->cap - 1 - s->len;
	}
	memcpy(s->p + s->len, src, sn);
	s->len += sn;
	s->p[s->len] = 0;
	return s->len + 1 == s->cap;
}

int str_addf(str_t *s, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(s->p + s->len, s->cap - s->len, fmt, ap);
	va_end(ap);
	if (n < 0) {
		return -1;
	} else if (s->len + n >= s->cap) {
		s->len = s->cap - 1;
		s->p[s->len] = 0;
		return 1;
	} else {
		s->len += n;
		return 0;
	}
}

int str_copy(char *buf, int bufsz, const char *src)
{
	str_t s = make_str(buf, bufsz);
	return str_add(&s, src);
}