#include "types.h"

int compare_string_x(const char *ap, unsigned alen, const char *bp,
		     unsigned blen)
{
	unsigned clen = alen < blen ? alen : blen;
	int c = memcmp(ap, bp, clen);
	return c ? c : ((int)alen - (int)blen);
}

int compare_string_p(const void *ca, const void *cb)
{
	const struct string *a = ca;
	const struct string *b = cb;
	return compare_string_x(a->p, a->len, b->p, b->len);
}
