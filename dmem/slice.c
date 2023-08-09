#include "slice.h"

int split_slice(slice_t src, char sep, slice_t *pleft, slice_t *prest)
{
	char *p = memchr(src.p, sep, src.len);
	if (!p) {
		return -1;
	}
	pleft->p = src.p;
	pleft->len = p - src.p;
	prest->p = p + 1;
	prest->len = src.len - pleft->len - 1;
	return 0;
}
