#include "txmap.h"

////////////////////////////////////
// Unique address encode/decode

size_t id_to_address(char *buf, int id)
{
	assert(id >= 0);
	size_t pfxlen = strlen(UNIQ_ADDR_PREFIX);
	memcpy(buf, UNIQ_ADDR_PREFIX, pfxlen);
	char *p = buf + UNIQ_ADDR_BUFLEN - 1;
	do {
		*(--p) = (id % 10) + '0';
		id /= 10;
	} while (id);
	size_t n = buf + UNIQ_ADDR_BUFLEN - 1 - p;
	memmove(buf + pfxlen, p, n);
	buf[pfxlen + n] = 0;
	return pfxlen + n;
}

int address_to_id(const str8_t *s)
{
	const char *p = s->p + strlen(UNIQ_ADDR_PREFIX);
	int len = s->len - strlen(UNIQ_ADDR_PREFIX);
	int id = 0;
	for (int i = 0; i < len; i++) {
		char start = (i || len == 1) ? '0' : '1';
		if (p[i] < start || p[i] > '9' || id >= (INT_MAX / 10)) {
			return -1;
		}
		id = (id * 10) | (p[i] - '0');
	}
	return id;
}

int append_id_address(struct builder *b, int id)
{
	size_t sz;
	char *p = start_string(b, &sz);
	if (id < 0) {
		sz = 0;
	} else if (sz < UNIQ_ADDR_BUFLEN) {
		builder_set_error(b);
	} else {
		sz = id_to_address(p, id);
	}
	finish_string(b, sz);
	return 0;
}

static int compare_id_tx(const void *key, const void *element)
{
	int id = (uintptr_t)key;
	const struct tx *tx = element;
	return id - tx->id;
}

int bsearch_tx(const struct txmap *m, int id)
{
	return lower_bound(&m->hdr, (void *)(uintptr_t)id, &compare_id_tx);
}
