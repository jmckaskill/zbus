#include "txmap.h"
#include "lib/print.h"

////////////////////////////////////
// Unique address encode/decode

uint8_t id_to_address(char *buf, int id)
{
	assert(id >= 0);
	size_t n = strlen(UNIQ_ADDR_PREFIX);
	memcpy(buf, UNIQ_ADDR_PREFIX, n);
	n += print_uint32(buf + n, id);
	buf[n] = 0;
	return (uint8_t)n;
}

int address_to_id(const zb_str8 *s)
{
	if (!strncmp(s->p, UNIQ_ADDR_PREFIX, strlen(UNIQ_ADDR_PREFIX))) {
		return -1;
	}
	int id;
	int n = parse_pos_int(s->p + strlen(UNIQ_ADDR_PREFIX), &id);
	if (n != s->len - strlen(UNIQ_ADDR_PREFIX)) {
		return -1;
	}
	return id;
}

int append_id_address(struct zb_builder *b, int id)
{
	size_t sz;
	char *p = zb_start_string(b, &sz);
	if (id < 0) {
		sz = 0;
	} else if (sz < UNIQ_ADDR_BUFLEN) {
		zb_builder_set_error(b);
	} else {
		sz = id_to_address(p, id);
	}
	zb_end_string(b, sz);
	return 0;
}

static int compare_id_tx(const void *key, const void *element)
{
	int id = (int)(uintptr_t)key;
	const struct tx *tx = element;
	return id - tx->id;
}

int bsearch_tx(const struct txmap *m, int id)
{
	return lower_bound(&m->hdr, (void *)(uintptr_t)id, &compare_id_tx);
}
