#pragma once
#include "vector.h"
#include "tx.h"

struct txmap {
	struct vector hdr;
	struct tx *v[0];
};

int bsearch_tx(const struct txmap *m, int id);

#define UNIQ_ADDR_PREFIX ":1."
#define UNIQ_ADDR_BUFLEN sizeof(":1.4294967296")

// buffer must be at least UNIX_ADDR_MAXLEN long
// this does not nul terminate the string
size_t id_to_address(char *buf, int id);
int address_to_id(const str8_t *s);
int append_id_address(struct builder *b, int id);

//////////////////////////////////
// inline

static inline struct txmap *edit_txmap(struct rcu_object **objs,
				       const struct txmap *om, int idx,
				       int insert)
{
	struct vector *v = edit_vector(objs, &om->hdr, idx, insert);
	return container_of(v, struct txmap, hdr);
}
