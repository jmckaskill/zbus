#include "addr.h"
#include "sub.h"
#include "rcu.h"
#include "busmsg.h"
#include "lib/algo.h"
#include "lib/log.h"
#include <limits.h>
#include <string.h>

///////////////////////////
// address data management

static inline void collect_address(struct rcu_object **objs, struct address *a)
{
	rcu_register_gc(objs, (rcu_fn)&free, &a->rcu);
}

struct address *new_address(const str8_t *name)
{
	struct address *a = fmalloc(sizeof(*a) + name->len);
	memset(a, 0, sizeof(*a));
	str8cpy(&a->name, name);
	return a;
}

struct address *edit_address(struct rcu_object **objs, const struct address *oa)
{
	struct address *na = fmalloc(sizeof(*na) + oa->name.len);
	memcpy(na, oa, sizeof(*oa) + oa->name.len);
	collect_address(objs, oa);
	return na;
}

static void copy_config(struct address *na, const struct address *oa)
{
	na->activatable = oa ? oa->activatable : false;
}

///////////////////////////////////
// lookup

static int cmp_slice_address(const void *key, const void *element)
{
	const str8_t *k = key;
	const struct address *a = element;
	return str8cmp(k, &a->name);
}

int bsearch_address(const struct addrmap *m, const str8_t *name)
{
	return lower_bound(&m->hdr, name, &cmp_slice_address);
}

///////////////////////////////////
// config updates

static int cmp_node_address(CRBNode *n, const struct addrmap *m, int idx)
{
	// treat the end condition for each list as equivalent to an infinitely
	// large value
	if (n == NULL) {
		// equiv to INF - x
		return 1;
	} else if (idx == vector_len(&m->hdr)) {
		// equiv to x - INF
		return -1;
	} else {
		struct address *an = node_to_addr(n);
		const struct address *am = m->v[idx];
		return str8cmp(&an->name, &am->name);
	}
}

static int new_merged_size(const struct addrmap *om, CRBTree *t)
{
	// first figure out how big the new map is going to be
	int oidx = 0;
	int nlen = 0;
	int olen = vector_len(&om->hdr);
	CRBNode *n = c_rbtree_first(t);
	while (n != NULL || oidx < olen) {
		int cmp = cmp_node_address(n, om, oidx);
		if (cmp < 0) {
			// only in new config
			nlen++;
			n = c_rbnode_next(n);
		} else if (cmp > 0) {
			// only in old config
			const struct address *a = om->v[oidx];
			if (a->tx || a->subs) {
				// keep addresses that are otherwise in use
				nlen++;
			}
			oidx++;
		} else {
			// in new and old config
			nlen++;
			oidx++;
			n = c_rbnode_next(n);
		}
	}
	return nlen;
}

struct addrmap *merge_addresses(struct rcu_object **objs,
				const struct addrmap *om, CRBTree *t)
{
	int nlen = new_merged_size(om, t);
	int olen = vector_len(&om->hdr);
	int nidx = 0;
	int oidx = 0;
	CRBNode *n = c_rbtree_first(t);

	struct addrmap *nm = edit_addrmap(objs, om, 0, nlen - olen);

	while (n != NULL || oidx < olen) {
		int cmp = cmp_node_address(n, om, oidx);
		if (cmp < 0) {
			// only in new config
			struct address *na = node_to_addr(n);
			nm->v[nidx++] = na;
			n = c_rbnode_next(n);

		} else if (cmp > 0) {
			// only in old config, keep if in use, but reset the
			// configuration to defaults
			const struct address *oa = om->v[oidx];

			// there has to be a reason why this address exists
			assert(oa->in_config || oa->tx || oa->subs);

			if (oa->in_config && !oa->tx && !oa->subs) {
				// was in the config previously and not in use
				collect_address(objs, oa);

			} else if (oa->in_config) {
				// was in the config previously and is in use,
				// reset config to defaults
				struct address *na = edit_address(objs, oa);
				copy_config(na, NULL);
				nm->v[nidx++] = na;
			} else {
				// was not in the config previously, leave as is
				nm->v[nidx++] = oa;
			}
			oidx++;
		} else {
			// in old and new. Use the node address in the RCU
			// vector, but copy all the non-config items over.
			const struct address *oa = om->v[oidx];
			struct address *na = node_to_addr(n);

			struct address tmp;
			copy_config(&tmp, na);
			memcpy(na, oa, sizeof(*na));
			copy_config(na, &tmp);

			collect_address(objs, oa);
			nm->v[nidx++] = na;

			oidx++;
			n = c_rbnode_next(n);
		}
	}
	assert(nidx == nlen);
	return nm;
}
