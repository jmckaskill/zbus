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

static void reset_config(struct address *a)
{
	// freeing adresses is serialized by the bus lock so don't need
	// atomics here
	if (a->cfg && --a->cfg->ref == 0) {
#if CAN_AUTOSTART
		free(a->cfg->exec);
#endif
		free(a->cfg);
	}
	a->cfg = NULL;
}

void free_address(struct address *a)
{
	if (a) {
		reset_config(a);
		free(a);
	}
}

void collect_address(struct rcu_object **objs, const struct address *a)
{
	static_assert(offsetof(struct address, rcu) == 0, "");
	rcu_register_gc(objs, (rcu_fn)&free_address, &a->rcu);
}

struct address *new_address(const zb_str8 *name)
{
	struct address *a = fmalloc(sizeof(*a) + name->len);
	memset(a, 0, sizeof(*a));
	zb_copy_str8(&a->name, name);
	reset_config(a);
	return a;
}

struct address *edit_address(struct rcu_object **objs, const struct address *oa)
{
	struct address *na = fmalloc(sizeof(*na) + oa->name.len);
	memcpy(na, oa, sizeof(*oa) + oa->name.len);
	if (na->cfg) {
		na->cfg->ref++;
	}
	collect_address(objs, oa);
	return na;
}

static struct addrcfg *new_addrcfg(void)
{
	struct addrcfg *c = fmalloc(sizeof(*c));
	c->ref = 1;
#if CAN_AUTOSTART
	c->exec = NULL;
#endif
#if HAVE_UNIX_GROUPS
	// if the config file doesn't specify a group, these will be
	// overwritten by the default access when we merge the config
	// into the RCU data
	c->gid_access = GROUP_UNKNOWN;
	c->gid_owner = GROUP_UNKNOWN;
#endif
	return c;
}

///////////////////////////////////
// lookup

static int cmp_slice_address(const void *key, const void *element)
{
	const zb_str8 *k = key;
	const struct address *a = element;
	return zb_cmp_str8(k, &a->name);
}

int bsearch_address(const struct addrmap *m, const zb_str8 *name)
{
	return lower_bound(&m->hdr, name, &cmp_slice_address);
}

///////////////////////////////////
// config updates

static int cmp_str8_addresss_node(CRBTree *t, void *k, CRBNode *n)
{
	zb_str8 *key = k;
	struct address *a = node_to_addr(n);
	return zb_cmp_str8(key, &a->name);
}

struct address *insert_addrtree(struct addrtree *t, const zb_str8 *name)
{
	CRBNode *p;
	CRBNode **l =
		c_rbtree_find_slot(&t->tree, &cmp_str8_addresss_node, name, &p);
	if (l) {
		t->len++;
		struct address *a = new_address(name);
		a->cfg = new_addrcfg();
		c_rbtree_add(&t->tree, p, l, &a->rb);
		return a;
	} else {
		return node_to_addr(p);
	}
}

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
		return zb_cmp_str8(&an->name, &am->name);
	}
}

static int new_merged_size(const struct addrmap *om, struct addrtree *t)
{
	// first figure out how big the new map is going to be
	int oidx = 0;
	int nlen = 0;
	int olen = vector_len(&om->hdr);
	CRBNode *n = c_rbtree_first(&t->tree);
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

static void set_default_group(struct addrcfg *c, int defgroup)
{
#if HAVE_UNIX_GROUPS
	if (c->gid_access == GROUP_UNKNOWN) {
		c->gid_access = defgroup;
	}
	if (c->gid_owner == GROUP_UNKNOWN) {
		c->gid_owner = defgroup;
	}
#endif
}

struct addrmap *merge_addresses(struct rcu_object **objs,
				struct rcu_object **released,
				const struct addrmap *om, struct addrtree *t,
				bool allow_unknown)
{
	int defgroup = allow_unknown ? GROUP_ANY : GROUP_NOBODY;
	int nlen = allow_unknown ? new_merged_size(om, t) : t->len;
	int olen = vector_len(&om->hdr);
	int nidx = 0;
	int oidx = 0;
	CRBNode *n = c_rbtree_first(&t->tree);

	struct addrmap *nm = edit_addrmap(objs, om, 0, nlen - olen);

	while (n != NULL || oidx < olen) {
		int cmp = cmp_node_address(n, om, oidx);
		if (cmp < 0) {
			// only in new config
			struct address *na = node_to_addr(n);
			set_default_group(na->cfg, defgroup);
			nm->v[nidx++] = na;
			n = c_rbnode_next(n);

		} else if (cmp > 0) {
			// only in old map, keep if in use, but reset the
			// configuration to defaults
			const struct address *oa = om->v[oidx];

			// there has to be a reason why this address exists
			assert(oa->cfg || oa->tx || oa->subs);

			if (!allow_unknown || (!oa->tx && !oa->subs)) {
				// No longer need this address. Add this to the
				// release list so we can notify remotes.
				collect_address(released, oa);
			} else if (oa->cfg) {
				// was in the config previously and is in use,
				// reset config to defaults
				struct address *na = edit_address(objs, oa);
				reset_config(na);
				nm->v[nidx++] = na;
			} else {
				// not in the config previously and still in
				// use, keep the old
				nm->v[nidx++] = oa;
			}

			oidx++;
		} else {
			// in old and new. Use the node address in the RCU
			// vector, but copy all the non-config items over.
			const struct address *oa = om->v[oidx];
			struct address *na = node_to_addr(n);

			struct addrcfg *cfg = na->cfg;
			set_default_group(cfg, defgroup);

			// do not increment oa->ref so that it gets free'd when
			// oa gets gc'd
			*na = *oa;
			na->cfg = cfg;
			collect_address(objs, oa);
			nm->v[nidx++] = na;

			oidx++;
			n = c_rbnode_next(n);
		}
	}
	assert(nidx == nlen);
	return nm;
}
