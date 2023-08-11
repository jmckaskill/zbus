#pragma once
#include "config.h"
#include "rcu.h"
#include "tx.h"
#include "vector.h"
#include "sec.h"
#include "lib/khash.h"
#include "dbus/types.h"
#include "dbus/str8.h"
#include "vendor/c-rbtree-3.1.0/src/c-rbtree.h"
#include <limits.h>
#include <time.h>

struct address {
	struct rcu_object rcu;
	struct CRBNode rb;
	struct submap *subs;
	// tx ptr is stored here, but doesn't contain a ref. This is not needed
	// as it's covered by the ref in the txmap.
	struct tx *tx;
	bool in_config;
#ifdef HAVE_AUTOLAUNCH
	time_t last_launch;
	bool running;
	bool activatable;
#endif
#ifdef HAVE_GID
	// for destinations, who can own it
	// for interfaces, who can publish to it
	int gid_owner;
	// for destinations, who can subscribe or communicate to the address
	// for interfaces, who can subscribe to it
	int gid_access;
#endif
	str8_t name;
};

struct addrmap {
	struct vector hdr;
	const struct address *v[0];
};

struct address *new_address(const str8_t *name);
struct address *edit_address(struct rcu_object **objs,
			     const struct address *oa);

static struct addrmap *edit_addrmap(struct rcu_object **objs,
				    const struct addrmap *om, int idx,
				    int insert);
int bsearch_address(const struct addrmap *m, const str8_t *name);

// merge_addresses merges the address in the tree into the addrmap updating
// it in the process. All address in the tree are consumed.
struct addrmap *merge_addresses(struct rcu_object **objs,
				const struct addrmap *om, CRBTree *t);

//////////////////////////////
// inline implementations

static inline void free_address(struct address *a)
{
	free(a);
}

static inline struct addrmap *edit_addrmap(struct rcu_object **objs,
					   const struct addrmap *om, int idx,
					   int insert)
{
	struct vector *v = edit_vector(objs, &om->hdr, idx, insert);
	return container_of(v, struct addrmap, hdr);
}

static inline struct address *node_to_addr(CRBNode *n)
{
	return container_of(n, struct address, rb);
}
