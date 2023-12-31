#pragma once
#include "config.h"
#include "rcu.h"
#include "tx.h"
#include "vector.h"
#include "sec.h"
#include "lib/khash.h"
#include "zbus/zbus.h"
#include "vendor/c-rbtree-3.1.0/src/c-rbtree.h"
#include <limits.h>
#include <time.h>

struct addrcfg {
	int ref;

#ifdef HAVE_UNIX_GROUPS
	// for destinations, who can own it
	// for interfaces, who can publish to it
	int gid_owner;
	// for destinations, who can subscribe or communicate to the address
	// for interfaces, who can subscribe to it
	int gid_access;
#endif

#ifdef CAN_AUTOSTART
	char *exec;
#endif
};

struct address {
	struct rcu_object rcu;
	struct CRBNode rb;

	// Addresses must have a non-zero subs, tx, or config
	// They are collected if all three drop off. tx ptr is stored here, but
	// doesn't contain a ref. This is not needed as it's covered by the ref
	// in the txmap.

	struct tx *tx;
	struct submap *subs;
	struct addrcfg *cfg;

#ifdef CAN_AUTOSTART
	struct timespec last_launch;
	bool running;
#endif
	zb_str8 name;
};

struct addrmap {
	struct vector hdr;
	const struct address *v[1];
};

struct addrtree {
	CRBTree tree;
	int len;
};

void free_address(struct address *a);
void collect_address(struct rcu_object **objs, const struct address *a);
struct address *new_address(const zb_str8 *name);
struct address *edit_address(struct rcu_object **objs,
			     const struct address *oa);

static struct addrmap *edit_addrmap(struct rcu_object **objs,
				    const struct addrmap *om, int idx,
				    int insert);
int bsearch_address(const struct addrmap *m, const zb_str8 *name);

// merge_addresses merges the address in the tree into the addrmap updating
// it in the process. All address in the tree are consumed. Removed names are
// kept separate so that we can send out the notifications.
struct addrmap *merge_addresses(struct rcu_object **objs,
				struct rcu_object **removed_names,
				const struct addrmap *om, struct addrtree *t,
				bool allow_unknown);

struct address *insert_addrtree(struct addrtree *t, const zb_str8 *name);

//////////////////////////////
// inline implementations

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
