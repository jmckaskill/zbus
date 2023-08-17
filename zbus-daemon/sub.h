#pragma once
#include "config.h"
#include "rcu.h"
#include "tx.h"
#include "vector.h"
#include "match.h"
#include "zbus/zbus.h"

struct subscription {
	union {
		struct rcu_object rcu;
		struct subscription *next;
	} h;
	// tx ptr here does not contain an active ref. This is covered by the
	// ref in the txmap.
	struct tx *tx;
	struct match m;
	uint32_t serial;
	char mstr[1];
};

struct submap {
	struct vector hdr;
	const struct subscription *v[1];
};

struct subscription *new_subscription(const char *mstr, struct match m);

static void free_submap(struct submap *m);
static struct submap *edit_submap(struct rcu_object **objs,
				  const struct submap *om, int idx, int insert);

struct submap *add_subscription(struct rcu_object **objs,
				const struct submap *om, struct tx *tx,
				const char *mstr, struct match match,
				uint32_t serial);

struct submap *rm_subscription(struct rcu_object **objs,
			       const struct submap *om, int idx);

int bsearch_subscription(const struct submap *s, struct tx *tx, const char *str,
			 struct match m);

///////////////////////
// inline
static inline void free_subscription(struct subscription *s)
{
	free(s);
}
static inline void free_submap(struct submap *m)
{
	free_vector(&m->hdr);
}
static inline struct submap *edit_submap(struct rcu_object **objs,
					 const struct submap *om, int idx,
					 int insert)
{
	struct vector *v = edit_vector(objs, &om->hdr, idx, insert);
	return container_of(v, struct submap, hdr);
}
