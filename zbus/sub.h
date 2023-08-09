#pragma once
#include "rcu.h"
#include "tx.h"
#include "vector.h"
#include "dbus/str8.h"
#include "dbus/match.h"

struct subscription {
	union {
		struct rcu_object rcu;
		struct subscription *next;
	} h;
	struct tx *tx;
	struct match m;
	uint32_t serial;
	char mstr[0];
};

struct submap {
	struct vector hdr;
	const struct subscription *v[0];
};

struct subscription *new_subscription(const char *mstr, struct match m);
void free_subscription(struct rcu_object *o);

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
