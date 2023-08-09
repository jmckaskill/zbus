#pragma once
#include <stdatomic.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdalign.h>

#define CACHE_LINE_SIZE 64

struct rcu_reader;
struct rcu_writer;
struct rcu_object;

typedef void (*rcu_fn)(struct rcu_object *);

// Header for objects that need to be collected with the RCU garbage collector.
// Should be at the start of the allocated structure.
struct rcu_object {
	unsigned version;
	struct rcu_object *next;
	rcu_fn fn;
};

const void *rcu_lock(struct rcu_reader *h);
void rcu_unlock(struct rcu_reader *h);

struct rcu_writer *new_rcu_writer(void);
void free_rcu_writer(struct rcu_writer *r);

const void *rcu_root(struct rcu_writer *w);
void rcu_commit(struct rcu_writer *w, void *p, struct rcu_object *objs);

struct rcu_reader *new_rcu_reader(struct rcu_writer *w);
void free_rcu_reader(struct rcu_writer *w, struct rcu_reader *r);

static inline void rcu_register_gc(struct rcu_object **list, rcu_fn fn,
				   const struct rcu_object *o)
{
	struct rcu_object *m = (struct rcu_object *)o;
	m->next = *list;
	m->fn = fn;
	*list = m;
}
