#include "rcu.h"
#include "dmem/vector.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#define NOT_IN_USE 0
#define DISABLE_GC 2
#define VALID_FLAG 1
#define VERSION_STEP 2

#define ROOT_NEXT_FLAG 1

struct rcu_reader {
	alignas(CACHE_LINE_SIZE) atomic_uint version;
	_Atomic(struct rcu_object *) *root;
};

static_assert(sizeof(struct rcu_reader) == CACHE_LINE_SIZE, "");

void *rcu_lock(struct rcu_reader *r)
{
	atomic_store_explicit(&r->version, DISABLE_GC, memory_order_release);
	struct rcu_object *d =
		atomic_load_explicit(r->root, memory_order_acquire);
	// Then once we have the data pointer, bring our version forward
	atomic_store_explicit(&r->version, d ? d->version : NOT_IN_USE,
			      memory_order_release);
	return d;
}

void rcu_unlock(struct rcu_reader *r)
{
	atomic_store_explicit(&r->version, NOT_IN_USE, memory_order_release);
}

DVECTOR_INIT(rcu_reader, struct rcu_reader *);

struct rcu_writer {
	d_vector(rcu_reader) readers;
	unsigned version;
	struct rcu_object *collect_oldest;
	struct rcu_object *collect_newest;

	alignas(CACHE_LINE_SIZE) _Atomic(struct rcu_object *) root;
};

static_assert(sizeof(struct rcu_writer) == 2 * CACHE_LINE_SIZE, "");

static inline struct rcu_object *get_root(struct rcu_writer *w)
{
	return atomic_load_explicit(&w->root, memory_order_relaxed);
}

static void do_collect(struct rcu_writer *w, struct rcu_object *o)
{
	if (o) {
		if (w->collect_newest) {
			w->collect_newest->next = o;
		} else {
			w->collect_oldest = o;
		}
		w->collect_newest = o;
		o->next = NULL;
		o->version = w->version;
	}
}

void rcu_collect(struct rcu_writer *w, void *p, rcu_free_fn free)
{
	// Ignore collecting the root. That will be collected in rcu_update
	struct rcu_object *o = p;
	if (o && o != get_root(w)) {
		o->free = free;
		do_collect(w, o);
	}
}

static void run_gc(struct rcu_writer *w, unsigned tgt_version)
{
	struct rcu_object *o = w->collect_oldest;

	while (o && (int)(tgt_version - o->version) >= 0) {
		struct rcu_object *next = o->next;
		if (o->free) {
			o->free(o);
		}
		o = next;
	}
	w->collect_oldest = o;
	if (!o) {
		w->collect_newest = NULL;
	}
}

struct rcu_writer *new_rcu_writer()
{
	struct rcu_writer *w = aligned_alloc(CACHE_LINE_SIZE, sizeof(*w));
	if (w) {
		dv_init(&w->readers);
		w->version = VALID_FLAG;
		w->collect_newest = NULL;
		w->collect_oldest = NULL;
		atomic_store_explicit(&w->root, NULL, memory_order_relaxed);
	}
	return w;
}

void free_rcu_writer(struct rcu_writer *w)
{
	if (w) {
		assert(w->readers.size == 0);
		do_collect(w, get_root(w));
		run_gc(w, w->version);
		dv_free(w->readers);
		free(w);
	}
}

struct rcu_reader *new_rcu_reader(struct rcu_writer *w)
{
	if (!w) {
		return NULL;
	}
	struct rcu_reader *r = aligned_alloc(CACHE_LINE_SIZE, sizeof(*r));
	if (r) {
		dv_append1(&w->readers, r);
		atomic_store_explicit(&r->version, NOT_IN_USE,
				      memory_order_relaxed);
		r->root = &w->root;
	}
	return r;
}

void free_rcu_reader(struct rcu_writer *w, struct rcu_reader *r)
{
	if (r) {
		dv_remove(&w->readers, r);
		free(r);
	}
}

void *rcu_root(struct rcu_writer *w)
{
	return get_root(w);
}

void rcu_update(struct rcu_writer *w, void *p, rcu_free_fn free)
{
	struct rcu_object *d = p;

	// Collect the old root. This will be free'd when we run the GC later.
	do_collect(w, get_root(w));

	// release the new data to the readers
	w->version += VERSION_STEP;
	d->version = w->version;
	d->free = free;
	atomic_store_explicit(&w->root, d, memory_order_release);

	// find the oldest version in active use
	unsigned version = w->version;
	for (int i = 0; i < w->readers.size; i++) {
		struct rcu_reader *r = w->readers.data[i];
		unsigned v =
			atomic_load_explicit(&r->version, memory_order_relaxed);
		if ((v & VALID_FLAG) && (int)(version - v) > 0) {
			version = v;
		} else if (v == DISABLE_GC) {
			return;
		}
	}

	// free everything before that point
	run_gc(w, version - VERSION_STEP);
}
