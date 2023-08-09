#include "rcu.h"
#include "lib/log.h"
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

const void *rcu_lock(struct rcu_reader *r)
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

struct rcu_writer {
	struct {
		size_t n;
		const struct rcu_reader **v;
	} rd;
	unsigned version;
	struct rcu_object *collect_oldest;
	struct rcu_object *collect_newest;

	alignas(CACHE_LINE_SIZE) _Atomic(struct rcu_object *) root;
};

static_assert(sizeof(struct rcu_writer) == 2 * CACHE_LINE_SIZE, "");

static void run_gc(struct rcu_writer *w, unsigned tgt_version);

static inline struct rcu_object *get_root(struct rcu_writer *w)
{
	return atomic_load_explicit(&w->root, memory_order_relaxed);
}

static void *fcache_aligned_alloc(size_t sz)
{
	void *p = aligned_alloc(CACHE_LINE_SIZE, sz);
	if (!p) {
		FATAL("aligned allocation failed");
	}
	return p;
}

struct rcu_writer *new_rcu_writer()
{
	struct rcu_writer *w = fcache_aligned_alloc(sizeof(*w));
	memset(w, 0, sizeof(*w));
	w->version = VALID_FLAG;
	return w;
}

void free_rcu_writer(struct rcu_writer *w)
{
	if (w) {
		assert(!w->rd.n);
		run_gc(w, w->version);
		free(w->rd.v);
		free(w);
	}
}

struct rcu_reader *new_rcu_reader(struct rcu_writer *w)
{
	struct rcu_reader *r = fcache_aligned_alloc(sizeof(*r));
	w->rd.v = frealloc(w->rd.v, (w->rd.n + 1) * sizeof(w->rd.v[0]));
	w->rd.v[w->rd.n++] = r;
	atomic_store_explicit(&r->version, NOT_IN_USE, memory_order_relaxed);
	r->root = &w->root;
	return r;
}

void free_rcu_reader(struct rcu_writer *w, struct rcu_reader *r)
{
	if (r) {
		const struct rcu_reader **v = w->rd.v;
		for (size_t i = 0, n = w->rd.n; i < n; i++) {
			if (v[i] == r) {
				size_t esz = sizeof(w->rd.v[0]);
				memmove(&v[i], &v[i + 1], (n - i - 1) * esz);
				w->rd.n--;
				break;
			}
		}
		free(r);
	}
}

const void *rcu_root(struct rcu_writer *w)
{
	return get_root(w);
}

static void free_list(struct rcu_object *o)
{
	while (o) {
		struct rcu_object *n = o->next;
		o->fn(o);
		o = n;
	}
}

static void collect_list(struct rcu_writer *w, struct rcu_object *o)
{
	while (o) {
		struct rcu_object *n = o->next;
		if (w->collect_newest) {
			w->collect_newest->next = o;
		} else {
			w->collect_oldest = o;
		}
		w->collect_newest = o;
		o->next = NULL;
		o->version = w->version;
		o = n;
	}
}

static void run_gc(struct rcu_writer *w, unsigned tgt_version)
{
	struct rcu_object *o = w->collect_oldest;

	while (o && (int)(tgt_version - o->version) >= 0) {
		struct rcu_object *n = o->next;
		o->fn(o);
		o = n;
	}
	w->collect_oldest = o;
	if (!o) {
		w->collect_newest = NULL;
	}
}

void rcu_commit(struct rcu_writer *w, void *p, struct rcu_object *objs)
{
	// release the new root to the readers
	struct rcu_object *d = p;
	w->version += VERSION_STEP;
	d->version = w->version;
	atomic_store_explicit(&w->root, d, memory_order_release);

	// find the oldest version in active use
	unsigned version = w->version;
	for (int i = 0; i < w->rd.n; i++) {
		const struct rcu_reader *r = w->rd.v[i];
		unsigned v =
			atomic_load_explicit(&r->version, memory_order_relaxed);
		if ((v & VALID_FLAG) && (int)(version - v) > 0) {
			version = v;
		} else if (v == DISABLE_GC) {
			return;
		}
	}

	// free everything before that point
	if (w->collect_oldest) {
		run_gc(w, version - VERSION_STEP);
	}

	// Free new objects if we can. Otherwise collect them to free later.
	if (!objs) {
		// no new objects
	} else if (version == w->version) {
		free_list(objs);
	} else {
		collect_list(w, objs);
	}
}
