#include "rcu.h"
#include "dmem/vector.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

struct rcu *rcu_lock(struct gc_handle *h)
{
	// First set the version to the oldest possible.
	// This way we don't end up with a dangling data pointer in case a GC
	// happens between the load and store.
	atomic_store_explicit(&h->version, 0, memory_order_release);
	struct rcu *data = atomic_load_explicit(h->data, memory_order_acquire);
	// Then once we have the data pointer, bring our version forward
	atomic_store_explicit(&h->version, data->version, memory_order_release);
	return data;
}

void rcu_unlock(struct gc_handle *h)
{
	atomic_store_explicit(&h->version, -1, memory_order_release);
}

struct gc_header {
	alignas(max_align_t) struct gc_header *next;
	destructor_fn destroy;
	unsigned version;
};

DVECTOR_INIT(gc_handle, struct gc_handle *);

struct gc {
	d_vector(gc_handle) handles;
	int version;

	struct gc_header *free_oldest;
	struct gc_header *free_newest;

	alignas(CACHE_LINE_SIZE) _Atomic(struct rcu *) data;
};

struct gc *new_gc()
{
	struct gc *g = aligned_alloc(CACHE_LINE_SIZE, sizeof(struct gc));
	dv_init(&g->handles);
	g->version = 0;
	g->free_newest = NULL;
	g->free_oldest = NULL;
	g->data = 0;
	return g;
}

static void do_run_gc(struct gc *g, int version);

void free_gc(struct gc *g)
{
	if (g) {
		assert(g->data == 0);
		assert(g->handles.size == 0);
		do_run_gc(g, g->version);
		dv_free(g->handles);
		free(g);
	}
}

struct gc_handle *gc_register(struct gc *g)
{
	struct gc_handle *h = aligned_alloc(CACHE_LINE_SIZE, sizeof(*h));
	dv_append1(&g->handles, h);
	h->version = -1;
	h->data = &g->data;
	return h;
}

void gc_unregister(struct gc *g, struct gc_handle *h)
{
	dv_remove(&g->handles, h);
	free(h);
}

void gc_set_rcu(struct gc *g, struct rcu *data)
{
	// TODO: handle overflow
	data->version = ++g->version;
	atomic_store_explicit(&g->data, data, memory_order_release);
}

void run_gc(struct gc *g)
{
	int version = g->version;
	for (int i = 0; i < g->handles.size; i++) {
		struct gc_handle *h = g->handles.data[i];
		int v = atomic_load_explicit(&h->version, memory_order_relaxed);
		if (0 <= v && v < version) {
			version = v;
		}
	}

	do_run_gc(g, version);
}

static void do_run_gc(struct gc *g, int version)
{
	struct gc_header *h = g->free_oldest;
	while (h && h->version < version) {
		struct gc_header *next = h->next;
		if (h->destroy) {
			h->destroy(h + 1);
		}
		free(h);
		h = next;
	}
	g->free_oldest = h;
	if (h == NULL) {
		g->free_newest = NULL;
	}
}

void *gc_alloc(size_t num, size_t sz)
{
	if (!num || !sz || sz > (size_t)-1 / num) {
		return NULL;
	}
	struct gc_header *h = malloc((num * sz) + sizeof(struct gc_header));
	return h ? (h + 1) : NULL;
}

void gc_collect(struct gc *g, void *p, destructor_fn destroy)
{
	if (p) {
		struct gc_header *hdr = ((struct gc_header *)p) - 1;
		if (g->free_newest) {
			g->free_newest->next = hdr;
		} else {
			g->free_oldest = hdr;
		}
		g->free_newest = hdr;
		hdr->next = NULL;
		hdr->version = g->version;
		hdr->destroy = destroy;
	}
}
