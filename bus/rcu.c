#include "rcu.h"
#include "dmem/vector.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

const struct rcu_root *rcu_lock(struct rcu_handle *h)
{
	// First set the version to the oldest possible (1).
	// This way we don't end up with a dangling root pointer in case a GC
	// happens between the two store calls.
	atomic_store_explicit(&h->version, 1, memory_order_release);
	uintptr_t uptr = atomic_load_explicit(h->root, memory_order_acquire);
	const struct rcu_root *root = (void *)uptr;
	// Then once we have the root pointer, bring our version forward
	atomic_store_explicit(&h->version, root->version, memory_order_release);
	return root;
}

void rcu_unlock(struct rcu_handle *h)
{
	atomic_store_explicit(&h->version, 0, memory_order_release);
}

struct rcu_header {
	struct rcu_header *next;
	uintptr_t version;
};

static_assert(sizeof(struct rcu_header) == 2 * sizeof(void *), "");

DVECTOR_INIT(rcu_handle, rcu_handle_t);

struct rcu {
	d_vector(rcu_handle) handles;
	uintptr_t version;

	struct rcu_header *free_oldest;
	struct rcu_header *free_newest;

	atomic_uintptr_t root CACHE_ALIGNED;
};

struct rcu *rcu_new()
{
	struct rcu *r = aligned_alloc(CACHE_LINE_SIZE, sizeof(struct rcu));
	memset(r, 0, sizeof(*r));
	r->version = 1;
	return r;
}

static void run_gc(struct rcu *r, unsigned version);

void rcu_free(struct rcu *r)
{
	if (r) {
		assert(r->root == 0);
		assert(r->handles.size == 0);
		run_gc(r, r->version);
		dv_free(r->handles);
		free(r);
	}
}

void rcu_register(struct rcu *r, struct rcu_handle *h)
{
	dv_append1(&r->handles, h);
	h->version = 0;
	h->root = &r->root;
}

void rcu_unregister(struct rcu *r, struct rcu_handle *h)
{
	dv_remove(&r->handles, h);
}

void rcu_update(struct rcu *r, struct rcu_root *root)
{
	root->version = ++r->version;
	uintptr_t u = (uintptr_t)(void *)root;
	atomic_store_explicit(&r->root, u, memory_order_release);
}

void rcu_run_gc(struct rcu *r)
{
	uintptr_t version = r->version;
	for (int i = 0; i < r->handles.size; i++) {
		rcu_handle_t h = r->handles.data[i];
		uintptr_t hver =
			atomic_load_explicit(&h->version, memory_order_relaxed);
		if (hver && hver < version) {
			version = hver;
		}
	}

	run_gc(r, version);
}

static void run_gc(struct rcu *r, unsigned version)
{
	struct rcu_header *p = r->free_oldest;
	while (p != NULL && p->version < version) {
		struct rcu_header *next = p->next;
		free(p);
		p = next;
	}
}

void *rcu_alloc(size_t num, size_t sz)
{
	if (num && sz > -1 / num) {
		return 0;
	}
	struct rcu_header *h = malloc(num * sz + 16);
	return h ? h + 16 : NULL;
}

void rcu_collect(struct rcu *r, void *p)
{
	struct rcu_header *hdr = ((struct rcu_header *)p) - 1;
	if (r->free_newest) {
		r->free_newest->next = hdr;
	} else {
		r->free_oldest = hdr;
	}
	r->free_newest = hdr;
	hdr->next = NULL;
	hdr->version = r->version;
}

char *rcu_strdup(const char *s)
{
	size_t sz = strlen(s);
	char *p = RCU_ALLOC(char, sz + 1);
	memcpy(p, s, sz + 1);
	return p;
}
