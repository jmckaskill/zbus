#pragma once
#include "config.h"
#include "bus.h"
#include <stdatomic.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

struct gc_handle {
	alignas(CACHE_LINE_SIZE) atomic_int version;
	_Atomic(struct rcu *) *data;
};

static_assert(sizeof(struct gc_handle) == CACHE_LINE_SIZE, "");

const struct rcu *rcu_lock(struct gc_handle *h);
void rcu_unlock(struct gc_handle *h);

struct gc;

struct gc_handle *gc_register(struct gc *r);
void gc_unregister(struct gc *r, struct gc_handle *h);

void update_rcu(struct gc *r, struct rcu *data);

struct gc *new_gc();
void free_gc(struct gc *r);

void run_gc(struct gc *gc);

void *gc_alloc(size_t num, size_t sz);
void gc_collect(struct gc *gc, void *p, destructor_fn destroy);

#define GC_ALLOC(TYPE, NUM) ((TYPE *)gc_alloc((NUM), sizeof(TYPE)))
