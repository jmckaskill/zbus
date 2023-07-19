#pragma once
#include "config.h"
#include "bus.h"
#include <stdatomic.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

struct rcu_root {
	uintptr_t version;
	struct rcu_data data;
};

struct rcu_handle {
	atomic_uintptr_t version CACHE_ALIGNED;
	atomic_uintptr_t *root;
};

static_assert(sizeof(struct rcu_handle) == CACHE_LINE_SIZE, "");

typedef struct rcu_handle *rcu_handle_t;

const struct rcu_root *rcu_lock(struct rcu_handle *h);
void rcu_unlock(struct rcu_handle *h);

struct rcu;

void rcu_register(struct rcu *root, struct rcu_handle *h);
void rcu_unregister(struct rcu *root, struct rcu_handle *h);

void rcu_update(struct rcu *r, struct rcu_root *root);

struct rcu *rcu_new();
void rcu_free(struct rcu *r);

unsigned rcu_gc_version(rcu_handle_t *handles, unsigned num);
void rcu_run_gc(struct rcu *gc);

void *rcu_alloc(size_t num, size_t sz);
char *rcu_strdup(const char *s);
void rcu_collect(struct rcu *gc, void *p);

#define RCU_ALLOC(TYPE, NUM) ((TYPE *)rcu_alloc((NUM), sizeof(TYPE)))
