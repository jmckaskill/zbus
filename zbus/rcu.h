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

typedef void (*rcu_free_fn)(void *);

// Header for objects that need to be collected with the RCU garbage collector.
// Should be at the start of the allocated structure.
struct rcu_object {
	unsigned version;
	struct rcu_object *next;
	rcu_free_fn free;
};

void *rcu_lock(struct rcu_reader *h);
void rcu_unlock(struct rcu_reader *h);

struct rcu_writer *new_rcu_writer(void);
void free_rcu_writer(struct rcu_writer *r);

void *rcu_root(struct rcu_writer *w);
void rcu_update(struct rcu_writer *w, void *p, rcu_free_fn free);
void rcu_collect(struct rcu_writer *w, void *p, rcu_free_fn free);

struct rcu_reader *new_rcu_reader(struct rcu_writer *w);
void free_rcu_reader(struct rcu_writer *w, struct rcu_reader *r);
