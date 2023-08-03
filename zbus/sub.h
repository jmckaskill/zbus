#pragma once
#include "rcu.h"
#include "tx.h"
#include "algo.h"
#include "lib/match.h"

struct subscription {
	struct rcu_object rcu;
	struct circ_list owner;
	struct tx *tx;
	struct match match;
	uint32_t serial;
	char mstr[0];
};

struct subscription_map {
	struct rcu_object rcu;
	int len;
	struct subscription *v[0];
};

void free_subscription_map(struct subscription_map *m);

int addrm_subscription(struct rcu_writer *w, struct subscription_map **pmap,
		       bool add, const struct match *m, struct tx *tx,
		       uint32_t serial, struct circ_list *o);

int find_subscriptions(struct subscription_map *m, slice_t interface,
		       struct subscription ***pfirst);
