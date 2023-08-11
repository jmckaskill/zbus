#pragma once
#include "config.h"
#include "tx.h"
#include "rcu.h"
#include "bus.h"
#include "lib/socket.h"
#include "dbus/str8.h"

struct rxname {
	struct rxname *next;
	str8_t name;
};

struct rx {
	struct bus *bus;
	struct tx *tx;
	struct rcu_reader *reader; // struct rcu_data
	struct rxconn conn;
	int num_names;
	int num_subs;
	struct rxname *names;
	struct subscription *subs;
	char buf[256];
	str8_t addr;
};

struct rx *new_rx(struct bus *bus, int id);
void free_rx(struct rx *r);
int run_rx(struct rx *r);
