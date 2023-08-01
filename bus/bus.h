#pragma once
#include "remote.h"

struct bus_name {
	slice_t name;
	struct remote *owner;
	int user;
	int group;
};

struct unique_name {
	int id;
	struct remote *owner;
};

struct bcast_sub {
	struct match match;
	struct remote *target;
};

struct rcu {
	uintptr_t version;

	// remotes sorted by remote id
	struct unique_name *remotes_v;
	int remotes_n;

	// bus names sorted by name
	struct bus_name *names_v;
	int names_n;

	// broadcast sorted by interface
	struct bcast_sub *bcast_v;
	int bcast_n;
};

// API for interacting with bus from main

int setup_signals();
int bind_bus(const char *sockpn);
int run_bus(int lfd);

// API for interacting with rcu data from remote

#define UNIQUE_ADDR_PREFIX S(":1.")

void id_to_string(buf_t *s, int id);
int id_from_string(slice_t s);
struct remote *lookup_name(struct rcu *d, slice_t name);
struct bus_name *lookup_bus_name(struct rcu *d, slice_t name);
struct remote *lookup_unique_name(struct rcu *d, slice_t name);
struct remote *lookup_remote(struct rcu *d, int id);
