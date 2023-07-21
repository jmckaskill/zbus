#pragma once
#include "remote.h"

struct bus_name {
	slice_t name;
	struct remote *owner;
	int user;
	int group;
};

int compare_bus_name(const void *a, const void *b);

struct unique_name {
	int id;
	struct remote *owner;
};

int compare_unique_name(const void *a, const void *b);

struct rcu {
	uintptr_t version;

	// remotes sorted by remote id
	struct unique_name *remotes_v;
	int remotes_n;

	// bus names sorted by name
	struct bus_name *names_v;
	int names_n;
};

int setup_signals();
int bind_bus(const char *sockpn);
int run_bus(int lfd);
