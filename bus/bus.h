#pragma once
#include "remote.h"

struct bus_name {
	struct remote *owner;
	int user;
	int group;
	int name_len;
	char name[1];
};

struct unique_name {
	int id;
	struct remote *owner;
};

struct rcu {
	uintptr_t version;

	// remotes sorted by remote id
	struct unique_name *remotes_v;
	int remotes_n;

	// bus names sorted by name
	struct bus_name **names_v;
	int names_n;
};

int setup_signals();
int bind_bus(const char *sockpn);
int run_bus(int lfd);
