#pragma once
#include "tx.h"
#include "rcu.h"
#include "bus.h"
#include "pid-unix.h"
#include "fd-unix.h"
#include "dbus/str8.h"

struct rxname {
	struct rxname *next;
	str8_t name;
};

struct rx {
	struct bus *bus;
	struct tx *tx;
	struct rcu_reader *reader; // struct rcu_data
	int fd;
	int num_names;
	int num_subs;
	struct rxname *names;
	struct subscription *subs;
	struct unix_fds unix_fds;
	char buf[CBUF_UNIX_FDS + 255];
	str8_t addr;
};

struct rx *new_rx(struct bus *bus, int fd, int id);
void free_rx(struct rx *r);
int rx_thread(void *);
