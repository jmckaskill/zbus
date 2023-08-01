#pragma once
#include "algo.h"
#include "tx.h"
#include "rcu.h"
#include "bus.h"

struct rx {
	struct bus *bus;
	struct tx *tx;
	struct rcu_reader *names; // struct rcu_names
	struct circ_list owned; // struct address
	struct circ_list subs;
	int fd;
	struct {
		char len;
		char p[UNIQ_ADDR_MAXLEN];
	} addr;
};

struct rx *new_rx(struct bus *bus, struct tx *tx, int fd);
void free_rx(struct rx *r);
int rx_thread(void *);

static inline int rxid(struct rx *r)
{
	// use the file descriptor as the unique id as we know this is unique to
	// this remote while the socket is open. Don't want an ID of 0 though so
	// offset by one.
	return r->fd + 1;
}
