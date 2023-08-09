#pragma once
#include "dbus/encode.h"
#include <threads.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <sys/socket.h>

#define NO_REPLY_SERIAL 2U

struct tx_msg {
	struct message m;
	struct {
		char *buf;
		size_t len;
	} hdr, body[2];
};

struct request {
	struct tx *remote;
	uint32_t reqidx;
	uint32_t serial;
};

struct requests {
	cnd_t cnd;
	uint32_t avail;
	struct request v[32];
};

struct tx {
	struct rcu_object rcu;

	// data that can be used without the lock
	atomic_int refcnt;
	int id;

	// data that requires the lock be held
	mtx_t lk;
	cnd_t send_cnd;
	int fd;
	int send_waiters;
	bool stalled;
	bool shutdown;
	bool closed;
	struct requests client;
	struct requests server;
};

struct tx *new_tx(int fd, int id);
static struct tx *ref_tx(struct tx *t);
void deref_tx(struct tx *t);
void close_tx(struct tx *t);
int send_message(struct tx *t, bool block, struct tx_msg *m);
int send_data(struct tx *t, bool block, struct tx_msg *m, char *buf, int sz);
int route_request(struct tx *client, struct tx *srv, struct tx_msg *m);
int route_reply(struct tx *server, struct tx_msg *m);

/////////////////////////////////////
// inline

static inline struct tx *ref_tx(struct tx *t)
{
	if (t) {
		atomic_fetch_add_explicit(&t->refcnt, 1, memory_order_relaxed);
	}
	return t;
}
