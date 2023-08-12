#pragma once
#include "config.h"
#include "rcu.h"
#include "sec.h"
#include "dbus/encode.h"
#include "lib/threads.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

#define NO_REPLY_SERIAL 2U
#define MAX_NUM_REQUESTS 32

struct rx;

struct txmsg {
	struct message m;
	struct {
		char *buf;
		int len;
	} hdr, body[2];
	struct rxconn *fdsrc;
};

struct request {
	struct tx *remote;
	uint32_t reqidx;
	uint32_t serial;
};

struct requests {
	cnd_t cnd;
	uint32_t avail;
	struct request v[MAX_NUM_REQUESTS];
};

struct tx {
	struct rcu_object rcu;

	// data that can be used without the lock
	atomic_int refcnt;
	int id;
	struct security *sec;

	// data that requires the lock be held
	mtx_t lk;
	cnd_t send_cnd;
	struct txconn conn;
	int send_waiters;
	bool stalled;
	bool shutdown;
	bool closed;
	struct requests client;
	struct requests server;
};

struct tx *new_tx(int id);
static struct tx *ref_tx(struct tx *t);
void deref_tx(struct tx *t);
void unregister_tx(struct rx *r);
int send_message(struct tx *t, bool block, struct txmsg *m);
int send_data(struct tx *t, bool block, struct txmsg *m, char *buf, int sz);
int route_request(struct rx *r, struct tx *srv, struct txmsg *m);
int route_reply(struct rx *r, struct txmsg *m);

/////////////////////////////////////
// inline

static inline struct tx *ref_tx(struct tx *t)
{
	atomic_fetch_add_explicit(&t->refcnt, 1, memory_order_relaxed);
	return t;
}
