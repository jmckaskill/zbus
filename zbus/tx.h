#pragma once
#include "lib/slice.h"
#include "lib/encode.h"
#include <threads.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

#define NO_REPLY_SERIAL UINT32_MAX
#define MAX_REQUEST_NUM (sizeof(unsigned) * CHAR_BIT)

struct tx_request {
	struct tx *client;
	uint32_t serial;
	uint16_t count;
};

struct tx {
	atomic_int refcnt;
	mtx_t lk;
	int fd;
	cnd_t send_cnd;
	int send_waiters;
	bool stalled;
	bool shutdown;
	int request_waiters;
	cnd_t request_cnd;
	// bit mask of which reply entries are available
	unsigned request_available;
	struct tx_request requests[MAX_REQUEST_NUM];
};

struct rope {
	struct rope *next;
	slice_t data;
};

size_t rope_size(struct rope *r);
struct rope *rope_skip(struct rope *r, size_t len);
const char *defrag_rope(char *buf, size_t bufsz, struct rope *r, size_t need);

struct tx *new_tx(int fd);
void ref_tx(struct tx *tx);
void deref_tx(struct tx *tx);
int send_data(struct tx *tx, bool block, const char *p, size_t sz);
int send_rope(struct tx *tx, bool block, struct rope *r);
int send_shutdown(struct tx *tx);
int send_request(struct tx *from, struct tx *to, slice_t sender,
		 const struct message *m, struct rope *body);
int send_reply(struct tx *from, slice_t sender, const struct message *m,
	       struct rope *body);
