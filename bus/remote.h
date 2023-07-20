#pragma once
#include "msgq.h"
#include "lib/unix.h"
#include <threads.h>

struct bus;

struct remote {
	// usable by any threads
	struct msgq *qcontrol;
	struct msgq *qdata;
	int id;

	// used by the bus thread and this particular remote thread
	struct bus *bus;
	struct msgq *busq;
	struct gc_handle *handle;
	thrd_t thread;
	slice_t busid;
	int sock;

	// used by the remote thread itself
	char _pad[CACHE_LINE_SIZE];
	int recv_used, recv_have;
	bool send_stalled;
	struct unix_oob send_oob;
	struct unix_oob recv_oob;
	struct page *in, *innext;
	struct page *out;
	int out_used;
	uint32_t next_serial;
	int addr_len;
	char addr_buf[16];
};

void init_remote(struct remote *r, int id);
void gc_remote(void *p);
int start_remote(struct remote *r);
void join_remote(struct remote *r);
