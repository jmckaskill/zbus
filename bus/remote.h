#pragma once
#include "msgq.h"
#include <threads.h>

struct remote {
	struct msgq *qcontrol;
	struct msgq *qdata;
	unsigned id;
};

struct remote *start_remote(struct msgq *bus, slice_t busid, int id, int sock);

void join_remote(struct remote *r);
