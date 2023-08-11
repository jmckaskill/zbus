#pragma once
#include "socket.h"

#ifdef _WIN32
#include "windows.h"

struct rxconn {
	HANDLE h;
	OVERLAPPED ol;
};

struct txconn {
	HANDLE h;
	OVERLAPPED ol;
};

static inline void win_init_rxconn(struct rxconn *c, HANDLE h)
{
	c->h = h;
	c->ol.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
}

static inline void win_init_txconn(struct txconn *c, HANDLE h)
{
	c->h = h;
	c->ol.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
}

// windows doesn't have a workable equivalent of readv for pipes
#define block_recv2(c, p1, n1, p2, n2) \
	((void)p2, (void)n2, block_recv1(c, p1, n1))
#define start_send3(c, p1, n1, p2, n2, p3, n3) \
	((void)p2, (void)n2, (void)p3, (void)n3, start_send1(c, p1, n1))

#endif
