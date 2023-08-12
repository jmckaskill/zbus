#pragma once
#include "socket.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <signal.h>
#include <pthread.h>

#define MAX_UNIX_FDS 256

struct rxconn {
	int fd;
	int clen;
	char ctrl[CMSG_SPACE(sizeof(int) * MAX_UNIX_FDS)];
};

struct txconn {
	int fd;
	int fdnum;
	struct rxconn *fdsrc;
	bool is_async;
	pthread_t thread;
};

int setup_cancel(int sig);

#define block_recv1(c, p, n) block_recv2(c, p, n, NULL, 0)
#define start_send1(c, p, n) start_send3(c, p, n, NULL, 0, NULL, 0)

#endif