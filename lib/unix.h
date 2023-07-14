#pragma once
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#define MAX_UNIX_FDS 16
#define CONTROL_BUFFER_SIZE                 \
	(CMSG_SPACE(sizeof(struct ucred)) + \
	 CMSG_SPACE(sizeof(int) * MAX_UNIX_FDS))

typedef union {
	char buf[CONTROL_BUFFER_SIZE];
	struct cmsghdr align;
} control_buf_t;

struct unix_oob {
	int pid;
	int uid;
	int gid;
	unsigned fdn;
	int fdv[MAX_UNIX_FDS];
};

void init_unix_oob(struct unix_oob *u);
void close_fds(struct unix_oob *u, unsigned num);
int parse_cmsg(struct unix_oob *u, struct msghdr *msg);
int write_cmsg(struct msghdr *msg, control_buf_t *buf,
	       const struct unix_oob *u);
