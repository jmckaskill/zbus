#pragma once
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#define MAX_UNIX_FDS 255
#define CBUF_UNIX_FDS CMSG_SPACE(sizeof(int) * MAX_UNIX_FDS)

struct unix_fds {
	int n;
	int v[MAX_UNIX_FDS];
};

void close_fds(struct unix_fds *u, unsigned num);
int parse_cmsg(struct unix_fds *u, const char *ctrl, size_t cn);
int write_cmsg(char **pcontrol, size_t *plen, char *buf, size_t sz,
	       const int *fdv, int fdn);

static inline void close_all_fds(struct unix_fds *u)
{
	if (u->n) {
		close_fds(u, u->n);
	}
}
