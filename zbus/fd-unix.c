#define _GNU_SOURCE
#include "fd-unix.h"
#include "dbus/types.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <fcntl.h>

void close_fds(struct unix_fds *u, unsigned num)
{
	assert(num <= u->n);
	for (unsigned i = 0; i < num; i++) {
		close(u->v[i]);
	}
	memmove(u->v, u->v + num, u->n - num);
	u->n -= num;
}

int parse_cmsg(struct unix_fds *u, const char *ctrl, size_t cn)
{
	struct msghdr msg;
	msg.msg_control = (void*)ctrl;
	msg.msg_controllen = cn;

	static_assert(CMSG_LEN(sizeof(int)) - CMSG_LEN(0) == sizeof(int),
		      "checking CMSG_LEN macro");
	int err = 0;

	for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c != NULL;
	     c = CMSG_NXTHDR(&msg, c)) {
		if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
		    c->cmsg_len >= CMSG_LEN(sizeof(int))) {
			int *pfd = (int *)CMSG_DATA(c);
			int n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			for (int i = 0; i < n; i++) {
				if (u->n >= MAX_UNIX_FDS) {
					close(pfd[i]);
					err = -1;
				} else {
					u->v[u->n++] = pfd[i];
					fcntl(pfd[i], F_SETFD, FD_CLOEXEC);
				}
			}
		}
	}

	return err;
}

int write_cmsg(char **pcontrol, size_t *plen, char *buf, size_t sz,
	       const int *fdv, int fdn)
{
	assert(fdn <= MAX_UNIX_FDS);
	if (fdn == 0) {
		*pcontrol = NULL;
		*plen = 0;
		return 0;
	}
	char *e = buf + sz;
	buf = ALIGN_PTR_UP(buf, sizeof(max_align_t));
	if (buf + CMSG_SPACE(sizeof(int) * fdn) > e) {
		return -1;
	}
	struct msghdr msg;
	msg.msg_control = buf;
	msg.msg_controllen = e - buf;
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fdn);

	int *pfd = (int *)CMSG_DATA(cmsg);
	memcpy(pfd, fdv, fdn * sizeof(int));
	*plen = CMSG_SPACE(sizeof(int) * fdn);
	*pcontrol = buf;
	return 0;
}
