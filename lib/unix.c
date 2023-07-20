#define _GNU_SOURCE
#include "unix.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>

void init_unix_oob(struct unix_oob *u)
{
	u->fdn = 0;
	u->pid = -1;
	u->uid = -1;
	u->gid = -1;
}

void close_fds(struct unix_oob *u, int num)
{
	assert(num <= u->fdn);
	for (int i = 0; i < num; i++) {
		close(u->fdv[i]);
	}
	memmove(u->fdv, u->fdv + num, u->fdn - num);
	u->fdn -= num;
}

int parse_cmsg(struct unix_oob *u, struct msghdr *msg)
{
	static_assert(CMSG_LEN(sizeof(int)) - CMSG_LEN(0) == sizeof(int),
		      "checking CMSG_LEN macro");
	int too_many_fds = 0;

	for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c != NULL;
	     c = CMSG_NXTHDR(msg, c)) {
		if (c->cmsg_level == SOL_SOCKET &&
		    c->cmsg_type == SCM_CREDENTIALS &&
		    c->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
			struct ucred *uc = (struct ucred *)CMSG_DATA(c);
			u->pid = uc->pid;
			u->uid = uc->uid;
			u->gid = uc->gid;

		} else if (c->cmsg_level == SOL_SOCKET &&
			   c->cmsg_type == SCM_RIGHTS &&
			   c->cmsg_len > CMSG_LEN(0)) {
			int *pfd = (int *)CMSG_DATA(c);
			int fdn = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			for (int i = 0; i < fdn; i++) {
				if (u->fdn >= MAX_UNIX_FDS) {
					close(pfd[i]);
					too_many_fds = 1;
				} else {
					u->fdv[u->fdn++] = pfd[i];
					fcntl(pfd[i], F_SETFD, FD_CLOEXEC);
				}
			}
		}
	}

	return too_many_fds;
}

int write_cmsg(struct msghdr *msg, control_buf_t *buf, const struct unix_oob *u)
{
	if (u == NULL || u->fdn == 0) {
		msg->msg_control = NULL;
		msg->msg_controllen = 0;
		return 0;
	}
	if (CMSG_SPACE(sizeof(int) * u->fdn) > sizeof(*buf)) {
		return -1;
	}
	msg->msg_control = buf;
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * u->fdn);

	int *pfd = (int *)CMSG_DATA(cmsg);
	memcpy(pfd, u->fdv, u->fdn * sizeof(int));
	msg->msg_controllen = CMSG_SPACE(sizeof(int) * u->fdn);
	return 0;
}
