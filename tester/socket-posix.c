#include "socket.h"

#ifndef _WIN32
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>

int sys_send(fd_t fd, const char *buf, int sz)
{
	return send(fd, buf, sz);
}

int sys_recv(fd_t fd, char *buf, int sz)
{
try_again:
	int r = read(fd, buf, sz);
	if (r < 0 && errno == EINTR) {
		goto try_again;
	} else if (r < 0) {
		ERROR("read,errno:%m,fd:%d", fd);
		return -1;
	} else if (r == 0) {
		ERROR("recv early EOF,fd:%d", fd);
		return -1;
	}
	struct logbuf b;
	if (start_debug(&b, "read")) {
		log_int(&b, "fd", fd);
		log_bytes(&b, "data", buf, r);
		finish_log(&b);
	}
	return r;
}

void sys_close(fd_t fd)
{
	close(fd);
}

int sys_open(fd_t *pfd, const char *sockpn, bool block)
{
	int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNIX);
	if (lfd < 0) {
		goto error;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	size_t len = strlen(sockpn);
	if (len + strlen(".ready") + 1 > sizeof(addr.sun_path)) {
		goto error;
	}
	memcpy(addr.sun_path, sockpn, len + 1);

	socklen_t salen = &addr.sun_path[len + 1] - (char *)&addr;
	if (!connect(lfd, (struct sockaddr *)&addr, salen)) {
		goto ok;
	} else if (!block || errno != ECONNREFUSED) {
		goto error
	}

	// server isn't up yet, let's wait on the ready fifo

	memcpy(&addr.sun_path[len], ".ready", sizeof(".ready"));
	int rfd = open(addr.sun_path, O_RDONLY);
	if (rfd < 0) {
		goto error;
	}
	close(rfd);

	// server is ready, let's try again

	addr.sun_path[len] = 0;
	if (connect(lfd, (struct sockaddr *)&addr, salen)) {
		goto error;
	}

ok:
	*pfd = lfd;
	return 0;
error:
	close(lfd);
	return -1;
}

char *sys_userid(char *buf, size_t sz)
{
	char *puid = buf + sz;
	int id = getuid();
	*(--puid) = 0;
	do {
		*(--puid) = (id % 10) + '0';
		id /= 10;
	} while (id);
	return puid;
}

#endif
