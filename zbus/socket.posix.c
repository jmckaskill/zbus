#define _POSIX_C_SOURCE 200809L
#include "socket.h"

#ifndef _WIN32
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

static int gai_connect(int family, const char *host, const char *port)
{
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (getaddrinfo(host, port, &hints, &res)) {
		return -1;
	}

	for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
		int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
				ai->ai_protocol);
		if (fd < 0) {
			continue;
		}
		if (connect(fd, ai->ai_addr, ai->ai_addrlen)) {
			close(fd);
			continue;
		}
		freeaddrinfo(res);
		return fd;
	}

	freeaddrinfo(res);
	return -1;
}

static int unix_connect(bool is_abstract, const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNIX);
	if (fd < 0) {
		return -1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	// copy the path over. Don't need to copy leading or trailing nul as
	// addr has been zeroed.
	char *p = &addr.sun_path[is_abstract ? 1 : 0];
	size_t len = strlen(path);
	if (p + len + 1 > addr.sun_path + sizeof(addr.sun_path)) {
		return -1;
	}
	memcpy(p, path, len);
	socklen_t salen = p + len + 1 - (char *)&addr;

	if (connect(fd, (struct sockaddr *)&addr, salen)) {
		close(fd);
		return -1;
	}

	return fd;
}

int zb_connect(zb_handle_t *pfd, const char *address)
{
	char *addr = strdup(address);
	int err = -1;

	for (;;) {
		const char *type, *host, *port;
		int n = zb_parse_address(addr, &type, &host, &port);
		if (n < 0) {
			goto out;
		}

		// Want to find the first address that we understand and can
		// connect with.
		int fd = -1;
		if (!strcmp(type, "unix")) {
			fd = unix_connect(false, host);
		} else if (!strcmp(type, "abstract")) {
			fd = unix_connect(true, host);
		} else if (!strcmp(type, "tcp")) {
			fd = gai_connect(AF_UNSPEC, host, port);
		} else if (!strcmp(type, "tcp4")) {
			fd = gai_connect(AF_INET, host, port);
		} else if (!strcmp(type, "tcp6")) {
			fd = gai_connect(AF_INET6, host, port);
		}

		if (fd >= 0) {
			*pfd = fd;
			err = 0;
			goto out;
		}
	}

out:
	free(addr);
	return err;
}

int zb_send(zb_handle_t fd, const void *buf, size_t sz)
{
	return write(fd, buf, sz);
}

int zb_recv(zb_handle_t fd, void *buf, size_t sz)
{
	for (;;) {
		int r = read(fd, buf, sz);
		if (r < 0 && errno == EINTR) {
			continue;
		}
		return r;
	}
}

void zb_close(zb_handle_t fd)
{
	close(fd);
}

char *zb_userid(char *buf, size_t sz)
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
