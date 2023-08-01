#include "sys.h"
#include "dmem/log.h"
#include <errno.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <poll.h>

int generate_busid(char *busid)
{
	static const char hex_enc[] = "0123456789abcdef";
	uint8_t rand[16];
	if (getentropy(rand, sizeof(rand))) {
		write_error("getentropy", errno);
		return -1;
	}
	for (int i = 0; i < sizeof(rand); i++) {
		busid[2 * i] = hex_enc[rand[i] >> 4];
		busid[2 * i + 1] = hex_enc[rand[i] & 15];
	}
	return 2 * sizeof(rand);
}

int bind_bus(const char *sockpn)
{
	int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNIX);
	if (lfd < 0) {
		write_error("socket", errno);
		goto error;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	size_t pnlen = strlen(sockpn);
	if (pnlen + 1 > sizeof(addr.sun_path)) {
		start_error("socket pathname too long", 0);
		log_cstring("path", sockpn);
		finish_log();
		goto error;
	}

	unlink(sockpn);

	memcpy(addr.sun_path, sockpn, pnlen + 1);

	socklen_t salen = addr.sun_path + pnlen + 1 - (char *)&addr;
	if (bind(lfd, (struct sockaddr *)&addr, salen) ||
	    listen(lfd, SOMAXCONN)) {
		start_error("bind", errno);
		log_cstring("path", sockpn);
		finish_log();
		goto error;
	}

	return lfd;
error:
	close(lfd);
	return -1;
}

int setup_signals()
{
	if (signal(SIGPIPE, SIG_IGN)) {
		write_error("ignore sigpipe", errno);
		return -1;
	}

	return 0;
}

int set_non_blocking(int fd)
{
	return fcntl(fd, F_SETFL, O_NONBLOCK);
}

int poll_one(int fd, bool read, bool write)
{
try_again:
	struct pollfd pfd = {
		.fd = fd,
		.events = (read ? POLLIN : 0) | (write ? POLLOUT : 0),
	};
	int n = poll(&pfd, 1, -1);
	if (n < 0 && errno == EINTR) {
		goto try_again;
	}
	return n <= 0;
}
