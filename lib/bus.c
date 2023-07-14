#define _GNU_SOURCE
#include "bus.h"
#include "str.h"
#include "log.h"
#include "unix.h"
#include "message.h"
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

int bind_unique_address(const char *dir, int owner, int group, int mode,
			char *uniqbuf, unsigned bufsz)
{
	// bind first to a temporary name
	// and then rename to our actual unique address
	// this removes the race between unlink and bind
	union {
		struct sockaddr a;
		struct sockaddr_un u;
	} a;

	a.u.sun_family = AF_UNIX;
	str_t temp_pn = MAKE_STR(a.u.sun_path);

	if (str_cat(&temp_pn, dir) || str_cat(&temp_pn, "/sock-XXXXXX")) {
		fprintf(stderr, "path %s too long\n", temp_pn.p);
		return -1;
	}
	if (mkdtemp(temp_pn.p) == NULL) {
		perror("mktemp");
		return -1;
	}

	// we now have stuff to unwind on error

	unsigned dirlen = temp_pn.len;
	int fd = -1;

	if (str_cat(&temp_pn, "/sock")) {
		fprintf(stderr, "path %s too long\n;", temp_pn.p);
		goto do_rmdir;
	}

	fd = socket(AF_UNIX, SOCK_DGRAM, PF_UNIX);
	if (fd < 0) {
		perror("socket");
		goto do_rmdir;
	}
	if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
		perror("fcntl");
		goto do_close;
	}

	int enable = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enable, sizeof(enable))) {
		perror("SO_PASSCRED");
		goto do_close;
	}

	socklen_t alen =
		offsetof(struct sockaddr_un, sun_path) + temp_pn.len + 1;
	if (bind(fd, &a.a, alen)) {
		perror("bind");
		goto do_close;
	}

	if ((mode >= 0 && chmod(temp_pn.p, mode))) {
		perror("chmod");
		goto do_unlink;
	}
	if ((owner >= 0 || group >= 0) && chown(temp_pn.p, owner, group)) {
		perror("chown");
		goto do_unlink;
	}

	char full_buf[256];
	str_t full_pn = MAKE_STR(full_buf);
	str_cat(&full_pn, dir);
	unsigned buslen = full_pn.len;

	if (str_catf(&full_pn, "/:%d.%d", getpid(), fd)) {
		fprintf(stderr, "printf failed\n");
		goto do_unlink;
	}

	if (uniqbuf) {
		// take a copy of the filename from full_pn
		str_t uniq = make_str(uniqbuf, bufsz);
		if (str_cat(&uniq, full_pn.p + buslen + 1)) {
			fprintf(stderr, "buf too small\n");
			goto do_unlink;
		}
	}

	if (rename(temp_pn.p, full_pn.p)) {
		perror("rename");
		goto do_unlink;
	}
	goto do_rmdir;

do_unlink:
	unlink(temp_pn.p);
do_close:
	close(fd);
	fd = -1;
do_rmdir:
	str_trunc(&temp_pn, dirlen);
	rmdir(temp_pn.p);
	return fd;
}

int blocking_poll(int fd, int event)
{
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = event;
try_again:
	int r = poll(&pfd, 1, -1);
	if (r > 0) {
		return 0;
	} else if (r < 0 && errno == EINTR) {
		goto try_again;
	} else {
		perror("poll");
		return -1;
	}
}

int blocking_send(int fd, const char *bus, slice_t to, const void *p,
		  unsigned sz, const struct unix_oob *oob)
{
	if (verbose) {
		log_data(p, sz, "sending to %s", to);
	}
	if (!to.len) {
		fprintf(stderr, "invalid destination\n");
		return -1;
	}

	struct sockaddr_un a;
	a.sun_family = AF_UNIX;

	str_t s = MAKE_STR(a.sun_path);
	str_cat(&s, bus);
	str_cat(&s, "/");
	if (str_cats(&s, to)) {
		fprintf(stderr, "destination name %s too long\n", s.p);
		return -1;
	}

	struct iovec iov;
	iov.iov_base = (void *)p;
	iov.iov_len = sz;

	struct msghdr m;
	m.msg_name = &a;
	m.msg_namelen = offsetof(struct sockaddr_un, sun_path) + s.len + 1;
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	m.msg_flags = 0;

	control_buf_t control;
	if (write_cmsg(&m, &control, oob)) {
		return -1;
	}

try_again:
	int r = sendmsg(fd, &m, 0);
	if (r < 0 && errno == EINTR) {
		goto try_again;
	} else if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		if (blocking_poll(fd, POLLOUT)) {
			return -1;
		}
		goto try_again;
	} else if (r < 0) {
		perror("sendmsg");
		return -1;
	} else if (r < sz) {
		fprintf(stderr, "short write\n");
		return -1;
	}

	return 0;
}

static int verify_sender(const struct message *m, int pid)
{
	// expect sender to be of the form :<pid>.<tail>
	// check the pid field against the SCM_CREDENTIALS data
	if (!m->sender.len || m->sender.p[0] != ':') {
		return -1;
	}
	if (pid < 0) {
		return -1;
	}
	char *p;
	unsigned long m_pid = strtoul(m->sender.p + 1, &p, 10);
	return m_pid != pid || *p != '.';
}

int recv_message(int fd, char *buf, unsigned bufsz, struct message *m,
		 struct iterator *body, struct unix_oob *oob)
{
	for (;;) {
		struct unix_oob u;
		init_unix_oob(&u);

		union {
			char buf[CONTROL_BUFFER_SIZE];
			struct cmsghdr align;
		} control;

		struct iovec iov;
		iov.iov_base = buf;
		iov.iov_len = bufsz;

		struct msghdr msg;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.buf;
		msg.msg_controllen = sizeof(control);
		msg.msg_flags = 0;

		ssize_t n = recvmsg(fd, &msg, 0);
		if (n < 0 && errno == EINTR) {
			continue;
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return RECV_MORE;
		} else if (n < 0) {
			// how does a unix datagram socket fail?
			perror("recvmmsg");
			return RECV_ERROR;
		}

		log_data(buf, n, "recv");

		// if oob is NULL, the user doesn't want any fds
		if (parse_cmsg(&u, &msg) || (oob == NULL && u.fdn)) {
			elog("too many unix fds");
			goto invalid_message;
		}

		if (n < MIN_MESSAGE_SIZE || n > MAX_MESSAGE_SIZE) {
			elog("message too large/small");
			goto invalid_message;
		}
		int len = raw_message_len(buf);
		if (len < 0 || len != n) {
			elog("unexpected size");
			goto invalid_message;
		}

		if (parse_message(buf, m, body)) {
			elog("parse error");
			goto invalid_message;
		}

		if (verify_sender(m, u.pid)) {
			elog("could not validate sender");
			goto invalid_message;
		}

		if (u.fdn != m->fdnum) {
			elog("mismatch in number of fds");
			goto invalid_message;
		}

		if (oob) {
			*oob = u;
		}

		return RECV_OK;

	invalid_message:
		close_fds(&u, u.fdn);
	}
}
