#include "socket-posix.h"
#ifndef _WIN32

static void close_all_fds(struct rxconn *c)
{
	struct msghdr m;
	m.msg_control = c->ctrl;
	m.msg_controllen = c->clen;

	for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c != NULL;
	     c = CMSG_NXTHDR(&m, c)) {
		if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
		    c->cmsg_len > CMSG_LEN(0)) {
			int *pfd = (int *)CMSG_DATA(c);
			int n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			for (int i = 0; i < n; i++) {
				close(pfd[i]);
			}
		}
	}

	c->clen = 0;
}

static int control_fdnum(struct rxconn *c)
{
	struct msghdr m;
	m.msg_control = c->ctrl;
	m.msg_controllen = c->clen;

	for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c != NULL;
	     c = CMSG_NXTHDR(&m, c)) {
		if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
		    c->cmsg_len > CMSG_LEN(0)) {
			int n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			return n;
		}
	}

	return 0;
}

void close_rx(struct rxconn *c)
{
	close_all_fds(c);
}

void close_tx(struct txconn *c)
{
	close(c->fd);
}

int block_recv2(struct rxconn *c, char *p1, int n1, char *p2, int n2)
{
	if (c->clen) {
		close_all_fds(c);
	}

	for (;;) {
		struct iovec v[2];
		v[0].iov_base = p1;
		v[0].iov_len = n1;
		v[1].iov_base = p2;
		v[1].iov_len = n2;

		struct msghdr m;
		memset(&m, 0, sizeof(m));
		m.msg_iov = v;
		m.msg_iovlen = n2 ? 2 : 1;
		m.msg_control = c->ctrl;
		m.msg_controllen = sizeof(c->ctrl);
		int n = recvmsg(fd, &m, MSG_CMSG_CLOEXEC);
		if (n < 0 && errno == EINTR) {
			continue;
		} else if (n < 0 && errno == EAGAIN) {
			for (;;) {
				struct pollfd pfd;
				pfd.fd = c->fd;
				pfd.events = POLLIN;
				int n = poll(&pfd, 1, -1);
				if (n > 0) {
					break;
				} else if (errno == EINTR) {
					continue;
				} else {
					return -1;
				}
			}
			continue;
		} else if (n < 0) {
			return -1;
		} else if (n == 0) {
			return 0;
		}

		c->clen = m.msg_controllen;
		return n;
	}
}

int start_send3(struct txconn *c, char *p1, int n1, char *p2, int n2, char *p3,
		int n3)
{
	assert(n1);

	struct iovec v[3];
	v[0].iov_base = p1;
	v[0].iov_len = n1;
	v[1].iov_base = p2;
	v[1].iov_len = n2;
	v[2].iov_base = p3;
	v[2].iov_len = n3;

	struct msghdr m;
	memset(&m, 0, sizeof(m));
	m.msg_iov = v;
	m.msg_iovlen = n3 ? 3 : (n2 ? 2 : 1);

	if (c->fdsrc) {
		if (c->fdnum == control_fdnum(c->fdsrc)) {
			m.msg_control = c->fdsrc->ctrl;
			m.msg_controllen = c->fdsrc->clen;
		} else {
			WARN("fdnum mismatch");
			close_all_fds(c->fdsrc);
		}
	}
	c->fdsrc = NULL;
	c->fdnum = 0;

	for (;;) {
		int w = sendmsg(c->fd, &m, 0);
		if (w >= 0) {
			return w;
		}

		switch (errno) {
		case EINTR:
			continue;
		case EAGAIN:
			return 0;
		default:
			return -1;
		}
	}
}

static int cancel_signal;

static void on_cancel(int)
{
}

int setup_cancel(int sig)
{
	cancel_signal = sig;

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &on_cancel;
	if (sigaction(sig, &sa, NULL)) {
		ERROR("setup cancel signal,errno:%m");
		return -1;
	}

	return 0;
}

void cancel_send(struct txconn *c)
{
	if (c->is_async) {
		pthread_kill(c->thread, cancel_signal);
	}
	shutdown(c->fd, SHUT_WR);
}

int finish_send(struct txconn *c, mtx_t *lk)
{
	c->thread = pthread_self();
	c->is_async = true;
	mtx_unlock(lk);

	struct pollfd pfd;
	pfd.fd = c->fd;
	pfd.events = POLLOUT;

	sigset_t ss;
	sigfillset(&ss);
	sigdelset(&ss, cancel_signal);

	int n = ppoll(&pfd, 1, NULL, &ss);

	mtx_lock(lk);
	c->is_async = false;
	return n < 0 ? -1 : 0;
}

#endif