#define _GNU_SOURCE
#include "rx.h"
#include "tx.h"
#include "bus.h"
#include "addr.h"
#include "busmsg.h"
#include "dispatch.h"
#include "txmap.h"
#include "dbus/stream.h"
#include "dbus/encode.h"
#include "dbus/decode.h"
#include "dbus/auth.h"
#include "lib/logmsg.h"
#include "lib/algo.h"
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <pthread.h>

struct rx *new_rx(struct bus *bus, struct tx *tx, int fd)
{
	struct rx *r = fmalloc(sizeof(*r) + UNIQ_ADDR_BUFLEN);
	memset(r, 0, sizeof(*r));
	r->bus = bus;
	r->tx = tx;
	ref_tx(tx);
	r->fd = fd;
	r->addr.len = id_to_address(r->addr.p, tx->id);
	return r;
}

void free_rx(struct rx *r)
{
	if (r) {
		shutdown(r->fd, SHUT_RD);
		// deref_tx may close the fd so do this last
		deref_tx(r->tx);
		assert(!r->names);
		assert(!r->subs);
		assert(!r->reader);
		free(r);
	}
}

static ssize_t recv_one(int fd, char *p1, size_t n1, char *p2, size_t n2)
{
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
		ssize_t n = recvmsg(fd, &m, 0);
		if (n < 0 && errno == EINTR) {
			continue;
		} else if (n < 0 && errno == EAGAIN) {
			if (poll_one(fd, true, false)) {
				return -1;
			}
			continue;
		} else if (n < 0) {
			ERROR("recv,errno:%m,fd:%d", fd);
			return -1;
		} else if (n == 0) {
			ERROR("recv early EOF,fd:%d", fd);
			return -1;
		} else {
			struct logbuf lb;
			if (start_debug(&lb, "recv")) {
				log_int(&lb, "fd", fd);
				log_bytes(&lb, "data1", p1, (n > n1) ? n1 : n);
				log_bytes(&lb, "data2", p2,
					  (n > n1) ? (n - n1) : 0);
				finish_log(&lb);
			}
			return n;
		}
	}
}

static int send_all(int fd, const char *p, size_t sz)
{
	while (sz) {
		int n = send(fd, p, sz, 0);
		if (n < 0 && errno == EINTR) {
			continue;
		} else if (n < 0 && errno == EAGAIN) {
			if (poll_one(fd, false, true)) {
				return -1;
			}
			continue;
		} else if (n <= 0) {
			ERROR("send,errno:%m,fd:%d", fd);
			return -1;
		} else {
			p += n;
			sz -= n;
			continue;
		}
	}
	return 0;
}

static int authenticate(struct rx *r)
{
	uint32_t serial;
	int state = 0;
	size_t insz = 0;
	char inbuf[256];
	char outbuf[64];

	for (;;) {
		int n = recv_one(r->fd, inbuf + insz, sizeof(inbuf) - insz,
				 NULL, 0);
		if (n < 0) {
			return -1;
		}
		insz += n;

		char *in = inbuf;
		char *out = outbuf;
		int err = step_server_auth(&state, &in, insz, &out,
					   sizeof(outbuf), r->bus->busid.p,
					   &serial);

		if (send_all(r->fd, outbuf, out - outbuf)) {
			return -1;
		}

		if (err == AUTH_OK) {
			break;
		} else if (err != AUTH_READ_MORE) {
			return -1;
		}

		// compact any remaining input data
		n = inbuf + insz - in;
		memmove(inbuf, in, n);
		insz = n;
	}

	// register_remote will send the Hello reply
	mtx_lock(&r->bus->lk);
	int err = register_remote(r->bus, r, &r->addr, serial, &r->reader);
	mtx_unlock(&r->bus->lk);
	return err;
}

static void unregister_with_bus(struct rx *r)
{
	mtx_lock(&r->bus->lk);
	rm_all_names_locked(r);
	rm_all_matches_locked(r);
	unregister_remote(r->bus, r, &r->addr, r->reader);
	r->reader = NULL;
	mtx_unlock(&r->bus->lk);

	close_tx(r->tx);
}

static int read_message(struct rx *r, struct msg_stream *s)
{
	struct tx_msg m;

	for (;;) {
		int sts = stream_next(s, &m.m);
		if (sts == STREAM_ERROR) {
			return -1;
		} else if (sts == STREAM_OK) {
			break;
		}
		char *p1, *p2;
		size_t n1, n2;
		stream_buffers(s, &p1, &n1, &p2, &n2);
		ssize_t n = recv_one(r->fd, p1, n1, p2, n2);
		if (n < 0) {
			return -1;
		}
		s->have += n;
	}

	m.m.sender = &r->addr;
	m.hdr.buf = NULL;
	m.hdr.len = 0;
	stream_body(s, &m.body[0].buf, &m.body[0].len, &m.body[1].buf,
		    &m.body[1].len);

	struct logbuf lb;
	if (start_debug(&lb, "read")) {
		log_int(&lb, "fd", r->fd);
		log_message(&lb, &m.m);
		if (m.body[0].len) {
			log_bytes(&lb, "body", m.body[0].buf, m.body[0].len);
		}
		if (m.body[1].len) {
			log_bytes(&lb, "body1", m.body[1].buf, m.body[1].len);
		}
		finish_log(&lb);
	}

	switch (m.m.type) {
	case MSG_METHOD: {
		int err;
		struct iterator ii;
		if (!m.m.destination) {
			err = peer_method(r, &m.m);
		} else if (!str8eq(m.m.destination, BUS_DESTINATION)) {
			err = unicast(r, &m);
		} else if (defragment_body(s, &m.m, &ii)) {
			err = ERR_OOM;
		} else {
			err = bus_method(r, &m.m, &ii);
		}

		if (err && !(m.m.flags & FLAG_NO_REPLY_EXPECTED)) {
			reply_error(r, m.m.serial, err);
		}
		break;
	}
	case MSG_SIGNAL:
		// ignore errors
		if (m.m.destination) {
			unicast(r, &m);
		} else {
			broadcast(r, &m);
		}
		break;
	case MSG_REPLY:
	case MSG_ERROR:
		if (!build_reply(r, &m)) {
			// ignore errors
			route_reply(r->tx, &m);
		}
		break;
	default:
		// drop everything else
		break;
	}

	return 0;
}

// doubles as the size of the complete buffer
#define MSG_LEN (128 * 1024)

// Size of the defragment buffer. Headers and bus message bodies must be smaller
// than this as they need to be defragmented to process.
#define DEFRAG_LEN (1024)

int rx_thread(void *udata)
{
	struct rx *r = udata;

	set_thread_name(r->addr.p);

	if (authenticate(r)) {
		goto free_rx;
	}

	struct msg_stream *s = fmalloc(sizeof(*s) + MSG_LEN + DEFRAG_LEN);
	must_set_non_blocking(r->fd);
	init_msg_stream(s, MSG_LEN, DEFRAG_LEN);

	while (!read_message(r, s)) {
	}

	free(s);
	unregister_with_bus(r);
free_rx:
	free_rx(r);
	return 0;
}
