#include "rx.h"
#include "tx.h"
#include "bus.h"
#include "addr.h"
#include "busmsg.h"
#include "dispatch.h"
#include "lib/stream.h"
#include "lib/encode.h"
#include "lib/decode.h"
#include "lib/auth.h"
#include "dmem/common.h"
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

struct rx *new_rx(struct bus *bus, struct tx *tx, int fd)
{
	struct rx *r = malloc(sizeof(*r));
	if (r) {
		r->bus = bus;
		r->tx = tx;
		r->names = NULL;
		circ_clear(&r->owned);
		circ_clear(&r->subs);
		r->fd = fd;
		r->addr.len = id_to_address(r->addr.p, rxid(r));
		ref_tx(tx);
	}
	return r;
}

void free_rx(struct rx *r)
{
	if (r) {
		shutdown(r->fd, SHUT_RD);
		// deref_tx may close the fd so do this last
		deref_tx(r->tx);
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
			write_error("recv", errno);
			return -1;
		} else if (n == 0) {
			write_error("recv early EOF", 0);
			return -1;
		} else {
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
			write_error("send", errno);
			return -1;
		} else {
			p += n;
			sz -= n;
			continue;
		}
	}
	return 0;
}

static void log_message(struct rx *r, struct message *m)
{
	start_verbose("rx message");
	log_number("remote", rxid(r));
	log_number("type", m->type);
	log_number("serial", m->serial);
	opt_log_number("reply", m->reply_serial);
	opt_log_number("flags", m->flags);
	opt_log_slice("dst", m->destination);
	opt_log_slice("iface", m->interface);
	opt_log_slice("member", m->member);
	opt_log_slice("path", m->path);
	opt_log_slice("error", m->error);
	finish_log();
}

static int authenticate(struct rx *r)
{
	slice_t busid = to_slice(r->bus->busid);
	uint32_t serial;
	int state = 0;
	size_t insz = 0;
	char ib[256];
	char ob[64];

	for (;;) {
		int n = recv_one(r->fd, ib + insz, sizeof(ib) - insz, NULL, 0);
		if (n < 0) {
			return -1;
		}
		insz += n;

		size_t outsz = sizeof(ob);
		slice_t in = make_slice(ib, insz);
		int err = step_server_auth(&state, &in, ob, &outsz, busid,
					   &serial);

		if (send_all(r->fd, ob, outsz)) {
			return -1;
		}

		if (err == AUTH_OK) {
			break;
		} else if (err != AUTH_READ_MORE) {
			return -1;
		}

		// compact any remaining input data
		memmove(ib, in.p, in.len);
		insz = in.len;
	}

	mtx_lock(&r->bus->lk);
	int err = register_remote(r->bus, rxid(r), to_slice(r->addr), r->tx,
				  &r->owned, &r->names);
	mtx_unlock(&r->bus->lk);

	if (err) {
		return err;
	}

	struct message m;
	init_message(&m, MSG_REPLY, NO_REPLY_SERIAL);
	m.signature = "s";
	m.reply_serial = serial;

	struct builder b = start_message(ib, sizeof(ib), &m);
	append_string(&b, to_slice(r->addr));
	int n = end_message(b);

	return n < 0 || send_all(r->fd, ib, n);
}

static void unregister_with_bus(struct rx *r)
{
	mtx_lock(&r->bus->lk);
	rm_all_names_locked(r);
	rm_all_matches_locked(r);
	unregister_remote(r->bus, rxid(r));
	mtx_unlock(&r->bus->lk);
}

static int read_message(struct rx *r, struct msg_stream *s)
{
	struct message m;
	struct rope r1, r2;

	for (;;) {
		int sts = stream_next(s, &m, &r1.data, &r2.data);
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

	log_message(r, &m);

	if (m.type == MSG_METHOD && slice_eq(m.destination, BUS_DESTINATION)) {
		defragment_body(s, &r1.data, &r2.data);
	}

	r1.next = r2.data.len ? &r2 : NULL;
	r2.next = NULL;

	return dispatch(r, &m, &r1);
}

// doubles as the size of the complete buffer
#define MAX_MSG_LEN (128 * 1024)

// Size of the defragment buffer. Headers and bus message bodies must be smaller
// than this as they need to be defragmented to process.
#define MAX_DEFRAG_LEN (1024)

int rx_thread(void *udata)
{
	struct rx *r = udata;

	if (authenticate(r)) {
		goto free_rx;
	}

	struct msg_stream *s =
		malloc(sizeof(*s) + MAX_MSG_LEN + MAX_DEFRAG_LEN);
	if (set_non_blocking(r->fd) || !s) {
		goto free_buffers;
	}
	init_msg_stream(s, MAX_MSG_LEN, MAX_DEFRAG_LEN);

	while (!read_message(r, s)) {
	}

free_buffers:
	free(s);
	unregister_with_bus(r);
free_rx:
	free_rx(r);
	return 0;
}
