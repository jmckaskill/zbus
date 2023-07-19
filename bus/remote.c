#define _GNU_SOURCE
#include "remote.h"
#include "page.h"
#include "messages.h"
#include "bus.h"
#include "lib/str.h"
#include "lib/auth.h"
#include "lib/marshal.h"
#include "lib/unix.h"
#include "lib/message.h"
#include "dmem/vector.h"
#include <stdlib.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

#define BUS_PATH "/org/freedesktop/DBus"
#define BUS_DESTINATION "org.freedesktop.DBus"
#define BUS_INTERFACE "org.freedesktop.DBus"
#define MONITORING_INTERFACE "org.freedesktop.DBus.Monitoring"
#define PEER_INTERFACE "org.freedesktop.DBus.Peer"
#define METHOD_HELLO "Hello"
#define METHOD_LIST_NAMES "ListNames"
#define METHOD_BECOME_MONITOR "BecomeMonitor"
#define METHOD_PING "Ping"
#define NOT_FOUND_ERROR "org.freedesktop.DBus.NotFoundError"

struct remote_priv {
	struct remote pub;
	struct msgq *bus;
	slice_t busid;
	int id;
	int sock;
	thrd_t thread;
	int send_off;
	unsigned recv_used, recv_have;
	bool send_stalled;
	struct unix_oob send_oob;
	struct unix_oob recv_oob;
	struct page *in, *innext;
	struct page *out;
	unsigned out_used;
	uint32_t next_serial;
	char addr_len;
	char addr_buf[31];
};

static inline slice_t unique_addr(struct remote_priv *p)
{
	return make_slice2(p->addr_buf, p->addr_len);
}

// returns +ve if the client socket was triggered
// 0 if just the message queue has been triggered
// -ve on error
static int poll_remote(struct remote_priv *p)
{
	struct pollfd pfd;
	pfd.fd = p->sock;
	pfd.events = POLLIN | (p->send_stalled ? POLLOUT : 0);
	pfd.revents = 0;
	sigset_t sig;
	sigfillset(&sig);
	sigdelset(&sig, SIGMSGQ);
try_again:
	int r = ppoll(&pfd, 1, NULL, &sig);
	if (r < 0 && errno == EAGAIN) {
		goto try_again;
	} else if (r == 0 || (r < 0 && errno != EINTR)) {
		return -1;
	}
	// either we've been signalled to process the message queue or there is
	// data to be read from the client socket
	if (r == 1 && (pfd.revents & POLLOUT)) {
		p->send_stalled = false;
	}
	return r > 0;
}

static int do_auth(struct remote_priv *p)
{
	// No dynamic allocation in this function, so simple returns

	pthread_setname_np(pthread_self(), p->addr_buf);

	str_t si = MAKE_STR(p->in->data);
	str_t so = MAKE_STR(p->out->data);
	int auth_state = 0;

	for (;;) {
		// Process any messages from the bus. Only allow the close
		// request while we are authenticating. All other messages are
		// ignored.
		struct msgq_entry *e;
		while ((e = msgq_acquire(p->pub.qcontrol)) != NULL) {
			if (e->cmd == MSG_SHUTDOWN) {
				return -1;
			}
			msgq_pop(p->pub.qcontrol, e);
		}

		// Read as much as we can
		for (;;) {
			int r = read(p->sock, si.p + si.len, si.cap - si.len);
			if (r < 0 && errno == EINTR) {
				continue;
			} else if (r < 0 && errno == EAGAIN) {
				break;
			} else if (r <= 0) {
				return -1;
			} else {
				si.len += r;
			}
		}

		// Process as much as we can
		int sts = step_server_auth(&si, &so, p->busid, unique_addr(p),
					   &auth_state);

		// Write all the output data. We shouldn't be writing enough to
		// run out our send buffer, so fail in that case.
		unsigned off = 0;
		while (off < so.len) {
			int w = write(p->sock, so.p + off, so.len - off);
			if (w < 0 && errno == EINTR) {
				continue;
			} else if (w <= 0) {
				return -1;
			}
			off += w;
		}
		so.len = 0;

		// Look to see if we are done
		switch (sts) {
		case AUTH_READ_MORE:
			if (si.len == si.cap) {
				// can't get any more
				return -1;
			}
			break;
		case AUTH_ERROR:
			return -1;
		default:
			p->recv_have = si.len;
			p->recv_used = (unsigned)sts;
			return 0;
		}

		if (poll_remote(p) < 0) {
			return -1;
		}
	}
}

static int process_controlq(struct remote_priv *p)
{
	struct msgq_entry *e;
	while ((e = msgq_acquire(p->pub.qcontrol)) != NULL) {
		if (e->cmd == MSG_SHUTDOWN) {
			return -1;
		}
		msgq_pop(p->pub.qcontrol, e);
	}
	return 0;
}

static int send_file(struct remote_priv *p, struct msgq_entry *e)
{
	if (p->send_oob.fdn == MAX_UNIX_FDS) {
		return -1;
	}
	// remove the file from the message so it doesn't get closed when
	// popping the message
	p->send_oob.fdv[p->send_oob.fdn++] = e->u.file;
	e->u.file = INVALID_FILE;
	return 0;
}

static int send_data(struct remote_priv *p, struct msgq_entry *e)
{
	struct iovec iov;
	iov.iov_base = (char *)e->u.paged.p + p->send_off;
	iov.iov_len = e->u.paged.len - p->send_off;

	struct msghdr m;
	m.msg_name = NULL;
	m.msg_namelen = 0;
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	m.msg_flags = 0;

	control_buf_t control;
	if (write_cmsg(&m, &control, &p->send_oob)) {
		return -1;
	}

try_again:
	int w = sendmsg(p->sock, &m, 0);
	if (w < 0 && errno == EINTR) {
		goto try_again;
	} else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		p->send_stalled = true;
		return 0;
	} else if (w <= 0) {
		perror("write");
		return -1;
	}

	// a chunk and any fds were sent, loop around to send some more
	init_unix_oob(&p->send_oob);
	p->send_off += w;
	if (p->send_off < e->u.paged.len) {
		// more to send
		return 0;
	}

	// we've sent the full message
	p->send_off = 0;
	return 1;
}

static int process_dataq(struct remote_priv *p)
{
	struct msgq_entry *e;
	while ((e = msgq_acquire(p->pub.qdata)) != NULL) {
		switch (e->cmd) {
		case MSG_SEND_DATA: {
			int sts = send_data(p, e);
			if (sts < 0) {
				return -1;
			} else if (sts == 0) {
				// still got more to send
				return 0;
			}
			break;
		}
		case MSG_SEND_FILE:
			if (send_file(p, e)) {
				return -1;
			}
			break;
		}
		msgq_pop(p->pub.qdata, e);
	}
	return 0;
}

#define SEND_TRY_AGAIN 1
#define SEND_ERROR -1
#define SEND_NOT_FOUND -2
#define SEND_OK 0

static str_t get_output_buffer(struct remote_priv *p)
{
	if (p->out_used + 128 >= sizeof(p->out->data)) {
		deref_page(p->out, 1);
		p->out = new_page(1);
		p->out_used = 0;
	}
	return make_str(p->out->data + p->out_used,
			sizeof(p->out->data) - p->out_used);
}

static int send_loopback(struct remote_priv *p, str_t s, int msgsz)
{
	if (msgsz < 0 && s.p == p->out->data) {
		return SEND_ERROR;
	} else if (msgsz < 0) {
		deref_page(p->out, 1);
		p->out = new_page(1);
		p->out_used = 0;
		p->next_serial--;
		return SEND_TRY_AGAIN;
	}

	s.len = msgsz;
	slice_t data = to_slice(s);
	if (MSGQ_SEND_PAGED(p->pub.qdata, MSG_SEND_DATA, data)) {
		return SEND_ERROR;
	}

	return SEND_OK;
}

static int reply_error(struct remote_priv *p, uint32_t serial,
		       const char *error_name)
{
	struct message r;
	init_message(&r, MSG_ERROR, p->next_serial++);
	r.reply_serial = serial;
	r.sender = MAKE_SLICE(BUS_DESTINATION);
	r.error = make_slice(error_name);

	str_t s = get_output_buffer(p);
	int msgsz = end_message(start_message(&r, s.p, s.cap));
	return send_loopback(p, s, msgsz);
}

static int reply_hello(struct remote_priv *p, uint32_t serial)
{
	struct message r;
	init_message(&r, MSG_REPLY, p->next_serial++);
	r.reply_serial = serial;
	r.sender = MAKE_SLICE(BUS_DESTINATION);
	r.signature = "s";

	str_t s = get_output_buffer(p);
	struct buffer b = start_message(&r, s.p, s.cap);
	append_string(&b, make_slice2(p->addr_buf, p->addr_len));
	int msgsz = end_message(b);

	return send_loopback(p, s, msgsz);
}

static int reply_empty(struct remote_priv *p, uint32_t serial)
{
	struct message r;
	init_message(&r, MSG_REPLY, p->next_serial++);
	r.reply_serial = serial;
	r.sender = MAKE_SLICE(BUS_DESTINATION);

	str_t s = get_output_buffer(p);
	int msgsz = end_message(start_message(&r, s.p, s.cap));

	return send_loopback(p, s, msgsz);
}

static int process_message(struct remote_priv *p, const struct message *m,
			   str_t *body)
{
	fprintf(stderr, "have message type %d to %s -> %s.%s on %s\n", m->type,
		m->destination.p, m->interface.p, m->member.p, m->path.p);

try_again:

	int sts = SEND_NOT_FOUND;
	uint32_t serial = m->serial;

	if (slice_eq(m->destination, BUS_DESTINATION) &&
	    slice_eq(m->path, BUS_PATH)) {
		if (slice_eq(m->interface, BUS_INTERFACE)) {
			switch (m->member.len) {
			case STRLEN(METHOD_HELLO):
				if (slice_eq(m->member, METHOD_HELLO)) {
					sts = reply_hello(p, serial);
				}
				break;
			}

		} else if (slice_eq(m->interface, MONITORING_INTERFACE)) {
			if (slice_eq(m->member, METHOD_BECOME_MONITOR)) {
				sts = reply_empty(p, serial);
			}
		}
	}

	if (sts == SEND_NOT_FOUND) {
		sts = reply_error(p, serial, NOT_FOUND_ERROR);
	}

	if (sts == SEND_TRY_AGAIN) {
		goto try_again;
	}

	return sts;
}

static int read_messages(struct remote_priv *p)
{
	for (;;) {
		unsigned max_page_read = sizeof(p->in->data) - MAX_FIELD_SIZE;

		if (p->recv_have >= max_page_read) {
			// message is too large
			return -1;
		}

		union {
			char buf[CONTROL_BUFFER_SIZE];
			struct cmsghdr align;
		} control;

		struct iovec iov[2];
		iov[0].iov_base = p->in->data + p->recv_have;
		iov[0].iov_len = max_page_read - p->recv_have;
		iov[1].iov_base = p->innext->data;
		iov[1].iov_len = sizeof(p->innext->data);

		struct msghdr msg;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;
		msg.msg_control = control.buf;
		msg.msg_controllen = sizeof(control);
		msg.msg_flags = 0;

	try_again:
		int n = recvmsg(p->sock, &msg, 0);
		if (n < 0 && errno == EINTR) {
			goto try_again;
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return 0;
		} else if (n < 0) {
			perror("recvmsg");
			return -1;
		} else if (n == 0) {
			return -1;
		}

		if (parse_cmsg(&p->recv_oob, &msg)) {
			fprintf(stderr, "too many file descriptors\n");
			return -1;
		}

		p->recv_have += n;

		for (;;) {
			// parse out as many messages as we can
			unsigned off = p->recv_used;
			if (off + MIN_MESSAGE_SIZE > p->recv_have) {
				// loop around and read some more
				break;
			}

			struct message msg;
			int msgsz = parse_header(&msg, p->in->data + off);
			if (msgsz < 0) {
				return -1;
			} else if (off + msgsz > p->recv_have) {
				// loop around and read some more
				break;
			}

			str_t s[2];
			s[0].p = p->in->data + off;
			s[0].len = p->recv_have;
			s[0].cap = sizeof(p->in->data);
			s[1].p = p->innext->data;
			s[1].len = 0;
			s[1].cap = sizeof(p->innext->data);

			if (p->recv_have > max_page_read - off) {
				s[0].len = max_page_read - off;
				s[1].len = p->recv_have - s[0].len;
			}

			if (parse_message(&msg, s)) {
				return -1;
			}
			if (process_message(p, &msg, s)) {
				return -1;
			}
			p->recv_used += msgsz;

			// loop around to process the next message
		}

		// Get a new page (or two) if we've completed them
		// that way we always have two pages available.
		// Note that we can't just reuse them directly as the
		// data inside may be being used by another thread.
		// Hence deref and rely on the allocator to recycle
		// them.
		while (p->recv_used >= max_page_read) {
			deref_page(p->in, 1);
			p->in = p->innext;
			p->innext = new_page(1);
			p->recv_used -= max_page_read;
			p->recv_have -= max_page_read;
		}

		// loop around to read some more
	}
}

static int run_remote(void *udata)
{
	struct remote_priv *p = udata;

	if (do_auth(p)) {
		goto cleanup;
	}

	// auth process sends one message
	p->next_serial = 2;
	p->innext = new_page(1);

	struct msg_authenticated ready = { .id = p->id };
	MSGQ_SEND(p->bus, MSG_AUTHENTICATED, &ready);

	for (;;) {
		if (process_controlq(p)) {
			goto cleanup;
		}

		if (!p->send_stalled && process_dataq(p)) {
			goto cleanup;
		}

		if (read_messages(p)) {
			return -1;
		}

		if (poll_remote(p) < 0) {
			goto cleanup;
		}
	}

cleanup:
	struct msg_disconnected closing = { .r = &p->pub };
	MSGQ_SEND(p->bus, MSG_DISCONNECTED, &closing);
	return 0;
}

struct remote *start_remote(struct msgq *bus, slice_t busid, int id, int sock)
{
	struct remote_priv *p = NEW(struct remote_priv);
	p->pub.qcontrol = msgq_new();
	p->pub.qdata = msgq_new();
	p->id = id;
	p->sock = sock;
	p->bus = bus;
	p->busid = busid;
	p->in = new_page(1);
	p->out = new_page(1);
	init_unix_oob(&p->send_oob);
	init_unix_oob(&p->recv_oob);
	thrd_create(&p->thread, &run_remote, p);
	str_t s = MAKE_STR(p->addr_buf);
	str_addf(&s, ":1.%d", id);
	p->addr_len = (char)s.len;
	return &p->pub;
}

void join_remote(struct remote *r)
{
	struct remote_priv *p = container_of(r, struct remote_priv, pub);
	thrd_join(p->thread, NULL);
	msgq_free(p->pub.qdata);
	msgq_free(p->pub.qcontrol);
	deref_page(p->in, 1);
	deref_page(p->out, 1);
	deref_page(p->innext, 1);
	close_fds(&p->send_oob, p->send_oob.fdn);
	close_fds(&p->recv_oob, p->recv_oob.fdn);
	close(p->sock);
	free(p);
}
