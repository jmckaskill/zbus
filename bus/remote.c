#define _GNU_SOURCE
#include "remote.h"
#include "page.h"
#include "messages.h"
#include "bus.h"
#include "rcu.h"
#include "lib/str.h"
#include "lib/auth.h"
#include "lib/marshal.h"
#include "lib/unix.h"
#include "lib/message.h"
#include "lib/multipart.h"
#include "dmem/vector.h"
#include <stdlib.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>

#define BUS_PATH "/org/freedesktop/DBus"

#define BUS_DESTINATION "org.freedesktop.DBus"

#define BUS_INTERFACE "org.freedesktop.DBus"
#define METHOD_GET_ID "GetId" // 5
#define METHOD_HELLO "Hello" // 5
#define METHOD_ADD_MATCH "AddMatch" // 8
#define METHOD_LIST_NAMES "ListNames" // 9
#define METHOD_REQUEST_NAME "RequestName" // 11
#define METHOD_RELEASE_NAME "ReleaseName" // 11
#define METHOD_REMOVE_MATCH "RemoveMatch" // 11
#define METHOD_NAME_HAS_OWNER "NameHasOwner" // 12
#define METHOD_GET_NAME_OWNER "GetNameOwner" // 12
#define METHOD_LIST_QUEUED_OWNERS "ListQueuedOwners" // 16
#define METHOD_START_SERVICE "StartServiceByName" // 18
#define METHOD_LIST_ACTIVATABLE_NAMES "ListActivatableNames" // 20
#define METHOD_GET_UNIX_USER "GetConnectionUnixUser" // 21
#define METHOD_GET_ADT "GetAdtAuditSessionData" // 22
#define METHOD_GET_CREDENTIALS "GetConnectionCredentials" // 24
#define METHOD_GET_UNIX_PROCESS_ID "GetConnectionUnixProcessID" // 26
#define METHOD_UPDATE_ENVIRONMENT "UpdateActivationEnvironment" // 27
#define METHOD_GET_SELINUX "GetConnectionSELinuxSEcurityContext" // 35

#define PEER_INTERFACE "org.freedesktop.DBus.Peer"
#define METHOD_PING "Ping"

#define MONITORING_INTERFACE "org.freedesktop.DBus.Monitoring"
#define METHOD_BECOME_MONITOR "BecomeMonitor"

#define ERR_WRONG_SIGNATURE "org.freedesktop.DBus.Error.WrongSignature"
#define ERR_NOT_FOUND "org.freedesktop.DBus.Error.NotFound"
#define ERR_NOT_SUPPORTED "org.freedesktop.DBUs.Error.NotSupported"
#define ERR_NO_REMOTE "org.freedesktop.DBus.Error.NoRemote"

#define STS_OK 0
#define STS_SEND_FAILED -1
#define STS_NOT_FOUND -2
#define STS_NOT_SUPPORTED -3
#define STS_PARSE_FAILED -4
#define STS_NO_REMOTE -5
#define STS_REMOTE_FAILED -6

static inline slice_t unique_addr(struct remote *r)
{
	return make_slice2(r->addr_buf, r->addr_len);
}

// returns +ve if the client socket was triggered
// 0 if just the message queue has been triggered
// -ve on error
static int poll_remote(struct remote *r)
{
	struct pollfd pfd;
	pfd.fd = r->sock;
	pfd.events = POLLIN | (r->send_stalled ? POLLOUT : 0);
	pfd.revents = 0;
	sigset_t sig;
	sigfillset(&sig);
	sigdelset(&sig, SIGMSGQ);
try_again:
	int n = ppoll(&pfd, 1, NULL, &sig);
	if (n < 0 && errno == EAGAIN) {
		goto try_again;
	} else if (r == 0 || (r < 0 && errno != EINTR)) {
		return -1;
	}
	// either we've been signalled to process the message queue or there is
	// data to be read from the client socket
	if (n == 1 && (pfd.revents & POLLOUT)) {
		r->send_stalled = false;
	}
	return n > 0;
}

static int do_auth(struct remote *r)
{
	// No dynamic allocation in this function, so simple returns

	pthread_setname_np(pthread_self(), r->addr_buf);

	str_t si = MAKE_STR(r->in->data);
	str_t so = MAKE_STR(r->out->data);
	int auth_state = 0;

	for (;;) {
		// Process any messages from the bus. Only allow the close
		// request while we are authenticating. All other messages are
		// ignored.
		struct msgq_entry *e;
		while ((e = msgq_acquire(r->qcontrol)) != NULL) {
			if (e->cmd == MSG_SHUTDOWN) {
				return -1;
			}
			msgq_pop(r->qcontrol, e);
		}

		// Read as much as we can
		for (;;) {
			int n = read(r->sock, si.p + si.len, si.cap - si.len);
			if (n < 0 && errno == EINTR) {
				continue;
			} else if (n < 0 && errno == EAGAIN) {
				break;
			} else if (n <= 0) {
				return -1;
			} else {
				si.len += n;
			}
		}

		// Process as much as we can
		int sts = step_server_auth(&si, &so, r->busid, unique_addr(r),
					   &auth_state);

		// Write all the output data. We shouldn't be writing enough to
		// run out our send buffer, so fail in that case.
		int off = 0;
		while (off < so.len) {
			int w = write(r->sock, so.p + off, so.len - off);
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
			r->recv_have = si.len;
			r->recv_used = sts;
			return 0;
		}

		if (poll_remote(r) < 0) {
			return -1;
		}
	}
}

static int process_controlq(struct remote *r)
{
	struct msgq_entry *e;
	while ((e = msgq_acquire(r->qcontrol)) != NULL) {
		if (e->cmd == MSG_SHUTDOWN) {
			return -1;
		}
		msgq_pop(r->qcontrol, e);
	}
	return 0;
}

static int send_file(struct remote *r, struct msgq_entry *e)
{
	if (r->send_oob.fdn == MAX_UNIX_FDS) {
		return -1;
	}
	// remove the file from the message so it doesn't get closed when
	// popping the message
	struct msg_send_file *m = (void *)e->data;
	r->send_oob.fdv[r->send_oob.fdn++] = m->file;
	m->file = INVALID_FILE;
	return 0;
}

static int send_data(struct remote *r, struct msg_send_data *m)
{
	struct iovec iov;
	iov.iov_base = (char *)m->data.p;
	iov.iov_len = m->data.len;

	assert(iov.iov_len > 0);

	struct msghdr h;
	h.msg_name = NULL;
	h.msg_namelen = 0;
	h.msg_iov = &iov;
	h.msg_iovlen = 1;
	h.msg_flags = 0;

	control_buf_t control;
	if (write_cmsg(&h, &control, &r->send_oob)) {
		return -1;
	}

try_again:
	int w = sendmsg(r->sock, &h, 0);
	if (w < 0 && errno == EINTR) {
		goto try_again;
	} else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		r->send_stalled = true;
		return 0;
	} else if (w <= 0) {
		perror("write");
		return -1;
	}

	// a chunk and any fds were sent, loop around to send some more
	init_unix_oob(&r->send_oob);
	if (w == m->data.len) {
		// we've sent the full message
		return 1;
	}

	// more to send
	m->data.p += w;
	m->data.len -= w;
	return 0;
}

static int process_dataq(struct remote *r)
{
	struct msgq_entry *e;
	while ((e = msgq_acquire(r->qdata)) != NULL) {
		switch (e->cmd) {
		case MSG_SEND_DATA: {
			struct msg_send_data *m = (void *)e->data;
			int sts = send_data(r, m);
			if (sts < 0) {
				return -1;
			} else if (sts == 0) {
				// still got more to send
				return 0;
			}
			break;
		}
		case MSG_SEND_FILE:
			if (send_file(r, e)) {
				return -1;
			}
			break;
		}
		msgq_pop(r->qdata, e);
	}
	return 0;
}

static str_t get_output_buffer(struct remote *r, int minsz)
{
	if (r->out_used + minsz >= sizeof(r->out->data)) {
		deref_page(r->out, 1);
		r->out = new_page(1);
		r->out_used = 0;
	}
	return make_str(r->out->data + r->out_used,
			sizeof(r->out->data) - r->out_used);
}

static int compare_unique_name(const void *a, const void *b)
{
	const struct unique_name *key = a;
	const struct unique_name *test = b;
	return key->id - test->id;
}

static slice_t next_part(str_t **pp, uint32_t *pleft)
{
	str_t *p = (*pp)++;
	uint32_t left = *pleft;
	if (left > p->len) {
		*pleft -= p->len;
		return make_slice2(p->p, p->len);
	} else {
		*pleft = 0;
		return make_slice2(p->p, left);
	}
}

static int num_parts(str_t *p, uint32_t n)
{
	int parts = 0;
	while (n) {
		next_part(&p, &n);
		parts++;
	}
	return parts;
}

static int send_unicast(struct remote *r, struct remote *dst, struct message *m,
			str_t *body)
{
	if (!dst) {
		return STS_NO_REMOTE;
	}

	// update the sender by rewriting the header
	str_t out = get_output_buffer(r, 256 + m->body_len);
	m->sender = make_slice2(r->addr_buf, r->addr_len);
	int hdrsz = write_message_header(m, out.p, out.cap);
	if (hdrsz < 0) {
		return STS_SEND_FAILED;
	}

	// Allocate the messages as one chunk.
	// Need one message for the header + 1 for each body part
	int msgs = 1 + num_parts(body, m->body_len);
	unsigned start;
	if (msgq_allocate(dst->qdata, msgs, &start)) {
		return STS_REMOTE_FAILED;
	}

	// setup the header
	unsigned idx = start;
	struct msgq_entry *e = msgq_get(dst->qdata, idx++);
	e->cmd = MSG_SEND_DATA;
	e->time_ms = 0;
	e->cleanup = &gc_send_data;
	struct msg_send_data *s = (void *)e->data;
	s->data = make_slice2(out.p, hdrsz);
	ref_paged_data(s->data.p, 1);

	// setup the body
	str_t *parts = body;
	uint32_t left = m->body_len;
	while (left) {
		e = msgq_get(dst->qdata, idx++);
		e->cmd = MSG_SEND_DATA;
		e->time_ms = 0;
		e->cleanup = &gc_send_data;
		s = (void *)e->data;
		s->data = next_part(&parts, &left);
		ref_paged_data(s->data.p, 1);
	}

	// and send it off
	if (msgq_release(dst->qdata, start, msgs)) {
		return STS_REMOTE_FAILED;
	}

	return 0;
}

static int process_unique_unicast(struct remote *r, struct message *m,
				  str_t *body, int id)
{
	const struct rcu *d = rcu_lock(r->handle);

	struct unique_name key = { .id = id };
	struct unique_name *dst = bsearch(&key, d->remotes_v, d->remotes_n,
					  sizeof(*d->remotes_v),
					  &compare_unique_name);

	int ret = send_unicast(r, dst->owner, m, body);

	rcu_unlock(r->handle);
	return ret;
}

static int send_loopback(struct remote *r, str_t s, int msgsz)
{
	if (msgsz < 0) {
		return STS_SEND_FAILED;
	}

	struct msg_send_data m;
	m.data = make_slice2(s.p, msgsz);
	if (msgq_send(r->qdata, MSG_SEND_DATA, &m, sizeof(m), &gc_send_data)) {
		return STS_SEND_FAILED;
	}

	r->out_used = ALIGN_UINT_UP(r->out_used + msgsz, 8);
	return STS_OK;
}

static int reply_error(struct remote *r, uint32_t serial,
		       const char *error_name)
{
	struct message rep;
	init_message(&rep, MSG_ERROR, r->next_serial++);
	rep.reply_serial = serial;
	rep.sender = MAKE_SLICE(BUS_DESTINATION);
	rep.error = make_slice(error_name);

	str_t s = get_output_buffer(r, 256);
	int msgsz = end_message(start_message(&rep, s.p, s.cap));
	return send_loopback(r, s, msgsz);
}

static int reply_hello(struct remote *r, uint32_t serial)
{
	struct message rep;
	init_message(&rep, MSG_REPLY, r->next_serial++);
	rep.reply_serial = serial;
	rep.sender = MAKE_SLICE(BUS_DESTINATION);
	rep.signature = "s";

	str_t s = get_output_buffer(r, 256);
	struct builder b = start_message(&rep, s.p, s.cap);
	append_string(&b, make_slice2(r->addr_buf, r->addr_len));
	int msgsz = end_message(b);

	return send_loopback(r, s, msgsz);
}

static int reply_empty(struct remote *r, uint32_t serial)
{
	struct message rep;
	init_message(&rep, MSG_REPLY, r->next_serial++);
	rep.reply_serial = serial;
	rep.sender = MAKE_SLICE(BUS_DESTINATION);

	str_t s = get_output_buffer(r, 256);
	int msgsz = end_message(start_message(&rep, s.p, s.cap));

	return send_loopback(r, s, msgsz);
}

static int add_match(struct remote *r, const struct message *m, str_t *body)
{
	slice_t match;
	struct multipart mi;
	init_multipart(&mi, body, m->body_len, m->signature);
	if (parse_multipart_string(&mi, &match)) {
		return STS_PARSE_FAILED;
	}

	fprintf(stderr, "add_match %.*s\n", match.len, match.p);

	return STS_NOT_SUPPORTED;
}

static int process_bus_interface(struct remote *r, const struct message *m,
				 str_t *body)
{
	// use the member length as a quick static hash
	switch (m->member.len) {
	case 5:
		if (slice_eq(m->member, METHOD_GET_ID)) {
		} else if (slice_eq(m->member, METHOD_HELLO)) {
			return reply_hello(r, m->serial);
		}
		break;
	case 8:
		if (slice_eq(m->member, METHOD_ADD_MATCH)) {
			return add_match(r, m, body);
		}
		break;
	case 9:
		if (slice_eq(m->member, METHOD_LIST_NAMES)) {
		}
		break;
	case 11:
		if (slice_eq(m->member, METHOD_REMOVE_MATCH)) {
		} else if (slice_eq(m->member, METHOD_REQUEST_NAME)) {
		} else if (slice_eq(m->member, METHOD_RELEASE_NAME)) {
		}
		break;
	case 12:
		if (slice_eq(m->member, METHOD_GET_NAME_OWNER)) {
		} else if (slice_eq(m->member, METHOD_NAME_HAS_OWNER)) {
		}
		break;
	case 16:

		if (slice_eq(m->member, METHOD_LIST_QUEUED_OWNERS)) {
		}
		break;
	case 18:

		if (slice_eq(m->member, METHOD_START_SERVICE)) {
		}
		break;
	case 20:

		if (slice_eq(m->member, METHOD_LIST_ACTIVATABLE_NAMES)) {
		}
		break;
	case 21:

		if (slice_eq(m->member, METHOD_GET_UNIX_USER)) {
		}
		break;
	case 22:

		if (slice_eq(m->member, METHOD_GET_ADT)) {
		}
		break;
	case 24:

		if (slice_eq(m->member, METHOD_GET_CREDENTIALS)) {
		}
		break;
	case 26:

		if (slice_eq(m->member, METHOD_GET_UNIX_PROCESS_ID)) {
		}
		break;
	case 27:

		if (slice_eq(m->member, METHOD_UPDATE_ENVIRONMENT)) {
		}
		break;
	case 35:

		if (slice_eq(m->member, METHOD_GET_SELINUX)) {
		}
		break;
	}

	return STS_NOT_FOUND;
}

#define UNIQUE_ADDR_PREFIX ":1."

static int id_to_string(char *p, size_t sz, int id)
{
	assert(sz > STRLEN(UNIQUE_ADDR_PREFIX) + (sizeof(int) * 4 + 2) / 3);
	return sprintf(p, UNIQUE_ADDR_PREFIX "%o", (unsigned)id);
}

static int id_from_string(slice_t s)
{
	const char *p = s.p + STRLEN(UNIQUE_ADDR_PREFIX);
	int len = s.len - STRLEN(UNIQUE_ADDR_PREFIX);
	if (len <= 0 || len > ((sizeof(int) * 4) - 1) / 3) {
		// make sure the number of octal bits wouldn't overflow an int
		return -1;
	}
	int id = 0;
	for (int i = 0; i < len; i++) {
		if (p[i] < (i ? '0' : '1') || p[i] > '7') {
			return -1;
		}
		id = (id << 3) | (p[i] - '0');
	}
	return id;
}

static int process_message(struct remote *r, struct message *m, str_t *body)
{
	fprintf(stderr, "have message type %d to %s -> %s.%s on %s\n", m->type,
		m->destination.p, m->interface.p, m->member.p, m->path.p);

	int sts = STS_NOT_FOUND;

	if (slice_eq(m->destination, BUS_DESTINATION)) {
		if (slice_eq(m->path, BUS_PATH)) {
			if (slice_eq(m->interface, BUS_INTERFACE)) {
				sts = process_bus_interface(r, m, body);

			} else if (slice_eq(m->interface,
					    MONITORING_INTERFACE) &&
				   slice_eq(m->member, METHOD_BECOME_MONITOR)) {
				sts = reply_empty(r, m->serial);
			}
		}
	} else if (begins_with(m->destination, UNIQUE_ADDR_PREFIX)) {
		int id = id_from_string(m->destination);
		if (id < 0) {
			sts = STS_NO_REMOTE;
		} else {
			sts = process_unique_unicast(r, m, body, id);
		}
	}

	switch (sts) {
	case STS_PARSE_FAILED:
		sts = reply_error(r, m->serial, ERR_WRONG_SIGNATURE);
		break;
	case STS_NOT_FOUND:
		sts = reply_error(r, m->serial, ERR_NOT_FOUND);
		break;
	case STS_NOT_SUPPORTED:
		sts = reply_error(r, m->serial, ERR_NOT_SUPPORTED);
		break;
	case STS_NO_REMOTE:
		sts = reply_error(r, m->serial, ERR_NO_REMOTE);
		break;
	}

	return sts;
}

static int read_messages(struct remote *r)
{
	for (;;) {
		int max_page_read =
			sizeof(r->in->data) - MULTIPART_WORKING_SPACE;

		if (r->recv_have >= max_page_read) {
			// message is too large
			return -1;
		}

		union {
			char buf[CONTROL_BUFFER_SIZE];
			struct cmsghdr align;
		} control;

		struct iovec iov[2];
		iov[0].iov_base = r->in->data + r->recv_have;
		iov[0].iov_len = max_page_read - r->recv_have;
		iov[1].iov_base = r->innext->data;
		iov[1].iov_len = sizeof(r->innext->data);

		struct msghdr msg;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;
		msg.msg_control = control.buf;
		msg.msg_controllen = sizeof(control);
		msg.msg_flags = 0;

	try_again:
		int n = recvmsg(r->sock, &msg, 0);
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

		if (parse_cmsg(&r->recv_oob, &msg)) {
			fprintf(stderr, "too many file descriptors\n");
			return -1;
		}

		r->recv_have += n;

		for (;;) {
			// parse out as many messages as we can
			int off = r->recv_used;
			if (off + MIN_MESSAGE_SIZE > r->recv_have) {
				// loop around and read some more
				break;
			}

			str_t s[3];
			s[0].p = r->in->data + off;
			s[0].len = r->recv_have;
			s[0].cap = sizeof(r->in->data) - off;
			s[1].p = r->innext->data;
			s[1].len = 0;
			s[1].cap = sizeof(r->innext->data);
			s[2].p = NULL;
			s[2].len = 0;
			s[2].cap = 0;

			if (r->recv_have > max_page_read - off) {
				s[0].len = max_page_read - off;
				s[1].len = r->recv_have - s[0].len;
			}

			struct message msg;
			int msgsz = parse_header(&msg, s);
			if (msgsz < 0) {
				return -1;
			} else if (off + msgsz > r->recv_have) {
				// loop around and read some more
				break;
			}

			if (parse_message(&msg, s)) {
				return -1;
			}
			if (process_message(r, &msg, s)) {
				return -1;
			}
			r->recv_used += msgsz;

			// loop around to process the next message
		}

		// Get a new page (or two) if we've completed them
		// that way we always have two pages available.
		// Note that we can't just reuse them directly as the
		// data inside may be being used by another thread.
		// Hence deref and rely on the allocator to recycle
		// them.
		while (r->recv_used >= max_page_read) {
			deref_page(r->in, 1);
			r->in = r->innext;
			r->innext = new_page(1);
			r->recv_used -= max_page_read;
			r->recv_have -= max_page_read;
		}

		// loop around to read some more
	}
}

static int run_remote(void *udata)
{
	struct remote *r = udata;

	if (do_auth(r)) {
		goto cleanup;
	}

	// auth process sends one message
	r->next_serial = 2;
	r->innext = new_page(1);

	struct msg_authenticated ready = { .remote = r };
	msgq_send(r->busq, MSG_AUTHENTICATED, &ready, sizeof(ready), NULL);

	for (;;) {
		if (process_controlq(r)) {
			goto cleanup;
		}

		if (!r->send_stalled && process_dataq(r)) {
			goto cleanup;
		}

		if (read_messages(r)) {
			goto cleanup;
		}

		if (poll_remote(r) < 0) {
			goto cleanup;
		}
	}

cleanup:
	struct msg_disconnected closing = { .remote = r };
	msgq_send(r->busq, MSG_DISCONNECTED, &closing, sizeof(closing), NULL);
	return 0;
}

int start_remote(struct remote *r)
{
	r->qcontrol = msgq_new();
	r->qdata = msgq_new();
	r->in = new_page(1);
	r->out = new_page(1);
	init_unix_oob(&r->send_oob);
	init_unix_oob(&r->recv_oob);

	r->addr_len = id_to_string(r->addr_buf, sizeof(r->addr_buf), r->id);

	if (thrd_create(&r->thread, &run_remote, r)) {
		msgq_free(r->qcontrol);
		msgq_free(r->qdata);
		deref_page(r->in, 1);
		deref_page(r->out, 1);
		return -1;
	}

	return 0;
}

void join_remote(struct remote *r)
{
	// Clean up everything except what other threads use. That is cleaned up
	// gc_remote when the remote struct is garbage collected.
	thrd_join(r->thread, NULL);
	deref_page(r->in, 1);
	deref_page(r->out, 1);
	deref_page(r->innext, 1);
	close_fds(&r->send_oob, r->send_oob.fdn);
	close_fds(&r->recv_oob, r->recv_oob.fdn);
	close(r->sock);
}

void gc_remote(void *p)
{
	struct remote *r = p;
	msgq_free(r->qcontrol);
	msgq_free(r->qdata);
}
