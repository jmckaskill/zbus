#include "remote.h"
#include "messages.h"
#include "page.h"
#include "lib/log.h"
#include "lib/encode.h"
#include <errno.h>
#include <sys/socket.h>

////////////////////////////
// Functions to send out the socket

static int send_file(struct remote *r, struct msgq_entry *e)
{
	if (r->send_oob.fdn == MAX_UNIX_FDS) {
		return -1;
	}
	// remove the file from the message so it doesn't get closed when
	// popping the message
	struct msg_file *m = (void *)e->data;
	r->send_oob.fdv[r->send_oob.fdn++] = m->file;
	m->file = INVALID_FILE;
	return 0;
}

static int send_data(struct remote *r, struct msg_data *m)
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
		r->can_write = false;
		return 0;
	} else if (w <= 0) {
		ELOG("write: %m");
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

int process_dataq(struct remote *r)
{
	struct msgq_entry *e;
	while ((e = msgq_acquire(r->qdata)) != NULL) {
		switch (e->cmd) {
		case MSG_DATA: {
			struct msg_data *m = (void *)e->data;
			int sts = send_data(r, m);
			if (sts < 0) {
				return -1;
			} else if (sts == 0) {
				// still got more to send
				return 0;
			}
			break;
		}
		case MSG_FILE:
			if (send_file(r, e)) {
				return -1;
			}
			break;
		}
		msgq_pop(r->qdata, e);
	}
	return 0;
}

//////////////////////
// Functions to feed the data queue

int send_loopback(struct remote *r, slice_t data)
{
	struct msg_data m;
	m.data = data;
	if (msgq_send(r->qdata, MSG_DATA, &m, sizeof(m), &gc_msg_data)) {
		return STS_SEND_FAILED;
	}
	ref_paged_data(data.p);
	return STS_OK;
}

int send_to(struct remote *r, struct remote *to, struct message *m,
	    struct body b)
{
	// update the sender by rewriting the header
	buf_t hdr;
	if (lock_buffer(&r->out, &hdr, 32 + m->header_len)) {
		return STS_REMOTE_FAILED;
	}
	m->sender = r->addr;
	if (append_header(&hdr, m)) {
		goto unlock;
	}

	// Allocate the messages as one chunk.
	// Need one message for the header + 1 for each body part
	int msgs = 1;
	uint32_t n = m->body_len;
	while (n) {
		n -= b.slices[msgs - 1].len;
		msgs++;
	}

	unsigned msgidx;
	if (msgq_allocate(to->qdata, msgs, &msgidx)) {
		goto unlock;
	}

	// setup the header
	struct msgq_entry *e = msgq_get(to->qdata, msgidx);
	e->cmd = MSG_DATA;
	e->cleanup = &gc_msg_data;

	struct msg_data *s = (void *)e->data;
	s->data = to_slice(hdr);
	ref_paged_data(hdr.p);

	// setup the body
	for (int i = 1; i < msgs; i++) {
		e = msgq_get(to->qdata, msgidx + i);
		e->cmd = MSG_DATA;
		e->cleanup = &gc_msg_data;

		s = (void *)e->data;
		s->data = b.slices[i - 1];
		ref_paged_data(b.slices[i - 1].p);
	}

	// and send it off
	msgq_release(to->qdata, msgidx, msgs);
	unlock_buffer(&r->out, hdr.len);
	return 0;
unlock:
	unlock_buffer(&r->out, 0);
	return STS_REMOTE_FAILED;
}

///////////////////////////
// Generic functions to send loopback messages

static const slice_t error_names[-(STS_MAX_ERROR + 1)] = {
	SLICE_INIT("org.freedesktop.DBus.Error.NotAllowed"),
	SLICE_INIT("org.freedesktop.DBus.Error.WrongSignature"),
	SLICE_INIT("org.freedesktop.DBus.Error.NotFound"),
	SLICE_INIT("org.freedesktop.DBUs.Error.NotSupported"),
	SLICE_INIT("org.freedesktop.DBus.Error.NoRemote"),
	SLICE_INIT("org.freedesktop.DBus.Error.RemoteNotResponsive"),
	SLICE_INIT("org.freedesktop.DBus.Error.NameHasNoOwner"),
	SLICE_INIT("org.freedesktop.DBus.Error.OutOfMemory"),
};

int loopback_error(struct remote *r, uint32_t serial, int errcode)
{
	if (!(STS_MAX_ERROR < errcode && errcode < 0)) {
		return errcode;
	}
	slice_t error_name = error_names[-(errcode + 1)];

	struct message rep;
	init_message(&rep, MSG_ERROR, r->next_serial++);
	rep.reply_serial = serial;
	rep.sender = BUS_DESTINATION;
	rep.error = error_name;

	buf_t s = lock_short_buffer(&r->out);
	if (append_header(&s, &rep) || send_loopback(r, to_slice(s))) {
		unlock_buffer(&r->out, 0);
		return STS_SEND_FAILED;
	}
	unlock_buffer(&r->out, s.len);
	return 0;
}

static int _loopback_uint32(struct remote *r, uint32_t serial, const char *sig,
			    uint32_t value)
{
	struct message m;
	init_message(&m, MSG_REPLY, r->next_serial++);
	m.reply_serial = serial;
	m.sender = BUS_DESTINATION;
	m.signature = sig;
	m.body_len = 4;

	buf_t s = lock_short_buffer(&r->out);
	append_header(&s, &m);
	struct builder b = start_message(&s, &m);
	_append4(&b, value, *sig);
	int err = end_message(&s, b) || send_loopback(r, to_slice(s));
	unlock_buffer(&r->out, err ? 0 : s.len);

	return err;
}

int loopback_uint32(struct remote *r, uint32_t serial, uint32_t value)
{
	return _loopback_uint32(r, serial, "u", value);
}

int loopback_bool(struct remote *r, uint32_t serial, bool value)
{
	return _loopback_uint32(r, serial, "b", value);
}

int loopback_string(struct remote *r, uint32_t serial, slice_t str)
{
	struct message rep;
	init_message(&rep, MSG_REPLY, r->next_serial++);
	rep.reply_serial = serial;
	rep.sender = BUS_DESTINATION;
	rep.signature = "s";

	buf_t s = lock_short_buffer(&r->out);
	struct builder b = start_message(&s, &rep);
	append_string(&b, r->addr);
	int err = end_message(&s, b) || send_loopback(r, to_slice(s));
	unlock_buffer(&r->out, err ? 0 : s.len);

	return err;
}

int loopback_empty(struct remote *r, uint32_t serial)
{
	struct message rep;
	init_message(&rep, MSG_REPLY, r->next_serial++);
	rep.reply_serial = serial;
	rep.sender = BUS_DESTINATION;

	buf_t s = lock_short_buffer(&r->out);
	int err = end_message(&s, start_message(&s, &rep)) ||
		  send_loopback(r, to_slice(s));
	unlock_buffer(&r->out, err ? 0 : s.len);

	return err;
}
