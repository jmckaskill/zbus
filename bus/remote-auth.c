#include "remote.h"
#include "page.h"
#include "messages.h"
#include "lib/auth.h"
#include "lib/encode.h"
#include <errno.h>
#include <unistd.h>

static int write_all(int fd, const char *data, int len)
{
	while (len) {
		int w = write(fd, data, len);
		if (w < 0 && errno == EINTR) {
			continue;
		} else if (w <= 0) {
			return -1;
		}
		data += w;
		len -= w;
	}
	return 0;
}

static int auth_locked(struct remote *r, buf_t *in, buf_t *out,
		       uint32_t *pserial)
{
	// serial is also used as a state variable for the auth step function
	*pserial = 0;

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

		// Read as much as we can. We shouldn't be reading enough to run
		// out of buffer, so fail in that case.
		for (;;) {
			int n = recv(r->sock, in->p + in->len,
				     in->cap - in->len, 0);
			if (n < 0 && errno == EINTR) {
				continue;
			} else if (n < 0 && errno == EAGAIN) {
				break;
			} else if (n <= 0) {
				return -1;
			} else if (n == in->cap - in->len) {
				// we've run out of buffer
				return -1;
			} else {
				in->len += n;
			}
		}

		// process the data we just read to create output data
		switch (step_server_auth(in, out, r->busid, r->addr, pserial)) {
		case AUTH_READ_MORE:
			if (in->len == in->cap) {
				// can't get any more
				return -1;
			}
			break;
		case AUTH_ERROR:
			return -1;
		case AUTH_OK:
		default:
			return 0;
		}

		// Write all the output data. We shouldn't be writing enough to
		// run out our send buffer, so fail in that case.
		if (write_all(r->sock, out->p, out->len)) {
			return -1;
		}
		out->len = 0;

		// wait for more data to be read or a message
		if (poll_socket(r->sock, NULL)) {
			return -1;
		}
	}
}

int authenticate(struct remote *r)
{
	buf_t in = make_buf(r->in->data, sizeof(r->in->data));

	uint32_t auth_serial;

	buf_t out = lock_short_buffer(&r->out);
	int used = auth_locked(r, &in, &out, &auth_serial);
	unlock_buffer(&r->out, 0);

	if (used < 0) {
		return -1;
	}
	r->recv_used = 0;
	r->recv_have = in.len;

	// now need to notify the bus and wait for the confirmation
	// That way the client doesn't try and send messages before other
	// clients can look them up.

	struct cmd_remote c;
	c.remote = r;
	msgq_send(r->busq, CMD_REGISTER, &c, sizeof(c), NULL);

	for (;;) {
		struct msgq_entry *e;
		while ((e = msgq_acquire(r->qcontrol)) != NULL) {
			switch (e->cmd) {
			case MSG_SHUTDOWN:
				return -1;
			case REP_REGISTER:
				goto send_hello_reply;
			}
		}

		// don't really care about the remote right now. Just need to
		// block waiting for the message queue to trigger.
		if (poll_socket(-1, NULL)) {
			return -1;
		}
	}

send_hello_reply:
	struct message msg;
	init_message(&msg, MSG_REPLY, r->next_serial++);
	msg.sender = BUS_DESTINATION;
	msg.reply_serial = auth_serial;
	msg.signature = "s";

	out = lock_short_buffer(&r->out);
	struct builder bd = start_message(&out, &msg);
	append_string(&bd, r->addr);
	int err = end_message(&out, bd) || write_all(r->sock, out.p, out.len);
	unlock_buffer(&r->out, 0);

	return err;
}
