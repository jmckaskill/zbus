#include "remote.h"
#include "page.h"
#include "messages.h"
#include "lib/auth.h"
#include <errno.h>
#include <unistd.h>

static int auth_locked(struct remote *r, str_t *in, str_t *out)
{
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
			int n = recv(r->sock, in->p + in->len,
				     in->cap - in->len, 0);
			if (n < 0 && errno == EINTR) {
				continue;
			} else if (n < 0 && errno == EAGAIN) {
				break;
			} else if (n <= 0) {
				return -1;
			} else {
				in->len += n;
			}
		}

		// Process as much as we can
		int sts = step_server_auth(in, out, r->busid, r->addr,
					   &auth_state);

		// Write all the output data. We shouldn't be writing enough to
		// run out our send buffer, so fail in that case.
		int off = 0;
		while (off < out->len) {
			int w = write(r->sock, out->p + off, out->len - off);
			if (w < 0 && errno == EINTR) {
				continue;
			} else if (w <= 0) {
				return -1;
			}
			off += w;
		}
		out->len = 0;

		// Look to see if we are done
		switch (sts) {
		case AUTH_READ_MORE:
			if (in->len == in->cap) {
				// can't get any more
				return -1;
			}
			break;
		case AUTH_ERROR:
			return -1;
		default:
			return sts;
		}

		if (poll_remote(r) < 0) {
			return -1;
		}
	}
}

int authenticate(struct remote *r)
{
	str_t in = make_str(r->in->data, sizeof(r->in->data));
	str_t out;

	lock_buffer(&r->out, &out, MAX_BUFFER_SIZE);
	int used = auth_locked(r, &in, &out);
	unlock_buffer(&r->out, 0);

	if (used < 0) {
		return -1;
	}
	// auth process sends one message
	r->next_serial = 2;
	r->recv_used = used;
	r->recv_have = in.len;
	return 0;
}
