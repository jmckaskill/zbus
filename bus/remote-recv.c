#include "remote.h"
#include "page.h"
#include "log.h"
#include "lib/decode.h"
#include <poll.h>
#include <errno.h>

#define BUS_PATH S("/org/freedesktop/DBus")
#define BUS_INTERFACE S("org.freedesktop.DBus")
#define PEER_INTERFACE S("org.freedesktop.DBus.Peer")
#define MONITORING_INTERFACE S("org.freedesktop.DBus.Monitoring")

///////////////////////////////
// Generic functions to read messages

slice_t defragment(str_t *buf, slice_t *slices, int len)
{
	if (!len) {
		return S("");
	}
	// skip over empty slices that a previous call to defragment consumed
	while (!slices->len) {
		slices++;
	}
	if (len <= slices->len) {
		// the chunk we are interested in is in a single fragment

		return split_slice(slices, len);
	}
	// the data is spread over multiple slices we have to make a copy
	// copy over complete parts
	int left = len;
	while (left > slices->len) {
		str_add(buf, *slices);
		left -= slices->len;
		slices++;
	}
	// and then the final partial part
	str_add(buf, split_slice(slices, left));

	return to_slice(*buf);
}

int read_string_msg(str_t *buf, struct message *m, struct body b, slice_t *p)
{
	slice_t data = defragment(buf, b.slices, m->body_len);
	struct iterator ii = make_iterator(m->signature, data);
	*p = parse_string(&ii);
	return iter_error(&ii);
}

/////////////////////////
// Socket processing functions

// returns +ve if the client socket was triggered
// 0 if just the message queue has been triggered
// -ve on error
int poll_remote(struct remote *r)
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

static int process_message(struct remote *r, struct message *m, struct body b)
{
	dlog("have message type %d to %s -> %s.%s on %s", m->type,
	     m->destination.p, m->interface.p, m->member.p, m->path.p);

	int err = STS_NOT_FOUND;

	if (slice_eq(m->destination, BUS_DESTINATION)) {
		if (slice_eq(m->path, BUS_PATH)) {
			if (slice_eq(m->interface, BUS_INTERFACE)) {
				err = bus_interface(r, m, b);

			} else if (slice_eq(m->interface, PEER_INTERFACE)) {
				err = peer_interface(r, m, b);

			} else if (slice_eq(m->interface,
					    MONITORING_INTERFACE)) {
				err = monitoring_interface(r, m, b);
			}
		}
	} else if (m->destination.len) {
		err = unicast(r, m, b);
	} else {
		err = broadcast(r, m, b);
	}

	if (err) {
		err = loopback_error(r, m->reply_serial, err);
	}

	return err;
}

static void get_page_slices(struct remote *r, slice_t *s)
{
	int used = r->recv_used;
	int have = r->recv_have;

	struct page *pg = r->in;
	s[0].p = pg->data + used;
	s[0].len = have - used;

	if (have > sizeof(pg->data)) {
		s[0].len = sizeof(pg->data) - used;
		have -= sizeof(pg->data);
		pg = pg->next;

		for (int si = 1; si < MAX_NUM_PAGES; si++) {
			s[si].p = pg->data;
			s[si].len = sizeof(pg->data);
			if (have <= sizeof(pg->data)) {
				s[si].len = have;
				break;
			}
			have -= sizeof(pg->data);
			pg = pg->next;
		}
	}
}

static struct body get_body(slice_t *slices, int sz)
{
	struct body b;
	if (sz) {
		// skip over empty slices to find the
		// start
		b.slices = slices;
		while (!b.slices->len) {
			b.slices++;
		}
		// skip to the last to update the length
		slice_t *last = b.slices;
		int left = sz;
		while (left > last->len) {
			left -= last->len;
		}
		last->len = sz;
	}
	return b;
}

int read_socket(struct remote *r)
{
	for (;;) {
		int page_read_size =
			sizeof(r->in->data) - MULTIPART_WORKING_SPACE;

		union {
			char buf[CONTROL_BUFFER_SIZE];
			struct cmsghdr align;
		} control;

		// find the first non-full page
		int have = r->recv_have;
		int used = r->recv_used;
		struct page **ppg = &r->in;
		while (have > page_read_size) {
			ppg = &(*ppg)->next;
			have -= page_read_size;
			used = 0;
		}

		// make sure we have 2 pages to read into (one empty and
		// one may be partially used)
		if (!*ppg) {
			*ppg = new_page(1);
		}
		if (!(*ppg)->next) {
			(*ppg)->next = new_page(1);
		}

		struct iovec iov[2];
		iov[0].iov_base = (*ppg)->data + used;
		iov[0].iov_len = page_read_size - used;
		iov[1].iov_base = (*ppg)->next->data;
		iov[1].iov_len = page_read_size;

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
			elog("recvmsg: %m");
			return -1;
		} else if (n == 0) {
			return -1;
		}

		if (parse_cmsg(&r->recv_oob, &msg)) {
			elog("too many file descriptors");
			return -1;
		}

		r->recv_have += n;

		for (;;) {
			// parse out as many messages as we can
			assert(r->recv_used < page_read_size);
			assert(r->recv_have <= MAX_NUM_PAGES * page_read_size);

			if (r->recv_used + DBUS_HDR_SIZE > r->recv_have) {
				// loop around and read some more
				break;
			}

			// copy the buffer ranges into slices
			slice_t slices[MAX_NUM_PAGES];
			get_page_slices(r, slices);

			struct message msg;

			// parse the header
			int hsz = DBUS_HDR_SIZE;
			str_t buf = lock_short_buffer(&r->out);
			slice_t hdr = defragment(&buf, slices, hsz);
			int fsz = parse_header(&msg, hdr.p);
			unlock_buffer(&r->out, 0);

			if (fsz < 0) {
				return -1;
			} else if (r->recv_used + hsz + fsz > r->recv_have) {
				break;
			}

			// parse the fields
			if (lock_buffer(&r->out, &buf, fsz)) {
				return -1;
			}
			slice_t fields = defragment(&buf, slices, fsz);
			int bsz = parse_fields(&msg, fields.p);
			unlock_buffer(&r->out, 0);

			int msgsz = hsz + fsz + bsz;
			if (bsz < 0 || msgsz > BUS_MAX_MSG_SIZE) {
				return -1;
			} else if (r->recv_used + msgsz > r->recv_have) {
				break;
			}

			// process the message
			if (process_message(r, &msg, get_body(slices, bsz))) {
				return -1;
			}
			r->recv_used += msgsz;

			// drop any completed pages
			while (r->recv_used >= page_read_size) {
				struct page *pg = r->in;
				r->in = pg->next;
				deref_page(pg, 1);
				r->recv_used -= page_read_size;
				r->recv_have -= page_read_size;
			}

			// loop around to process the next message
		}

		// loop around to read some more
	}
}
