#include "remote.h"
#include "page.h"
#include "lib/log.h"
#include "lib/decode.h"
#include <poll.h>
#include <errno.h>

///////////////////////////////
// Generic functions to read messages

slice_t defragment(buf_t *buf, const slice_t *slices, int len)
{
	if (len <= slices->len) {
		// the chunk we are interested in is in a single fragment
		return make_slice(slices->p, len);
	}
	// the data is spread over multiple slices we have to make a copy
	// copy over complete parts
	while (len && len > slices->len) {
		buf_add(buf, *slices);
		len -= slices->len;
		slices++;
	}
	// and then the final partial part
	buf_add(buf, make_slice(slices->p, len));
	return to_slice(*buf);
}

slice_t *skip_parts(slice_t *slices, int len)
{
	// skip complete parts
	while (len && len > slices->len) {
		len -= slices->len;
		slices++;
	}
	// split the last partial part
	slices->p += len;
	slices->len -= len;
	return slices;
}

int read_string_msg(buf_t *buf, struct message *m, struct body b, slice_t *p)
{
	slice_t data = defragment(buf, b.slices, m->body_len);
	struct iterator ii;
	init_iterator(&ii, m->signature, data);
	*p = parse_string(&ii);
	return iter_error(&ii);
}

/////////////////////////
// Socket processing functions

// returns -ve on error
int poll_socket(int fd, bool *pcan_write)
{
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (pcan_write && !*pcan_write) {
		pfd.events |= POLLOUT;
	}
	sigset_t sig;
	sigfillset(&sig);
	sigdelset(&sig, SIGMSGQ);
	sigdelset(&sig, SIGINT);
	sigdelset(&sig, SIGTERM);
try_again:
	int n = ppoll(&pfd, (fd >= 0 ? 1 : 0), NULL, &sig);
	if (n < 0 && errno == EAGAIN) {
		goto try_again;
	} else if (n == 0 || (n < 0 && errno != EINTR)) {
		ELOG("poll: %m");
		return -1;
	}
	// either we've been signalled to process the message queue or there is
	// data to be read from the client socket
	if (pcan_write && (n == 1) && (pfd.revents & POLLOUT)) {
		*pcan_write = true;
	}
	return 0;
}

static int process_message(struct remote *r, struct message *m, struct body b)
{
	ELOG("have message type %d to %s -> %s.%s on %s", m->type,
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

static struct body get_body(slice_t *slices, int hsz, int bsz)
{
	struct body b = {
		.slices = NULL,
		.len = bsz,
	};
	if (bsz) {
		// skip over the header
		while (hsz > slices->len) {
			hsz -= slices->len;
			slices++;
		}
		slices->p += hsz;
		slices->len -= hsz;
		b.slices = slices;

		// skip to the last to update the length
		while (bsz > slices->len) {
			bsz -= slices->len;
			slices++;
		}
		slices->len = bsz;
	}
	return b;
}

int read_socket(struct remote *r)
{
	for (;;) {
		union {
			char buf[CONTROL_BUFFER_SIZE];
			struct cmsghdr align;
		} control;

		// find the first non-full page
		int have = r->recv_have;
		int used = r->recv_used;
		struct page **ppg = &r->in;
		while (have > sizeof((*ppg)->data)) {
			ppg = &(*ppg)->next;
			have -= sizeof((*ppg)->data);
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
		iov[0].iov_len = sizeof((*ppg)->data) - used;
		iov[1].iov_base = (*ppg)->next->data;
		iov[1].iov_len = sizeof((*ppg)->next->data);

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
			ELOG("recvmsg: %m");
			return -1;
		} else if (n == 0) {
			return -1;
		}

		if (parse_cmsg(&r->recv_oob, &msg)) {
			ELOG("too many file descriptors");
			return -1;
		}

		r->recv_have += n;

		while (r->recv_used < r->recv_have) {
			// copy the buffer ranges into slices
			slice_t slices[MAX_NUM_PAGES];
			get_page_slices(r, slices);

			struct message msg;

			// parse the header size
			char szbuf[16];
			buf_t buf = MAKE_BUF(szbuf);
			slice_t hdr = defragment(&buf, slices, buf.cap);
			int hsz = parse_header_size(hdr);

			if (hsz < sizeof(szbuf)) {
				return -1;
			} else if (r->recv_used + hsz > r->recv_have) {
				break;
			}

			// parse the fields
			if (lock_buffer(&r->out, &buf, hsz)) {
				return -1;
			}
			hdr = defragment(&buf, slices, hsz);
			int bsz = parse_header(&msg, hdr);
			unlock_buffer(&r->out, 0);

			// get the body
			int msgsz = hsz + bsz;
			if (bsz < 0 || msgsz > BUS_MAX_MSG_SIZE) {
				return -1;
			} else if (r->recv_used + msgsz > r->recv_have) {
				break;
			}
			struct body body = get_body(slices, hsz, bsz);
			r->recv_used += msgsz;

			// process the message
			if (process_message(r, &msg, body)) {
				return -1;
			}

			// drop any completed pages
			while (r->recv_used >= sizeof(r->in->data)) {
				struct page *pg = r->in;
				r->in = pg->next;
				deref_page(pg, 1);
				r->recv_used -= sizeof(pg->data);
				r->recv_have -= sizeof(pg->data);
			}

			// loop around to process the next message
		}

		// loop around to read some more
	}
}
