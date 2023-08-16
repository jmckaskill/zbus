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
#include <stdlib.h>

struct rx *new_rx(struct bus *bus, int id)
{
	struct rx *r = fmalloc(sizeof(*r) + UNIQ_ADDR_BUFLEN);
	memset(r, 0, sizeof(*r));
	r->bus = bus;
	r->tx = new_tx(id);
	r->addr.len = id_to_address(r->addr.p, id);
	return r;
}

void free_rx(struct rx *r)
{
	if (r) {
		close_rx(&r->conn);
		deref_tx(r->tx);
		assert(!r->names);
		assert(!r->subs);
		assert(!r->reader);
		free(r->txbuf);
		free(r);
	}
}

static int send_auth(struct txconn *c, char *p, size_t sz)
{
	while (sz) {
		int n = start_send1(c, p, sz);
		if (n <= 0) {
			// we shouldn't have sent enough to consume the tx
			// buffer so consider async sends as errors
			ERROR("send,errno:%m");
			return -1;
		}
		p += n;
		sz -= n;
	}
	return 0;
}

static struct zb_stream *authenticate(struct rx *r)
{
	uint32_t serial;
	int state = 0;
	size_t inhave = 0;
	char in[256];
	char out[64];
	char *innext = in;
	char *ie = in + sizeof(in);
	char *oe = out + sizeof(out);

	for (;;) {
		// compact any remaining input data
		inhave = in + inhave - innext;
		memmove(in, innext, inhave);

		int n = block_recv1(&r->conn, in + inhave, ie - in - inhave);
		if (n < 0) {
			return NULL;
		}
		inhave += n;

		char *op = out;
		int err = zb_step_server_auth(&state, &innext, in + inhave, &op,
					      oe, r->bus->busid.p, &serial);

		if (send_auth(&r->tx->conn, out, op - out)) {
			return NULL;
		}

		if (err == ZB_STREAM_OK) {
			break;
		} else if (err != ZB_STREAM_READ_MORE) {
			return NULL;
		}
	}

	if (load_security(&r->tx->conn, &r->tx->sec)) {
		return NULL;
	}

	// auth successful, setup the full size receive and transmit buffers
	char *buf = malloc(sizeof(struct zb_stream) + RX_BUFSZ + RX_HDRSZ +
			   TX_BUFSZ);
	if (!buf) {
		return NULL;
	}
	r->txbuf = buf;

	struct zb_stream *s = (void *)(buf + TX_BUFSZ);
	zb_init_stream(s, RX_BUFSZ, RX_HDRSZ);

	// copy the remaining data into the msg receive buffer
	size_t sz = in + inhave - innext;
	if (sz) {
		char *p1, *p2;
		size_t n1, n2;
		zb_get_stream_recvbuf(s, &p1, &n1, &p2, &n2);
		assert(n1 > sizeof(in));
		memcpy(p1, innext, sz);
		s->have = sz;
	}

	// register_remote will send the Hello reply
	mtx_lock(&r->bus->lk);
	int err = register_remote(r->bus, r, &r->addr, serial, &r->reader);
	mtx_unlock(&r->bus->lk);
	return err ? NULL : s;
}

static void unregister_with_bus(struct rx *r)
{
	mtx_lock(&r->bus->lk);
	rm_all_names_locked(r);
	rm_all_matches_locked(r);
	unregister_remote(r->bus, r, &r->addr, r->reader);
	r->reader = NULL;
	mtx_unlock(&r->bus->lk);
	unregister_tx(r);
}

static void read_messages(struct rx *r, struct zb_stream *s)
{
	for (;;) {
		struct txmsg m;

		for (;;) {
			int sts = zb_read_message(s, &m.m);
			if (sts == ZB_STREAM_ERROR) {
				return;
			} else if (sts == ZB_STREAM_OK) {
				break;
			}
			char *p1, *p2;
			size_t n1, n2;
			zb_get_stream_recvbuf(s, &p1, &n1, &p2, &n2);
			int n = block_recv2(&r->conn, p1, (int)n1, p2, (int)n2);
			if (n <= 0) {
				return;
			}
			s->have += n;
		}

		size_t n1, n2;
		zb_get_stream_body(s, &m.body[0].buf, &n1, &m.body[1].buf, &n2);
		m.hdr.buf = NULL;
		m.hdr.len = 0;
		m.body[0].len = (int)n1;
		m.body[1].len = (int)n2;
		m.fdsrc = &r->conn;
		m.m.sender = &r->addr;

		struct logbuf lb;
		if (start_debug(&lb, "read")) {
			log_int(&lb, "id", r->tx->id);
			log_message(&lb, &m.m);
			if (m.body[0].len) {
				log_bytes(&lb, "body", m.body[0].buf,
					  m.body[0].len);
			}
			if (m.body[1].len) {
				log_bytes(&lb, "body1", m.body[1].buf,
					  m.body[1].len);
			}
			finish_log(&lb);
		}

		switch (m.m.type) {
		case ZB_METHOD: {
			int err;
			struct zb_iterator ii;
			if (!m.m.destination) {
				err = peer_method(r, &m.m);
			} else if (!zb_eq_str8(m.m.destination,
					       BUS_DESTINATION)) {
				err = unicast(r, &m);
			} else if (zb_defragment_body(s, &m.m, &ii)) {
				err = ERR_OOM;
			} else {
				err = bus_method(r, &m.m, &ii);
			}

			if (err && !(m.m.flags & ZB_NO_REPLY_EXPECTED)) {
				reply_error(r, m.m.serial, err);
			}
			break;
		}
		case ZB_SIGNAL:
			// ignore errors
			if (m.m.destination) {
				unicast(r, &m);
			} else {
				broadcast(r, &m);
			}
			break;
		case ZB_REPLY:
		case ZB_ERROR:
			if (!build_reply(r, &m)) {
				// ignore errors
				route_reply(r, &m);
			}
			break;
		default:
			// drop everything else
			break;
		}
	}
}

int run_rx(struct rx *r)
{
	struct zb_stream *s = authenticate(r);
	if (s) {
		read_messages(r, s);
		unregister_with_bus(r);
	}
	free_rx(r);
	return 0;
}
