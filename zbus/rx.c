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
		free(r);
	}
}

static int send_auth(struct txconn *c, char *p, int sz)
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

static int authenticate(struct rx *r)
{
	uint32_t serial;
	int state = 0;
	int insz = 0;
	char inbuf[256];
	char outbuf[64];

	for (;;) {
		int n = block_recv1(&r->conn, inbuf + insz,
				    sizeof(inbuf) - insz);
		if (n < 0) {
			return -1;
		}
		insz += n;

		char *in = inbuf;
		char *out = outbuf;
		int err = step_server_auth(&state, &in, insz, &out,
					   sizeof(outbuf), r->bus->busid.p,
					   &serial);

		if (send_auth(&r->tx->conn, outbuf, (int)(out - outbuf))) {
			return -1;
		}

		if (err == AUTH_OK) {
			break;
		} else if (err != AUTH_READ_MORE) {
			return -1;
		}

		// compact any remaining input data
		int sz = (int)(inbuf + insz - in);
		memmove(inbuf, in, sz);
		insz = sz;
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
	unregister_tx(r);
}

static int read_message(struct rx *r, struct msg_stream *s)
{
	struct txmsg m;

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
		int n = block_recv2(&r->conn, p1, (int)n1, p2, (int)n2);
		if (n < 0) {
			return -1;
		}
		s->have += n;
	}

	size_t n1, n2;
	stream_body(s, &m.body[0].buf, &n1, &m.body[1].buf, &n2);
	m.hdr.buf = NULL;
	m.hdr.len = 0;
	m.body[0].len = (int)n1;
	m.body[1].len = (int)n2;
	m.m.sender = &r->addr;

	struct logbuf lb;
	if (start_debug(&lb, "read")) {
		log_int(&lb, "id", r->tx->id);
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
			route_reply(r, &m);
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

int run_rx(struct rx *r)
{
	if (authenticate(r) || load_security(&r->tx->conn, &r->tx->sec)) {
		goto free_rx;
	}

	struct msg_stream *s = fmalloc(sizeof(*s) + MSG_LEN + DEFRAG_LEN);
	init_msg_stream(s, MSG_LEN, DEFRAG_LEN);

	while (!read_message(r, s)) {
	}

	free(s);
	unregister_with_bus(r);
free_rx:
	free_rx(r);
	return 0;
}
