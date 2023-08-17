#define _GNU_SOURCE
#include "rx.h"
#include "tx.h"
#include "bus.h"
#include "addr.h"
#include "busmsg.h"
#include "dispatch.h"
#include "txmap.h"
#include "auth.h"
#include "dbus/zbus.h"
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
			if (sts < 0) {
				return;
			} else if (sts > 0) {
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
