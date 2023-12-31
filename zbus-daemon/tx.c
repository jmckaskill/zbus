#define _GNU_SOURCE
#include "tx.h"
#include "rx.h"
#include "busmsg.h"
#include "zbus/zbus.h"
#include "lib/logmsg.h"
#include "lib/log.h"

static void cancel_client_requests(struct tx *client);
static void cancel_server_requests(struct rx *r, struct tx *srv);

struct tx *new_tx(int id)
{
	struct tx *t = fmalloc(sizeof(*t));
	memset(t, 0, sizeof(*t));
	if (mtx_init(&t->lk, mtx_plain) != thrd_success ||
	    cnd_init(&t->send_cnd) != thrd_success ||
	    cnd_init(&t->client.cnd) != thrd_success ||
	    cnd_init(&t->server.cnd) != thrd_success) {
		FATAL("failed to create locks,errno:%m");
	}
	atomic_store_explicit(&t->refcnt, 1, memory_order_relaxed);
	t->id = id;
	t->client.avail = UINT32_MAX;
	t->server.avail = UINT32_MAX;
	return t;
}

void deref_tx(struct tx *t)
{
	if (t && atomic_fetch_sub_explicit(&t->refcnt, 1,
					   memory_order_acq_rel) == 1) {
		mtx_destroy(&t->lk);
		cnd_destroy(&t->send_cnd);
		cnd_destroy(&t->client.cnd);
		cnd_destroy(&t->server.cnd);
		free_security(t->sec);
		close_tx(&t->conn);
		free(t);
	}
}

void unregister_tx(struct rx *r)
{
	struct tx *t = r->tx;
	mtx_lock(&t->lk);
	cancel_send(&t->conn);
	t->shutdown = true;
	t->closed = true;
	t->stalled = false;
	if (t->send_waiters) {
		cnd_broadcast(&t->send_cnd);
	}
	mtx_unlock(&t->lk);
	cancel_client_requests(t);
	cancel_server_requests(r, t);
	if (!t->client.avail) {
		cnd_broadcast(&t->client.cnd);
	}
	if (!t->server.avail) {
		cnd_broadcast(&t->server.cnd);
	}
}

static int send_locked(struct tx *t, bool block, struct txmsg *m)
{
	assert(m->hdr.len);

	struct logbuf lb;
	if (start_debug(&lb, "send")) {
		log_int(&lb, "id", t->id);
		if (m->hdr.len) {
			log_bytes(&lb, "hdr", m->hdr.buf, m->hdr.len);
		}
		if (m->body[0].len) {
			log_bytes(&lb, "body0", m->body[0].buf, m->body[0].len);
		}
		if (m->body[1].len) {
			log_bytes(&lb, "body1", m->body[1].buf, m->body[1].len);
		}
		finish_log(&lb);
	}

	if (t->shutdown) {
		return -1;
	} else if (t->stalled && !block) {
		// We don't want to stick around for the remote. DBUS doesn't
		// allow dropping individual packets. Have to drop the entire
		// connection and let the client resync.
		ERROR("overrun on tx buffer");
		goto shutdown;
	}

	if (t->stalled) {
		t->send_waiters++;
		do {
			cnd_wait(&t->send_cnd, &t->lk);
		} while (t->stalled && !t->shutdown);
		t->send_waiters--;
	}

	char *p1 = m->hdr.buf;
	int n1 = m->hdr.len;
	char *p2 = m->body[0].buf;
	int n2 = m->body[0].len;
	char *p3 = m->body[1].buf;
	int n3 = m->body[1].len;

#ifdef CAN_SEND_UNIX_FDS
	t->conn.fdnum = m->m.fdnum;
	t->conn.fdsrc = m->fdsrc;
#endif

	for (;;) {
		if (t->shutdown) {
			return -1;
		}
		assert(n1);

		int total = n1 + n2 + n3;
		int w = start_send3(&t->conn, p1, n1, p2, n2, p3, n3);
		if (w >= total) {
			break;
		} else if (w < 0) {
			ERROR("start_send,errno:%m");
			goto shutdown;
		} else if (w == 0) {
			if (!block) {
				ERROR("overrun on tx buffer");
				goto shutdown;
			}

			t->stalled = true;
			int err = finish_send(&t->conn, &t->lk);
			t->stalled = false;

			if (err) {
				ERROR("finish_send,errno:%m");
				goto shutdown;
			}
			continue;
		}

		// partial write - update pointers to figure out next chunk

		if (w < n1) {
			p1 += w;
			n1 -= w;
		} else if (w < n1 + n2) {
			w -= n1;
			p1 = p2 + w;
			n1 = n2 - w;
			p2 = p3;
			n2 = n3;
			n3 = 0;
		} else {
			w -= n1 + n2;
			p1 = p3 + w;
			n1 = n3 - w;
			n2 = 0;
			n3 = 0;
		}
	}

	if (t->send_waiters) {
		cnd_signal(&t->send_cnd);
	}

	return 0;

shutdown:
	if (!t->shutdown) {
		t->shutdown = true;
		t->stalled = false;
		cancel_send(&t->conn);
		cnd_broadcast(&t->send_cnd);
	}
	return -1;
}

int send_message(struct tx *t, bool block, struct txmsg *m)
{
	mtx_lock(&t->lk);
	int err = send_locked(t, block, m);
	mtx_unlock(&t->lk);
	return err;
}

int send_data(struct tx *t, bool block, struct txmsg *m, char *buf, int sz)
{
	if (sz < 0) {
		return ERR_INTERNAL;
	}
	// buf may actually contain some body, but we treat it is all in the
	// header so that we send it as one chunk to the kernel.
	m->hdr.buf = buf;
	m->hdr.len = sz;
	m->body[0].len = 0;
	m->body[1].len = 0;
	m->fdsrc = NULL;
	return send_message(t, block, m);
}

///////////////////////////////////////
// request/reply routing

static int acquire_request(struct tx *t, struct requests *s, mtx_t *lk)
{
	while (!s->avail && !t->closed) {
		cnd_wait(&s->cnd, lk);
	}
	if (t->closed) {
		return -1;
	}
	int idx = x_ffs(s->avail) - 1;
	assert(0 <= idx && idx < 32);
	s->avail &= ~(1U << idx);
	return idx;
}

static inline uint32_t encode_serial(struct request *r)
{
	return (r->serial << 6) | (r->reqidx << 1) | 1;
}

static int decode_serial(struct requests *s, uint32_t serial)
{
	int idx = (serial >> 1) & 31;
	if (!(serial & 1) || (serial >> 6) != s->v[idx].serial) {
		return -1;
	}
	return idx;
}

static void release_request(struct requests *s, int idx)
{
	bool wakeup = (s->avail == 0);
	s->avail |= 1U << idx;
	s->v[idx].remote = NULL;
	if (wakeup) {
		cnd_signal(&s->cnd);
	}
}

int route_request(struct rx *r, struct tx *srv, struct txmsg *m)
{
	struct tx *client = r->tx;
	assert(m->m.type == ZB_METHOD && !(m->m.flags & ZB_NO_REPLY_EXPECTED));

	// acquire the client request in a lock to synchronize with other
	// replies coming in. After allocation we can modify the request itself
	// any time until we notify the server. The only entities who are
	// interested are the client thread which we are currently running
	// inside or the server thread which doesn't know about this request
	// yet.
	mtx_lock(&client->lk);
	int cidx = acquire_request(client, &client->client, &client->lk);
	// this shouldn't fail as we are calling from the client thread, which
	// shouldn't call this function after shutting down
	assert(cidx >= 0);
	mtx_unlock(&client->lk);

	mtx_lock(&srv->lk);
	int sidx = acquire_request(srv, &srv->server, &srv->lk);
	if (sidx < 0) {
		// server has shutdown
		release_request(&client->client, cidx);
		mtx_unlock(&srv->lk);
		return -1;
	}
	struct request *sreq = &srv->server.v[sidx];
	sreq->remote = client;
	sreq->reqidx = cidx;
	sreq->serial++;
	struct request *creq = &client->client.v[cidx];
	creq->remote = srv;
	creq->reqidx = sidx;
	creq->serial = m->m.serial;

	// overwrite the serial to something we can use
	m->m.serial = encode_serial(sreq);
	zb_set_serial(m->hdr.buf, m->m.serial);

	int err = send_locked(srv, true, m);
	if (err) {
		// do this within the server lock so that the server doesn't try
		// and shutdown before we make these calls. This can't occur on
		// the client side as we are running on the client thread.
		release_request(&srv->server, sidx);
		release_request(&client->server, cidx);
	}
	mtx_unlock(&srv->lk);
	return err;
}

int route_reply(struct rx *r, struct txmsg *m)
{
	struct tx *srv = r->tx;
	uint32_t serial = m->m.reply_serial;

	mtx_lock(&srv->lk);
	int sidx = decode_serial(&srv->server, serial);
	if (sidx < 0) {
		mtx_unlock(&srv->lk);
		return -1;
	}
	struct request *sreq = &srv->server.v[sidx];
	// ref the client so that it isn't free'd between the srv unlock and the
	// client lock
	struct tx *client = ref_tx(sreq->remote);
	int cidx = sreq->reqidx;
	release_request(&srv->server, sidx);
	mtx_unlock(&srv->lk);

	mtx_lock(&client->lk);
	struct request *creq = &client->client.v[cidx];
	int err = -1;
	if (!client->closed && creq->remote == srv && creq->reqidx == sidx) {
		// only release the client request if it matches
		zb_set_reply_serial(m->hdr.buf, creq->serial);
		release_request(&client->client, cidx);
		err = send_locked(client, false, m);
	}
	mtx_unlock(&client->lk);
	deref_tx(client);
	return err;
}

static void cancel_client_requests(struct tx *client)
{
	for (int cidx = 0; cidx < MAX_NUM_REQUESTS; cidx++) {
		struct request *cr = &client->client.v[cidx];
		struct tx *srv = cr->remote;
		if (!srv) {
			continue;
		}
		mtx_lock(&srv->lk);
		struct request *sr = &srv->server.v[cr->reqidx];
		if (!srv->closed && sr->remote == client &&
		    sr->reqidx == cidx) {
			release_request(&srv->server, cr->reqidx);
		}
		mtx_unlock(&srv->lk);
		cr->remote = NULL;
	}
}

static void cancel_server_requests(struct rx *r, struct tx *srv)
{
	for (int sidx = 0; sidx < MAX_NUM_REQUESTS; sidx++) {
		struct request *sr = &srv->server.v[sidx];
		struct tx *client = sr->remote;
		if (!client) {
			continue;
		}
		mtx_lock(&client->lk);
		struct request *cr = &client->client.v[sr->reqidx];
		if (!client->closed && cr->remote == srv &&
		    cr->reqidx == sidx) {
			release_request(&client->client, sr->reqidx);
			reply_error(r, cr->serial, ERR_DISCONNECT);
		}
		mtx_unlock(&client->lk);
		sr->remote = NULL;
	}
}
