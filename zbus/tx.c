#define _GNU_SOURCE
#include "tx.h"
#include "sys.h"
#include "lib/encode.h"
#include "lib/log.h"
#include "dmem/log.h"
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <sys/socket.h>

_Atomic(uint32_t) g_next_serial = 1;

struct tx *new_tx(int fd)
{
	struct tx *t = malloc(sizeof(*t));
	if (!t) {
		return NULL;
	}
	if (mtx_init(&t->lk, mtx_plain) != thrd_success) {
		goto do_free;
	}
	if (cnd_init(&t->send_cnd) != thrd_success) {
		goto destroy_mutex;
	}
	if (cnd_init(&t->request_cnd) != thrd_success) {
		goto destroy_send_cnd;
	}
	atomic_store_explicit(&t->refcnt, 1, memory_order_relaxed);
	t->fd = fd;
	t->send_waiters = 0;
	t->request_waiters = 0;
	t->stalled = false;
	t->request_available = (unsigned)-1;
	for (int i = 0; i < MAX_REQUEST_NUM; i++) {
	}
	return t;

destroy_send_cnd:
	cnd_destroy(&t->send_cnd);
destroy_mutex:
	mtx_destroy(&t->lk);
do_free:
	free(t);
	return NULL;
}

void deref_tx(struct tx *t)
{
	if (t && atomic_fetch_sub_explicit(&t->refcnt, 1,
					   memory_order_acq_rel) == 1) {
		mtx_destroy(&t->lk);
		cnd_destroy(&t->send_cnd);
		close(t->fd);
		free(t);
	}
}

void ref_tx(struct tx *t)
{
	atomic_fetch_add_explicit(&t->refcnt, 1, memory_order_relaxed);
}

static int send_shutdown_locked(struct tx *t)
{
	int err = shutdown(t->fd, SHUT_WR);
	if (err) {
		ERROR("shutdown,errno:%m");
	}
	t->shutdown = true;
	if (t->send_waiters) {
		cnd_broadcast(&t->send_cnd);
	}
	return err;
}

int send_shutdown(struct tx *t)
{
	mtx_lock(&t->lk);
	int err = send_shutdown_locked(t);
	mtx_unlock(&t->lk);
	return err;
}

size_t rope_size(struct rope *r)
{
	size_t ret = 0;
	while (r) {
		ret += r->data.len;
		r = r->next;
	}
	return ret;
}

struct rope *rope_skip(struct rope *r, size_t len)
{
	while (len) {
		if (len == r->data.len) {
			return r->next;
		} else if (len < r->data.len) {
			r->data.p += len;
			r->data.len -= len;
			return r;
		}
		len -= r->data.len;
		r = r->next;
	}
	return r;
}

const char *defrag_rope(char *buf, size_t bufsz, struct rope *r, size_t need)
{
	if (need > bufsz) {
		return NULL;
	} else if (!need) {
		return buf;
	} else if (need <= r->data.len) {
		return r->data.p;
	}
	char *p = buf;
	while (need > r->data.len) {
		memcpy(p, r->data.p, r->data.len);
		p += r->data.len;
		need -= r->data.len;
		r = r->next;
	}
	memcpy(p, r->data.p, need);
	return buf;
}

static int send_locked(struct tx *t, bool block, struct rope *r)
{
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

		if (t->shutdown) {
			return -1;
		}
	}

	while (r) {
		int vn = 0;
		struct iovec v[3];
		for (struct rope *q = r; q != NULL && vn < 3; q = q->next) {
			v[vn].iov_base = (char *)q->data.p;
			v[vn].iov_len = q->data.len;
			vn++;
		}

		struct msghdr m;
		memset(&m, 0, sizeof(m));
		m.msg_iov = v;
		m.msg_iovlen = vn;

		int w = sendmsg(t->fd, &m, 0);
		if (w < 0 && errno == EINTR) {
			continue;
		} else if (w < 0 && errno == EAGAIN) {
			if (!block) {
				ERROR("overrun on tx buffer");
				goto shutdown;
			}

			t->stalled = true;
			mtx_unlock(&t->lk);
			int err = poll_one(t->fd, false, true);
			mtx_lock(&t->lk);
			t->stalled = false;

			if (t->shutdown) {
				return -1;
			} else if (err) {
				ERROR("poll,errno:%m");
				goto shutdown;
			}
			continue;
		} else if (w <= 0) {
			ERROR("send,errno:%m");
			goto shutdown;
		} else {
			if (start_debug("send")) {
				log_int("fd", t->fd);
				int n = w;
				struct rope *p = r;
				while (n > 0) {
					slice_t s = p->data;
					log_bytes("data", s.p,
						  (n < s.len) ? n : s.len);
					n -= s.len;
				}
				finish_log();
			}
			r = rope_skip(r, w);
			continue;
		}
	}

	if (t->send_waiters) {
		cnd_signal(&t->send_cnd);
	}

	return 0;

shutdown:
	send_shutdown_locked(t);
	return -1;
}

int send_rope(struct tx *t, bool block, struct rope *r)
{
	mtx_lock(&t->lk);
	int err = send_locked(t, block, r);
	mtx_unlock(&t->lk);
	return err;
}

int send_data(struct tx *t, bool block, const char *data, size_t sz)
{
	struct rope rope;
	rope.next = NULL;
	rope.data = make_slice(data, sz);
	mtx_lock(&t->lk);
	int err = send_locked(t, block, &rope);
	mtx_unlock(&t->lk);
	return err;
}

int send_request(struct tx *c, struct tx *s, slice_t sender,
		 const struct message *m, struct rope *body)
{
	// rewrite the header, updating and filtering fields
	char buf[256];
	struct message h;
	init_message(&h, m->type, NO_REPLY_SERIAL);
	h.path = m->path;
	h.interface = m->interface;
	h.member = m->member;
	// leave error blank
	// leave destination blank
	h.sender = sender;
	h.signature = m->signature;
	// leave reply_serial as 0
	h.flags = m->flags;
	size_t bsz = rope_size(body);
	int sz = write_header(buf, sizeof(buf), &h, bsz);
	if (sz < 0) {
		return -1;
	}

	mtx_lock(&s->lk);

	// acquire a request entry and rewrite the serial
	unsigned reqidx = 0;
	if (m->type == MSG_METHOD && !(m->flags & FLAG_NO_REPLY_EXPECTED)) {
		s->request_waiters++;
		while (!(reqidx = ffs(s->request_available))) {
			cnd_wait(&s->request_cnd, &s->lk);
		}
		s->request_waiters--;
		struct tx_request *r = &s->requests[reqidx - 1];
		r->count++;
		r->client = c;
		r->serial = m->serial;
		ref_tx(c);
		s->request_available &= ~(1U << (reqidx - 1));
		h.serial = ((uint32_t)reqidx << 16) | r->count;
		set_serial(buf, h.serial);
	}

	if (start_debug("send request")) {
		log_int("fd", s->fd);
		log_message(&h);
		log_uint("body", bsz);
		finish_log();
	}

	struct rope rope;
	rope.next = body;
	rope.data.p = buf;
	rope.data.len = sz;
	if (send_locked(s, true, &rope)) {
		goto error;
	}
	mtx_unlock(&s->lk);
	return 0;

error:
	if (reqidx) {
		s->request_available |= 1U << (reqidx - 1);
		s->requests[reqidx - 1].client = NULL;
		deref_tx(c);
	}
	mtx_unlock(&s->lk);
	return -1;
}

static struct tx *consume_request(struct tx *f, uint32_t *pserial)
{
	uint16_t count = (uint16_t)*pserial;
	unsigned reqidx = *pserial >> 16;
	if (!reqidx || reqidx >= MAX_REQUEST_NUM) {
		return NULL;
	}

	mtx_lock(&f->lk);
	struct tx_request *r = &f->requests[reqidx - 1];
	struct tx *client = r->client;
	if (client && r->count == count) {
		r->client = NULL;
		*pserial = r->serial;
		f->request_available |= 1U << (reqidx - 1);
	}
	if (f->request_waiters) {
		cnd_signal(&f->request_cnd);
	}
	mtx_unlock(&f->lk);

	// return client with an active ref
	return client;
}

int send_reply(struct tx *s, slice_t sender, const struct message *m,
	       struct rope *body)
{
	// the request is consumed, but c has an active ref
	uint32_t serial = m->reply_serial;
	struct tx *c = consume_request(s, &serial);
	if (!c) {
		return -1;
	}

	// rewrite the header, updating and filtering fields
	char buf[256];
	struct message h;
	init_message(&h, m->type, NO_REPLY_SERIAL);
	// leave path blank
	// leave interface blank
	// leave member blank
	if (m->type == MSG_ERROR) {
		h.error = m->error;
	}
	// leave destination blank
	h.sender = sender;
	h.signature = m->signature;
	h.reply_serial = serial;
	h.flags = m->flags;
	int sz = write_header(buf, sizeof(buf), &h, rope_size(body));

	struct rope rope;
	rope.next = body;
	rope.data.p = buf;
	rope.data.len = sz;
	int err = (sz < 0) || send_rope(c, false, &rope);

	deref_tx(c);
	return err;
}