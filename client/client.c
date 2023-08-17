#define _DEFAULT_SOURCE
#include "client.h"
#include "socket.h"
#include "dbus/zbus.h"
#include "lib/logmsg.h"
#include "lib/algo.h"
#include <stdint.h>

static int write_all(fd_t fd, char *b, size_t sz, const char *args, ...)
	GNU_PRINTF_ATTRIBUTE(4, 5);

static int write_all(fd_t fd, char *b, size_t sz, const char *args, ...)
{
	struct logbuf lb;
	if (start_debug(&lb, "write")) {
		va_list ap;
		va_start(ap, args);
		log_vargs(&lb, args, ap);
		log_uint(&lb, "fd", (unsigned)fd);
		log_bytes(&lb, "data", b, sz);
		finish_log(&lb);
	}
	while (sz) {
		int w = sys_send(fd, b, (int)sz);
		if (w <= 0) {
			char buf[128];
			struct logbuf lb;
			start_log(&lb, buf, sizeof(buf), LOG_ERROR, "write");
			va_list ap;
			va_start(ap, args);
			log_vargs(&lb, args, ap);
			log_errno(&lb, "errno");
			log_uint(&lb, "fd", (unsigned)fd);
			finish_log(&lb);
			return -1;
		}
		b += w;
		sz -= w;
	}
	return 0;
}

void close_client(struct client *c)
{
	if (c) {
		sys_close(c->fd);
		free(c);
	}
}

static int on_connected(void *udata, struct client *c, struct zb_message *m,
			struct zb_iterator *ii)
{
	unregister_cb(c, m->reply_serial);
	if (m->type != ZB_REPLY) {
		goto error;
	}
	const zb_str8 *addr = zb_parse_str8(ii);
	if (!addr) {
		goto error;
	}
	LOG("connected,address:%s", addr->p);
	return 0;

error:
	ERROR("failed to connect");
	return -1;
}

struct client *open_client(const char *sockpn)
{
	fd_t fd;
	if (sys_open(&fd, sockpn)) {
		FATAL("failed to open dbus socket,errno:%m");
	}

	size_t msgsz = 4096;
	size_t defrag = 1024;
	struct client *c = fmalloc(sizeof(*c) + msgsz + defrag);
	c->fd = fd;
	c->cb_available = UINT16_MAX;
	memset(&c->cbs, 0, sizeof(c->cbs));
	zb_init_stream(&c->in, msgsz, defrag);

	char uidbuf[64];
	const char *uid = sys_userid(uidbuf, sizeof(uidbuf));

	uint32_t serial = register_cb(c, &on_connected, c);
	char buf[256];
	int n = zb_write_auth_external(buf, sizeof(buf), uid, serial);
	write_all(fd, buf, n, "send_auth,fd:%u", (unsigned)fd);

	return c;
}

uint32_t register_cb(struct client *c, message_fn fn, void *udata)
{
	assert(fn != NULL);
	int idx = ffs(c->cb_available);
	if (!idx) {
		return 0;
	}
	struct zb_message_cb *cb = &c->cbs[idx - 1];
	cb->fn = fn;
	cb->udata = udata;
	cb->counter++;
	c->cb_available &= ~(1U << (idx - 1));
	uint32_t serial = idx | (((uint32_t)cb->counter) << 16);
	return serial;
}

void unregister_cb(struct client *c, uint32_t serial)
{
	int idx = serial & UINT16_MAX;
	uint16_t counter = (uint16_t)(serial >> 16);
	struct zb_message_cb *cb = &c->cbs[idx - 1];
	assert(0 < idx && idx <= sizeof(c->cbs) / sizeof(c->cbs[0]));
	assert(counter == cb->counter);
	assert(!(c->cb_available & (1U << (idx - 1))));
	c->cb_available |= 1U << (idx - 1);
	cb->fn = NULL;
	cb->udata = NULL;
}

int distribute_message(struct client *c, struct zb_message *m,
		       struct zb_iterator *body)
{
	unsigned idx = m->reply_serial & UINT16_MAX;
	uint16_t counter = (uint16_t)(m->reply_serial >> 16);
	if (!idx || idx > sizeof(c->cbs) / sizeof(c->cbs[0])) {
		return 0;
	}
	struct zb_message_cb *cb = &c->cbs[idx - 1];
	if (cb->fn && counter == cb->counter) {
		return cb->fn(cb->udata, c, m, body);
	} else {
		return 0;
	}
}

int vsend_signal(struct client *c, const zb_str8 *path, const zb_str8 *iface,
		 const zb_str8 *mbr, const char *sig, va_list ap)
{
	struct zb_message m;
	zb_init_message(&m, ZB_SIGNAL, UINT32_MAX);
	m.member = mbr;
	m.path = path;
	m.interface = iface;
	m.signature = sig;

	char buf[256];
	struct zb_builder b;
	zb_start(&b, buf, sizeof(buf), &m);

	zb_add_multiv(&b, sig, ap);

	int sz = zb_end(&b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz, "send_signal,path:%s,iface:%s,mbr:%s",
		      path->p, iface->p, mbr->p)) {
		return -1;
	}
	return 0;
}

int vcall_method(struct client *c, uint32_t serial, const zb_str8 *dst,
		 const zb_str8 *path, const zb_str8 *iface, const zb_str8 *mbr,
		 const char *sig, va_list ap)
{
	struct zb_message m;
	zb_init_message(&m, ZB_METHOD, serial ? serial : UINT32_MAX);
	m.flags = serial ? 0 : ZB_NO_REPLY_EXPECTED;
	m.member = mbr;
	m.destination = dst;
	m.path = path;
	m.interface = iface;
	m.signature = sig;

	char buf[256];
	struct zb_builder b;
	zb_start(&b, buf, sizeof(buf), &m);

	zb_add_multiv(&b, sig, ap);

	int sz = zb_end(&b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz, "dst:%s,path:%s,iface:%s,mbr:%s", dst->p,
		      path->p, iface->p, mbr->p)) {
		return -1;
	}
	return 0;
}

int vsend_reply(struct client *c, const struct zb_message *req, const char *sig,
		va_list ap)
{
	struct zb_message m;
	zb_init_message(&m, ZB_REPLY, UINT32_MAX);
	m.signature = sig;
	m.reply_serial = req->serial;
	m.destination = req->sender;

	char buf[256];
	struct zb_builder b;
	zb_start(&b, buf, sizeof(buf), &m);

	zb_add_multiv(&b, sig, ap);

	int sz = zb_end(&b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz, "type:%s,request:%x,dst:%s", "reply(2)",
		      req->serial, req->sender->p)) {
		return -1;
	}
	return 0;
}

int send_error(struct client *c, uint32_t request_serial, const zb_str8 *error)
{
	struct zb_message m;
	zb_init_message(&m, ZB_ERROR, UINT32_MAX);
	m.error = error;
	m.reply_serial = request_serial;

	char buf[256];
	struct zb_builder b;
	zb_start(&b, buf, sizeof(buf), &m);

	int sz = zb_end(&b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz, "send_error,request:%u,error:%s",
		      request_serial, error->p)) {
		return -1;
	}
	return 0;
}

int send_signal(struct client *c, const zb_str8 *path, const zb_str8 *iface,
		const zb_str8 *mbr, const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	return vsend_signal(c, path, iface, mbr, sig, ap);
}

int call_method(struct client *c, uint32_t serial, const zb_str8 *dst,
		const zb_str8 *path, const zb_str8 *iface, const zb_str8 *mbr,
		const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	return vcall_method(c, serial, dst, path, iface, mbr, sig, ap);
}

int send_reply(struct client *c, const struct zb_message *req, const char *sig,
	       ...)
{
	va_list ap;
	va_start(ap, sig);
	return vsend_reply(c, req, sig, ap);
}

int call_bus_method(struct client *c, uint32_t serial, const zb_str8 *member,
		    const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	return vcall_method(c, serial, ZB_S8("\024org.freedesktop.DBus"),
			    ZB_S8("\025/org/freedesktop/DBus"),
			    ZB_S8("\024org.freedesktop.DBus"), member, sig, ap);
}

int read_data(struct client *c)
{
	char *p1, *p2;
	size_t n1, n2;
	zb_get_stream_recvbuf(&c->in, &p1, &n1, &p2, &n2);
	int n = sys_recv(c->fd, p1, (int)n1);
	if (n < 0) {
		return -1;
	}
	c->in.have += n;
	return 0;
}

static int read_more(struct client *c)
{
	char *p1, *p2;
	size_t n1, n2;
	zb_get_stream_recvbuf(&c->in, &p1, &n1, &p2, &n2);
	int n = sys_recv(c->fd, p1, (int)n1);
	if (n < 0) {
		return -1;
	}
	c->in.have += n;
	return 0;
}

int read_auth(struct client *c)
{
	for (;;) {
		int sts = zb_read_auth(&c->in);
		if (sts > 0) {
			return 0;
		} else if (!sts && !read_more(c)) {
			continue;
		} else {
			return -1;
		}
	}
}

int read_message(struct client *c, struct zb_message *msg,
		 struct zb_iterator *body)
{
	for (;;) {
		int sts = zb_read_message(&c->in, msg);
		if (sts > 0) {
			struct logbuf lb;
			if (start_debug(&lb, "read message")) {
				log_uint(&lb, "fd", (unsigned)c->fd);
				log_message(&lb, msg);
				finish_log(&lb);
			}
			return zb_defragment_body(&c->in, msg, body);

		} else if (!sts && !read_more(c)) {
			continue;
		} else {
			return -1;
		}
	}
}