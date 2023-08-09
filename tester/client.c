#include "client.h"
#include "dbus/auth.h"
#include "lib/logmsg.h"
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>

static int write_all(int fd, char *b, size_t sz, const char *args, ...)
	__attribute__((format(printf, 4, 5)));

static int write_all(int fd, char *b, size_t sz, const char *args, ...)
{
	struct logbuf lb;
	if (start_debug(&lb, "write")) {
		va_list ap;
		va_start(ap, args);
		log_vargs(&lb, args, ap);
		log_int(&lb, "fd", fd);
		log_bytes(&lb, "data", b, sz);
		finish_log(&lb);
	}
	while (sz) {
		int w = write(fd, b, sz);
		if (w <= 0) {
			char buf[128];
			struct logbuf lb;
			start_log(&lb, buf, sizeof(buf), LOG_ERROR, "write");
			va_list ap;
			va_start(ap, args);
			log_vargs(&lb, args, ap);
			log_errno(&lb, "errno");
			log_int(&lb, "fd", fd);
			finish_log(&lb);
			return -1;
		}
		b += w;
		sz -= w;
	}
	return 0;
}

static int read_one(int fd, char *buf, size_t cap)
{
try_again:
	int r = read(fd, buf, cap);
	if (r < 0 && errno == EINTR) {
		goto try_again;
	} else if (r < 0) {
		ERROR("read,errno:%m,fd:%d", fd);
		return -1;
	} else if (r == 0) {
		ERROR("recv early EOF,fd:%d", fd);
		return -1;
	}
	struct logbuf b;
	if (start_debug(&b, "read")) {
		log_int(&b, "fd", fd);
		log_bytes(&b, "data", buf, r);
		finish_log(&b);
	}
	return r;
}

static int connect_unix(const char *sockpn)
{
	int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNIX);
	if (lfd < 0) {
		goto error;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	size_t len = strlen(sockpn);
	if (len + 1 > sizeof(addr.sun_path)) {
		goto error;
	}
	memcpy(addr.sun_path, sockpn, len + 1);

	socklen_t salen = &addr.sun_path[len + 1] - (char *)&addr;
	if (connect(lfd, (struct sockaddr *)&addr, salen)) {
		goto error;
	}

	return lfd;
error:
	close(lfd);
	return -1;
}

static const char *get_user_id(char *buf, size_t sz)
{
	char *puid = buf + sz;
	int id = getuid();
	*(--puid) = 0;
	do {
		*(--puid) = (id % 10) + '0';
		id /= 10;
	} while (id);
	return puid;
}

struct client *open_client(const char *sockpn)
{
	struct client *c = NULL;
	int fd = connect_unix(sockpn);
	if (fd < 0) {
		ERROR("failed to open dbus socket,errno:%m");
		goto error;
	}

	char uidbuf[16];
	const char *uid = get_user_id(uidbuf, sizeof(uidbuf));

	char inbuf[256], outbuf[256];
	size_t insz = 0;
	int state = 0;
	uint32_t serial;

	for (;;) {
		char *in = inbuf;
		char *out = outbuf;
		int err = step_client_auth(&state, &in, insz, &out,
					   sizeof(outbuf), uid, &serial);

		if (write_all(fd, outbuf, out - outbuf, "state:%d", state)) {
			goto error;
		}

		if (err == AUTH_OK) {
			break;
		} else if (err != AUTH_READ_MORE) {
			goto error;
		}

		int n = inbuf + insz - in;
		memmove(inbuf, in, n);
		insz = n;

		n = read_one(fd, inbuf + insz, sizeof(inbuf) - insz);
		if (n < 0) {
			goto error;
		}
		insz += n;
	}

	size_t msgsz = 4096;
	size_t defrag = 1024;
	c = fmalloc(sizeof(*c) + msgsz + defrag);
	c->fd = fd;
	c->cb_available = UINT16_MAX;
	memset(&c->cbs, 0, sizeof(c->cbs));
	init_msg_stream(&c->in, msgsz, defrag);

	struct message m;
	struct iterator ii;
	if (read_message(c, &m, &ii) || m.type != MSG_REPLY ||
	    m.reply_serial != serial) {
		goto error;
	}
	const str8_t *addr = parse_string8(&ii);
	if (iter_error(&ii)) {
		goto error;
	}
	LOG("connected,address:%s", addr->p);
	return c;

error:
	free(c);
	close(fd);
	return NULL;
}

void close_client(struct client *c)
{
	if (c) {
		close(c->fd);
		free(c);
	}
}

uint32_t register_cb(struct client *c, message_fn fn, void *udata)
{
	int idx = ffs(c->cb_available);
	if (!idx) {
		return 0;
	}
	c->cbs[idx - 1].fn = fn;
	c->cbs[idx - 1].udata = udata;
	c->cb_available &= ~(1U << (idx - 1));
	return idx;
}

void unregister_cb(struct client *c, uint32_t serial)
{
	assert(0 < serial && serial <= sizeof(c->cbs) / sizeof(c->cbs[0]));
	c->cb_available |= 1U << (serial - 1);
	c->cbs[serial - 1].fn = NULL;
	c->cbs[serial - 1].udata = NULL;
}

int vsend_signal(struct client *c, const str8_t *path, const str8_t *iface,
		 const str8_t *mbr, const char *sig, va_list ap)
{
	struct message m;
	init_message(&m, MSG_SIGNAL, UINT32_MAX);
	m.member = mbr;
	m.path = path;
	m.interface = iface;
	m.signature = sig;

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);

	append_multiv(&b, sig, ap);

	int sz = end_message(b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz,
		      "send_signal,path:%.*s,iface:%.*s,mbr:%.*s", S_PRI(*path),
		      S_PRI(*iface), S_PRI(*mbr))) {
		return -1;
	}
	return 0;
}

int vcall_method(struct client *c, uint32_t serial, const str8_t *dst,
		 const str8_t *path, const str8_t *iface, const str8_t *mbr,
		 const char *sig, va_list ap)
{
	struct message m;
	init_message(&m, MSG_METHOD, serial ? serial : UINT32_MAX);
	m.flags = serial ? 0 : FLAG_NO_REPLY_EXPECTED;
	m.member = mbr;
	m.destination = dst;
	m.path = path;
	m.interface = iface;
	m.signature = sig;

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);

	append_multiv(&b, sig, ap);

	int sz = end_message(b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz, "dst:%.*s,path:%.*s,iface:%.*s,mbr:%.*s",
		      S_PRI(*dst), S_PRI(*path), S_PRI(*iface), S_PRI(*mbr))) {
		return -1;
	}
	return 0;
}

int vsend_reply(struct client *c, const struct message *req, const char *sig,
		va_list ap)
{
	struct message m;
	init_message(&m, MSG_REPLY, UINT32_MAX);
	m.signature = sig;
	m.reply_serial = req->serial;
	m.destination = req->sender;

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);

	append_multiv(&b, sig, ap);

	int sz = end_message(b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz, "type:%s,request:%x,dst:%.*s", "reply(2)",
		      req->serial, S_PRI(*req->sender))) {
		return -1;
	}
	return 0;
}

int send_error(struct client *c, uint32_t request_serial, const str8_t *error)
{
	struct message m;
	init_message(&m, MSG_ERROR, UINT32_MAX);
	m.error = error;
	m.reply_serial = request_serial;

	char buf[256];
	struct builder b = start_message(buf, sizeof(buf), &m);

	int sz = end_message(b);
	if (sz < 0) {
		ERROR("failed to encode message");
		return -1;
	}
	if (write_all(c->fd, buf, sz, "send_error,request:%u,error:%.*s",
		      request_serial, S_PRI(*error))) {
		return -1;
	}
	return 0;
}

int send_signal(struct client *c, const str8_t *path, const str8_t *iface,
		const str8_t *mbr, const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	return vsend_signal(c, path, iface, mbr, sig, ap);
}

int call_method(struct client *c, uint32_t serial, const str8_t *dst,
		const str8_t *path, const str8_t *iface, const str8_t *mbr,
		const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	return vcall_method(c, serial, dst, path, iface, mbr, sig, ap);
}

int send_reply(struct client *c, const struct message *req, const char *sig,
	       ...)
{
	va_list ap;
	va_start(ap, sig);
	return vsend_reply(c, req, sig, ap);
}

int call_bus_method(struct client *c, uint32_t serial, const str8_t *member,
		    const char *sig, ...)
{
	va_list ap;
	va_start(ap, sig);
	return vcall_method(c, serial, S8("\024org.freedesktop.DBus"),
			    S8("\025/org/freedesktop/DBus"),
			    S8("\024org.freedesktop.DBus"), member, sig, ap);
}

int read_message(struct client *c, struct message *msg, struct iterator *body)
{
	for (;;) {
		int err = stream_next(&c->in, msg);

		if (err == STREAM_MORE) {
			char *p1, *p2;
			size_t n1, n2;
			stream_buffers(&c->in, &p1, &n1, &p2, &n2);
			int n = read_one(c->fd, p1, n1);
			if (n < 0) {
				return -1;
			}
			c->in.have += n;
			continue;
		} else if (err == STREAM_OK) {
			struct logbuf lb;
			if (start_debug(&lb, "read message")) {
				log_int(&lb, "fd", c->fd);
				log_message(&lb, msg);
				finish_log(&lb);
			}
			return defragment_body(&c->in, msg, body);
		} else {
			return -1;
		}
	}
}

int distribute_message(struct client *c, struct message *m,
		       struct iterator *body)
{
	if (!(0 < m->reply_serial &&
	      m->reply_serial <= sizeof(c->cbs) / sizeof(c->cbs[0]))) {
		return 0;
	}
	int idx = m->reply_serial - 1;
	if (c->cb_available & (1U << idx)) {
		return 0;
	} else {
		return c->cbs[idx].fn(c->cbs[idx].udata, c, m, body);
	}
}